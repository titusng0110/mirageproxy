package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("clientid")

	var batch postBatch
	if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
		log.Printf("[UPLOAD] Bad Request from %s: %v", r.RemoteAddr, err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	if DebugMode {
		log.Printf("[UPLOAD] Received batch of %d part(s) from %s", len(batch.Parts), r.RemoteAddr)
	}

	acks := make([]bool, len(batch.Parts))
	for i := range batch.Parts {
		p := batch.Parts[i]
		p.ClientID = clientID // the authenticated identity wins over the body
		acks[i] = handleUploadPart(p)
	}

	bits := make([]byte, len(acks))
	for i, ok := range acks {
		if ok {
			bits[i] = '1'
		} else {
			bits[i] = '0'
		}
	}

	resp := ackPayload{Acked: string(bits)}

	// Piggyback ride: attach queued downstream parts to this response so
	// download traffic also moves on upload round-trips. Non-blocking and
	// capped at piggybackBudget bytes of payload; each part is consumed by
	// exactly one lane (this response or /poll), never both, so per-session
	// ordering and delivery guarantees are unchanged.
	cg := getClientGroup(clientID)
	budget := piggybackBudget
drain:
	for count := 0; count < 64; count++ { // count cap bounds response size when parts are tiny
		select {
		case p := <-cg.DownstreamChan:
			if len(p.Data) > budget {
				// Doesn't fit in the remaining budget: hand it back for the
				// next consumer. The client's reorder window tolerates the
				// resulting reshuffle.
				cg.DownstreamChan <- p
				break drain
			}
			budget -= len(p.Data)
			resp.Downstream = append(resp.Downstream, p)
			if budget == 0 {
				break drain
			}
		default:
			break drain
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// writeDownstreamPart emits one part as an NDJSON line on the poll stream.
func writeDownstreamPart(w http.ResponseWriter, p part) {
	line, err := json.Marshal(p)
	if err != nil {
		return // cannot happen: part holds only strings and ints
	}
	w.Write(append(line, '\n'))
}

func pollHandler(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("clientid")
	cg := getClientGroup(clientID)

	log.Printf("[POLL] Client connected: %s", clientID)

	flusher, canFlush := w.(http.Flusher)

	// The rotator signals impending connection teardown through the
	// tracked connection (threaded in via Server.ConnContext). Ending the
	// poll on that signal lets the client reconnect on a fresh connection
	// cleanly, instead of discovering the closure as a chopped stream. A
	// nil channel never fires, so connections without tracking are
	// unaffected.
	var drainCh <-chan struct{}
	if tc, ok := r.Context().Value(connCtxKey{}).(*trackedConn); ok {
		drainCh = tc.drainCh
	}

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	timeout := time.After(60 * time.Second)
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-drainCh:
			// The rotator is winding this connection down; end the stream
			// cleanly so the client's poller reconnects right away.
			if DebugMode {
				log.Printf("[POLL] Rotation drain signal, ending stream for: %s", clientID)
			}
			return
		case <-r.Context().Done():
			log.Printf("[POLL] Client disconnected early: %s", clientID)
			return
		case <-timeout:
			if DebugMode {
				log.Printf("[POLL] Gracefully refreshing poll connection for: %s", clientID)
			}
			return
		case <-ticker.C:
			w.Write([]byte("{}\n")) // Heartbeat
			if canFlush {
				flusher.Flush()
			}
		case p := <-cg.DownstreamChan:
			writeDownstreamPart(w, p)

		drainLoop:
			for i := 0; i < 50; i++ {
				select {
				case m := <-cg.DownstreamChan:
					writeDownstreamPart(w, m)
				default:
					break drainLoop
				}
			}
			if canFlush {
				flusher.Flush()
			}
		}
	}
}
