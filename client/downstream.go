package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

func runPoller(client *http.Client) {
	pollURL := fmt.Sprintf("%s/poll?clientid=%s", RemoteServerURL, myClientID)
	log.Printf("[POLL] Starting downstream poller: %s", pollURL)

	for {
		req, _ := http.NewRequest(http.MethodGet, pollURL, nil)
		now := time.Now().Unix()
		req.Header.Set("X-Auth-Time", fmt.Sprintf("%d", now))
		req.Header.Set("X-Auth-Sig", generateSignature(now, "poll-"+myClientID))
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/114.0.0.0")

		resp, err := client.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			log.Printf("[POLL] Connection failed (Status: %d, Err: %v), retrying in 2s...", func() int {
				if resp != nil {
					return resp.StatusCode
				}
				return 0
			}(), err)
			time.Sleep(2 * time.Second)
			continue
		}

		if DebugMode {
			log.Printf("[POLL] Connected to remote stream")
		}

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || line == "{}" {
				continue // Ignore heartbeats
			}
			var p part
			if err := json.Unmarshal([]byte(line), &p); err == nil {
				processDownstreamPayload(p)
			} else {
				log.Printf("[POLL] JSON unmarshal error: %v", err)
			}
		}
		if err := scanner.Err(); err != nil {
			log.Printf("[POLL] Stream read error: %v", err)
		}
		resp.Body.Close()

		if DebugMode {
			log.Printf("[POLL] Remote stream ended, reconnecting...")
		}
	}
}

// processDownstreamPayload buffers an incoming part into the session's
// reorder window. Future sequences are accepted and held; data is written
// to the local connection only once the head sequence is fully assembled,
// cascading through any complete sequences behind it.
func processDownstreamPayload(p part) {
	if p.ClientID != "" && p.ClientID != myClientID {
		return // Not for us.
	}
	if DebugMode {
		log.Printf("[DOWNSTREAM] Received ReqID: %s | Seq: %d | Part: %d/%d", p.RequestID, p.Seq, p.Part, p.TotalParts)
	}

	if p.Final {
		// Server-side teardown signal: the remote end of this session is
		// gone, so kill the local connection to fail fast instead of
		// hanging. Unknown sessions (already closed locally) are ignored.
		if fl := lookupFlow(p.RequestID); fl != nil {
			log.Printf("[DOWNSTREAM] Server closed session %s; closing local connection", p.RequestID)
			fl.kill()
		}
		return
	}

	if p.Seq <= 0 || p.TotalParts <= 0 || p.Part < 1 || p.Part > p.TotalParts || p.Data == "" {
		return // Malformed part.
	}

	sessionMu.RLock()
	sess, ok := sessions[p.RequestID]
	sessionMu.RUnlock()
	if !ok {
		if DebugMode {
			log.Printf("[DOWNSTREAM] Discarded payload for unknown/closed ReqID: %s", p.RequestID)
		}
		return
	}

	downstreamMu.Lock()
	w := downstreamWindows[p.RequestID]
	if w == nil {
		// The server's global queue is FIFO, so the first part we see for a
		// session is the oldest one in flight; it becomes the window head.
		w = &rxWindow{head: p.Seq, entries: make(map[int]*chunkBuffer)}
		downstreamWindows[p.RequestID] = w
	}
	if p.Seq < w.head {
		downstreamMu.Unlock()
		return // Stale duplicate of already-flushed data.
	}
	if p.Seq >= w.head+windowSeqs {
		downstreamMu.Unlock()
		// Cannot happen while the server backpressures; guarded anyway.
		log.Printf("[DOWNSTREAM] Window overflow for %s seq %d (head %d); dropping", p.RequestID, p.Seq, w.head)
		return
	}

	mb := w.entries[p.Seq]
	if mb == nil {
		mb = &chunkBuffer{total: p.TotalParts, parts: make(map[int]string), updatedAt: time.Now()}
		w.entries[p.Seq] = mb
	}
	if _, dup := mb.parts[p.Part]; !dup {
		mb.parts[p.Part] = p.Data
	}
	mb.updatedAt = time.Now()

	// Pop every complete sequence at the head (cascading) while holding the
	// lock, but perform the socket writes after releasing it.
	var ready []string
	for {
		mb := w.entries[w.head]
		if mb == nil || len(mb.parts) < mb.total {
			break
		}
		var combined strings.Builder
		for i := 1; i <= mb.total; i++ {
			combined.WriteString(mb.parts[i])
		}
		delete(w.entries, w.head)
		w.head++
		ready = append(ready, combined.String())
	}
	downstreamMu.Unlock()

	for _, blob := range ready {
		decoded, err := base64.StdEncoding.DecodeString(blob)
		if err != nil {
			log.Printf("[DOWNSTREAM] Base64 decode error for %s: %v", p.RequestID, err)
			continue
		}
		sess.writeMutex.Lock()
		writeErr := writeFull(sess.conn, decoded)
		sess.writeMutex.Unlock()
		if writeErr != nil {
			log.Printf("[DOWNSTREAM] Write error for ReqID %s: %v", p.RequestID, writeErr)
		}
		if DebugMode {
			log.Printf("[DOWNSTREAM] Wrote %d bytes to local connection for ReqID: %s", len(decoded), p.RequestID)
		}
	}
}
