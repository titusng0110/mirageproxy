package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	"mirageproxy/internal/shared"
)

// Set to true to see detailed chunk-level logs. Set to false for connection-only logs.
const DebugMode = false

// Injected at build time via -ldflags
var (
	ProxySecret = "default_secret_if_not_built_properly"
)

const (
	LocalListenAddr = ":30001"
	ShadowSocksAddr = "127.0.0.1:5080"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	log.Println("[MAIN] Starting proxy server...")
	go backgroundCleanup()
	go downstreamRouter()
	go rotateLoop()

	mux := http.NewServeMux()
	mux.HandleFunc("/upload", requireAuth(uploadHandler))
	mux.HandleFunc("/poll", requireAuth(pollHandler))
	mux.HandleFunc("/", camouflage) // Catch-all for active probes

	server := &http.Server{
		Addr:    LocalListenAddr,
		Handler: mux,
		// Thread the tracked connection into every request context so
		// handlers (the poll stream in particular) can observe rotation.
		// HTTP/2 is enabled natively: Serve() configures it, and the TLS
		// listener below advertises h2 via ALPN.
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if tc, ok := c.(*trackedConn); ok {
				return context.WithValue(ctx, connCtxKey{}, tc)
			}
			return ctx
		},
		// Untrack connections the moment they close, so the rotation
		// registry holds only live connections. Without this, a flood of
		// probe connections (which the camouflage design actively invites)
		// lingers in the registry for up to rotateMaxAge+rotateGrace and
		// makes every rotator sweep progressively more expensive.
		// StateClosed fires for both protocols: net/http emits StateNew
		// and StateClosed itself, while the HTTP/2 stack emits
		// StateActive/StateIdle in between.
		ConnState: func(c net.Conn, st http.ConnState) {
			if st == http.StateClosed {
				if tc, ok := c.(*trackedConn); ok {
					untrackConn(tc)
				}
			}
		},
	}

	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		log.Fatalf("[MAIN] Failed to load TLS certificate: %v", err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		// Explicit ALPN advertisement: the h2 offer keeps uTLS clients on
		// the HTTP/2 path, with http/1.1 available as fallback. Handshakes
		// are bounded by handshakeTimeout on the accept path.
		NextProtos: []string{"h2", "http/1.1"},
		MinVersion: tls.VersionTLS12,
	}

	ln, err := net.Listen("tcp", LocalListenAddr)
	if err != nil {
		log.Fatalf("[MAIN] Failed to listen: %v", err)
	}

	log.Printf("[MAIN] Server listening on https://%s (connections rotated every %s-%s)",
		LocalListenAddr, rotateMinAge, rotateMaxAge)
	if err := server.Serve(&rotatingListener{Listener: tls.NewListener(ln, tlsConfig)}); err != nil {
		log.Fatalf("[MAIN] Server failed: %v", err)
	}
}

// ============================================================================
// Camouflage and authentication — the front door
// ============================================================================

// nginx404Body is a byte-exact replica of the stock nginx 404 error page as
// served by nginx/1.31.7: the newer multi-line layout with CRLF line endings
// and a trailing newline (153 bytes total). DPI systems fingerprint servers
// by these exact bytes, so they are reproduced verbatim.
const nginx404Body = "<html>\r\n" +
	"<head><title>404 Not Found</title></head>\r\n" +
	"<body>\r\n" +
	"<center><h1>404 Not Found</h1></center>\r\n" +
	"<hr><center>nginx/1.31.7</center>\r\n" +
	"</body>\r\n" +
	"</html>\r\n"

func camouflage(w http.ResponseWriter, r *http.Request) {
	if DebugMode {
		log.Printf("[CAMOUFLAGE] Served 404 to %s for path: %s", r.RemoteAddr, r.URL.Path)
	}
	w.Header().Set("Server", "nginx/1.31.7")
	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Content-Length", strconv.Itoa(len(nginx404Body)))
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte(nginx404Body))
}

func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientID := r.URL.Query().Get(shared.ParamClientID)
		reqID := r.URL.Query().Get(shared.ParamRequestID)
		switch r.URL.Path {
		case "/poll":
			// The poll connection is bound to the client identity.
			reqID = shared.PollID(clientID)
		case "/upload":
			// Upload batches span many concurrent sessions, so the signature
			// identity is the client, not any single request.
			reqID = shared.UploadID(clientID)
		}

		if err := shared.VerifyAuth(r, ProxySecret, reqID); err != nil {
			log.Printf("[AUTH] Denied %s: %v", r.RemoteAddr, err)
			camouflage(w, r)
			return
		}
		next.ServeHTTP(w, r)
	}
}

// ============================================================================
// HTTP handlers
// ============================================================================

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get(shared.ParamClientID)

	var batch shared.PostBatch
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

	resp := shared.AckPayload{Acked: string(bits)}

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
func writeDownstreamPart(w http.ResponseWriter, p shared.Part) {
	line, err := json.Marshal(p)
	if err != nil {
		return // cannot happen: part holds only strings and ints
	}
	w.Write(append(line, '\n'))
}

func pollHandler(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get(shared.ParamClientID)
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
