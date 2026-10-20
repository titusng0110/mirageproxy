package main

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
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
