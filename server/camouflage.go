package main

import (
	"log"
	"net/http"
	"strconv"
	"time"
)

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
		timeStr := r.Header.Get("X-Auth-Time")
		clientSig := r.Header.Get("X-Auth-Sig")
		clientID := r.URL.Query().Get("clientid")
		reqID := r.URL.Query().Get("requestid")
		switch r.URL.Path {
		case "/poll":
			// The poll connection is bound to the client identity.
			reqID = "poll-" + clientID
		case "/upload":
			// Upload batches span many concurrent sessions, so the signature
			// identity is the client, not any single request.
			reqID = "upload-" + clientID
		}

		clientTime, err := strconv.ParseInt(timeStr, 10, 64)
		if err != nil || timeStr == "" || clientSig == "" {
			log.Printf("[AUTH] Denied %s: Missing or invalid headers", r.RemoteAddr)
			camouflage(w, r)
			return
		}

		now := time.Now().Unix()
		if clientTime < now-90 || clientTime > now+90 {
			log.Printf("[AUTH] Denied %s: Time skew detected (Client: %d, Server: %d)", r.RemoteAddr, clientTime, now)
			camouflage(w, r)
			return
		}

		if clientSig != generateSignature(clientTime, reqID) {
			log.Printf("[AUTH] Denied %s: Invalid signature", r.RemoteAddr)
			camouflage(w, r)
			return
		}
		next.ServeHTTP(w, r)
	}
}
