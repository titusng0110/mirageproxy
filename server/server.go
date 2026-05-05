package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
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
	readTimeout     = 180 * time.Second
	chunkSize       = 16 * 1024
	idleTimeout     = 15 * time.Minute
)

type postPayload struct {
	Data  string `json:"data,omitempty"`
	Final bool   `json:"final,omitempty"`
}

type downstreamPayload struct {
	RequestID  string `json:"request_id,omitempty"`
	Seq        int    `json:"seq,omitempty"`
	Data       string `json:"data,omitempty"`
	Part       int    `json:"part,omitempty"`
	TotalParts int    `json:"total_parts,omitempty"`
}

type messageBuffer struct {
	totalParts int
	parts      map[int]string
	updatedAt  time.Time
}

type ClientGroup struct {
	DownstreamChan chan string
	LastActive     time.Time
}

type Session struct {
	RequestID    string
	ClientID     string
	Conn         net.Conn
	writeMutex   sync.Mutex
	cancel       context.CancelFunc
	mu           sync.Mutex
	postBuffers  map[int]*messageBuffer
	seenSeqs     map[int]time.Time
	lastActivity time.Time
}

var (
	stateMu      sync.RWMutex
	sessions     = make(map[string]*Session)
	clientGroups = make(map[string]*ClientGroup)
)

func generateSignature(timestamp int64, id string) string {
	msg := fmt.Sprintf("%d:%s", timestamp, id)
	mac := hmac.New(sha256.New, []byte(ProxySecret))
	mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))
}

func camouflage(w http.ResponseWriter, r *http.Request) {
	if DebugMode {
		log.Printf("[CAMOUFLAGE] Served 404 to %s for path: %s", r.RemoteAddr, r.URL.Path)
	}
	w.Header().Set("Server", "nginx/1.18.0")
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte(`<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>nginx/1.18.0</center></body></html>`))
}

func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		timeStr := r.Header.Get("X-Auth-Time")
		clientSig := r.Header.Get("X-Auth-Sig")
		reqID := r.URL.Query().Get("requestid")
		if r.URL.Path == "/poll" {
			reqID = "poll-" + r.URL.Query().Get("clientid")
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

func getClientGroup(clientID string) *ClientGroup {
	stateMu.Lock()
	defer stateMu.Unlock()
	cg, exists := clientGroups[clientID]
	if !exists {
		cg = &ClientGroup{
			DownstreamChan: make(chan string, 2000),
			LastActive:     time.Now(),
		}
		clientGroups[clientID] = cg
		log.Printf("[CLIENT] New client group created: %s", clientID)
	}
	cg.LastActive = time.Now()
	return cg
}

func (s *Session) closeSession() {
	if s.cancel != nil {
		s.cancel()
	}
	if s.Conn != nil {
		s.Conn.Close()
	}
	stateMu.Lock()
	delete(sessions, s.RequestID)
	stateMu.Unlock()
	log.Printf("[SESSION] Closed session %s", s.RequestID)
}

func (s *Session) startSession(ctx context.Context, cg *ClientGroup) {
	defer s.closeSession()
	buf := make([]byte, 128*1024)
	seq := 0

	log.Printf("[SESSION] Started downstream reader for %s", s.RequestID)

	for {
		s.Conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, err := s.Conn.Read(buf)

		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				s.mu.Lock()
				inactive := time.Since(s.lastActivity) > readTimeout
				s.mu.Unlock()
				if inactive {
					log.Printf("[SESSION] Downstream reader timed out due to inactivity: %s", s.RequestID)
					return
				}
				continue
			}
			log.Printf("[SESSION] Downstream read error for %s: %v", s.RequestID, err)
			return
		}

		if n > 0 {
			s.mu.Lock()
			s.lastActivity = time.Now()
			s.mu.Unlock()
			seq++

			encodedStr := base64.StdEncoding.EncodeToString(buf[:n])
			totalLen := len(encodedStr)
			totalChunks := (totalLen + chunkSize - 1) / chunkSize

			if DebugMode {
				log.Printf("[DOWNSTREAM] %s: Read %d bytes from Shadowsocks, queuing %d chunks (Seq: %d)", s.RequestID, n, totalChunks, seq)
			}

			for i := 0; i < totalChunks; i++ {
				start := i * chunkSize
				end := start + chunkSize
				if end > totalLen {
					end = totalLen
				}

				payload := downstreamPayload{
					RequestID:  s.RequestID,
					Seq:        seq,
					Data:       encodedStr[start:end],
					Part:       i + 1,
					TotalParts: totalChunks,
				}
				jsonData, _ := json.Marshal(payload)

				select {
				case cg.DownstreamChan <- string(jsonData):
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	requestID := q.Get("requestid")
	clientID := q.Get("clientid")
	seq, _ := strconv.Atoi(q.Get("seq"))
	part, _ := strconv.Atoi(q.Get("part"))
	totalPart, _ := strconv.Atoi(q.Get("totalpart"))

	var payload postPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		log.Printf("[UPLOAD] Bad Request from %s: %v", r.RemoteAddr, err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	cg := getClientGroup(clientID)

	stateMu.RLock()
	sess, exists := sessions[requestID]
	stateMu.RUnlock()

	if !exists {
		log.Printf("[SESSION] Dialing Shadowsocks for new session %s...", requestID)

		conn, err := net.DialTimeout("tcp", ShadowSocksAddr, 5*time.Second)

		if err == nil {
			ctx, cancel := context.WithCancel(context.Background())
			newSess := &Session{
				RequestID:    requestID,
				ClientID:     clientID,
				Conn:         conn,
				cancel:       cancel,
				postBuffers:  make(map[int]*messageBuffer),
				seenSeqs:     make(map[int]time.Time),
				lastActivity: time.Now(),
			}

			stateMu.Lock()
			if existingSess, stillExists := sessions[requestID]; stillExists {
				sess = existingSess
				conn.Close()
			} else {
				sessions[requestID] = newSess
				sess = newSess
				go sess.startSession(ctx, cg)
				log.Printf("[SESSION] Successfully connected %s to Shadowsocks", requestID)
			}
			stateMu.Unlock()
		} else {
			log.Printf("[SESSION] Failed to connect to Shadowsocks for %s: %v", requestID, err)
			w.WriteHeader(http.StatusGatewayTimeout)
			return
		}
	}

	if sess == nil {
		w.WriteHeader(http.StatusOK)
		return
	}

	if payload.Final {
		log.Printf("[UPLOAD] Received final payload for session %s, closing...", requestID)
		go sess.closeSession()
		w.WriteHeader(http.StatusOK)
		return
	}

	sess.mu.Lock()
	defer sess.mu.Unlock()
	sess.lastActivity = time.Now()

	if _, seen := sess.seenSeqs[seq]; seen && seq != 0 {
		if DebugMode {
			log.Printf("[UPLOAD] Ignoring duplicate chunk Seq %d Part %d/%d for %s", seq, part, totalPart, requestID)
		}
		w.WriteHeader(http.StatusOK)
		return
	}

	if payload.Data != "" {
		if DebugMode {
			log.Printf("[UPLOAD] Received chunk Seq %d Part %d/%d for %s", seq, part, totalPart, requestID)
		}

		mb, ok := sess.postBuffers[seq]
		if !ok {
			mb = &messageBuffer{totalParts: totalPart, parts: make(map[int]string), updatedAt: time.Now()}
			sess.postBuffers[seq] = mb
		}
		mb.parts[part] = payload.Data
		mb.updatedAt = time.Now()

		if len(mb.parts) == mb.totalParts {
			var combined strings.Builder
			for i := 1; i <= mb.totalParts; i++ {
				combined.WriteString(mb.parts[i])
			}
			data, err := base64.StdEncoding.DecodeString(combined.String())

			delete(sess.postBuffers, seq)
			sess.seenSeqs[seq] = time.Now()

			if err == nil {
				if DebugMode {
					log.Printf("[UPLOAD] Reassembled Seq %d for %s, writing %d bytes to Shadowsocks", seq, requestID, len(data))
				}
				sess.writeMutex.Lock()
				sess.Conn.Write(data)
				sess.writeMutex.Unlock()
			} else {
				log.Printf("[UPLOAD] Error decoding base64 for %s seq %d: %v", requestID, seq, err)
			}
		}
	}
	w.WriteHeader(http.StatusOK)
}

func pollHandler(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("clientid")
	cg := getClientGroup(clientID)

	log.Printf("[POLL] Client connected: %s", clientID)

	flusher, canFlush := w.(http.Flusher)

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	timeout := time.After(60 * time.Second)
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
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
		case msg := <-cg.DownstreamChan:
			w.Write([]byte(msg + "\n"))

		drainLoop:
			for i := 0; i < 50; i++ {
				select {
				case m := <-cg.DownstreamChan:
					w.Write([]byte(m + "\n"))
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

func backgroundCleanup() {
	for {
		time.Sleep(1 * time.Minute)
		now := time.Now()
		var expiredSessions []string

		stateMu.RLock()
		for reqID, sess := range sessions {
			sess.mu.Lock()
			inactive := now.Sub(sess.lastActivity) > idleTimeout

			for seq, buf := range sess.postBuffers {
				if now.Sub(buf.updatedAt) > 2*time.Minute {
					if DebugMode {
						log.Printf("[CLEANUP] Evicted stale chunk buffer for %s Seq %d", reqID, seq)
					}
					delete(sess.postBuffers, seq)
				}
			}
			for seq, t := range sess.seenSeqs {
				if now.Sub(t) > 5*time.Minute {
					delete(sess.seenSeqs, seq)
				}
			}
			sess.mu.Unlock()

			if inactive {
				expiredSessions = append(expiredSessions, reqID)
			}
		}
		stateMu.RUnlock()

		for _, reqID := range expiredSessions {
			stateMu.RLock()
			sess, ok := sessions[reqID]
			stateMu.RUnlock()
			if ok {
				sess.closeSession()
				log.Printf("[CLEANUP] Evicted dead session: %s", reqID)
			}
		}
	}
}

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	log.Println("[MAIN] Starting proxy server...")
	go backgroundCleanup()

	mux := http.NewServeMux()
	mux.HandleFunc("/upload", requireAuth(uploadHandler))
	mux.HandleFunc("/poll", requireAuth(pollHandler))
	mux.HandleFunc("/", camouflage) // Catch-all for active probes

	server := &http.Server{
		Addr:         LocalListenAddr,
		Handler:      mux,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	log.Printf("[MAIN] Server listening on https://%s", LocalListenAddr)
	if err := server.ListenAndServeTLS("server.crt", "server.key"); err != nil {
		log.Fatalf("[MAIN] Server failed: %v", err)
	}
}
