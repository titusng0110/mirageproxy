package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag" // Added for command line flags
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

const DebugMode = false

var (
	ProxySecret     = "default"
	RemoteServerURL = "https://127.0.0.1:30001"
)

const (
	LocalListenAddr = ":30000"
	chunkSize       = 16 * 1024
	idleTimeout     = 15 * time.Minute
)

var myClientID = fmt.Sprintf("client-%d", time.Now().UnixNano())

type downstreamPayload struct {
	RequestID  string `json:"request_id,omitempty"`
	Seq        int    `json:"seq,omitempty"`
	Data       string `json:"data,omitempty"`
	Part       int    `json:"part,omitempty"`
	TotalParts int    `json:"total_parts,omitempty"`
}

type postPayload struct {
	Data  string `json:"data,omitempty"`
	Final bool   `json:"final,omitempty"`
}

type session struct {
	conn         net.Conn
	writeMutex   sync.Mutex
	lastActivity time.Time
	mu           sync.Mutex
}

// writeFull writes the entire buffer to conn, looping until complete.
// net.Conn.Write is allowed to return fewer bytes than requested, so a
// single unchecked call can silently truncate data and corrupt the stream.
func writeFull(conn net.Conn, buf []byte) error {
	for len(buf) > 0 {
		n, err := conn.Write(buf)
		if n > 0 {
			buf = buf[n:]
		}
		if err != nil {
			return err
		}
	}
	return nil
}

type chunkBuffer struct {
	total     int
	parts     map[int]string
	updatedAt time.Time
}

var (
	sessionMu sync.RWMutex
	sessions  = make(map[string]*session)

	downstreamChunks   = make(map[string]*chunkBuffer)
	downstreamChunksMu sync.Mutex
)

func generateSignature(timestamp int64, id string) string {
	msg := fmt.Sprintf("%d:%s", timestamp, id)
	mac := hmac.New(sha256.New, []byte(ProxySecret))
	mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))
}

func getUTLSClient(skipTLSVerify bool) *http.Client {
	uTLSDialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}

		tcpConn, err := net.DialTimeout(network, addr, 10*time.Second)
		if err != nil {
			return nil, err
		}

		config := &utls.Config{
			ServerName:         host,
			InsecureSkipVerify: skipTLSVerify, // Controlled by the command line flag
		}

		uConn := utls.UClient(tcpConn, config, utls.HelloChrome_Auto)
		if err := uConn.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		return uConn, nil
	}

	transport := &http.Transport{
		DialTLSContext:      uTLSDialer,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	}

	return &http.Client{
		Transport: transport,
	}
}

func sendChunk(ctx context.Context, client *http.Client, reqID string, seq, part, totalPart int, payload postPayload) error {
	targetURL := fmt.Sprintf("%s/upload?requestid=%s&clientid=%s&seq=%d&part=%d&totalpart=%d", RemoteServerURL, reqID, myClientID, seq, part, totalPart)
	data, _ := json.Marshal(payload)

	maxRetries := 5
	for attempt := 0; attempt < maxRetries; attempt++ {
		if DebugMode && !payload.Final {
			log.Printf("[UPLOAD] Sending ReqID: %s | Seq: %d | Part: %d/%d (Attempt %d)", reqID, seq, part, totalPart, attempt+1)
		}

		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(data))

		now := time.Now().Unix()
		req.Header.Set("X-Auth-Time", fmt.Sprintf("%d", now))
		req.Header.Set("X-Auth-Sig", generateSignature(now, reqID))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/114.0.0.0")

		resp, err := client.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			return nil // Success
		}

		errStr := "unknown"
		if err != nil {
			errStr = err.Error()
		} else if resp != nil {
			errStr = fmt.Sprintf("HTTP %d", resp.StatusCode)
			resp.Body.Close()
		}

		log.Printf("[UPLOAD] Failed to send chunk ReqID %s Seq %d Part %d/%d: %v. Retrying...", reqID, seq, part, totalPart, errStr)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(attempt+1) * 500 * time.Millisecond):
		}
	}
	return fmt.Errorf("failed to send chunk after %d retries", maxRetries)
}

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
			var payload downstreamPayload
			if err := json.Unmarshal([]byte(line), &payload); err == nil {
				processDownstreamPayload(payload)
			} else {
				log.Printf("[POLL] JSON unmarshal error: %v", err)
			}
		}
		resp.Body.Close()

		if DebugMode {
			log.Printf("[POLL] Remote stream ended, reconnecting...")
		}
	}
}

func processDownstreamPayload(msg downstreamPayload) {
	if DebugMode {
		log.Printf("[DOWNSTREAM] Received ReqID: %s | Seq: %d | Part: %d/%d", msg.RequestID, msg.Seq, msg.Part, msg.TotalParts)
	}

	if msg.TotalParts > 1 {
		chunkKey := fmt.Sprintf("%s-%d", msg.RequestID, msg.Seq)
		downstreamChunksMu.Lock()
		buf, exists := downstreamChunks[chunkKey]
		if !exists {
			buf = &chunkBuffer{total: msg.TotalParts, parts: make(map[int]string), updatedAt: time.Now()}
			downstreamChunks[chunkKey] = buf
		}
		buf.parts[msg.Part] = msg.Data
		buf.updatedAt = time.Now()

		if len(buf.parts) < buf.total {
			downstreamChunksMu.Unlock()
			return
		}

		var combined strings.Builder
		for i := 1; i <= buf.total; i++ {
			combined.WriteString(buf.parts[i])
		}
		delete(downstreamChunks, chunkKey)
		downstreamChunksMu.Unlock()
		msg.Data = combined.String()
	}

	sessionMu.RLock()
	sess, ok := sessions[msg.RequestID]
	sessionMu.RUnlock()
	if !ok {
		if DebugMode {
			log.Printf("[DOWNSTREAM] Discarded payload for unknown/closed ReqID: %s", msg.RequestID)
		}
		return
	}

	decoded, err := base64.StdEncoding.DecodeString(msg.Data)
	if err == nil {
		sess.writeMutex.Lock()
		writeErr := writeFull(sess.conn, decoded)
		sess.writeMutex.Unlock()
		if writeErr != nil {
			log.Printf("[DOWNSTREAM] Write error for ReqID %s: %v", msg.RequestID, writeErr)
		}
		if DebugMode {
			log.Printf("[DOWNSTREAM] Wrote %d bytes to local connection for ReqID: %s", len(decoded), msg.RequestID)
		}
	} else {
		log.Printf("[DOWNSTREAM] Base64 decode error for %s: %v", msg.RequestID, err)
	}
}

func handleConnection(conn net.Conn, client *http.Client) {
	defer conn.Close()
	reqID := fmt.Sprintf("%d-%d", time.Now().UnixNano(), rand.Intn(1000))
	log.Printf("[SESSION] Accepted local connection %s -> mapped to ReqID: %s", conn.RemoteAddr(), reqID)

	sess := &session{conn: conn, lastActivity: time.Now()}

	sessionMu.Lock()
	sessions[reqID] = sess
	sessionMu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	defer func() {
		sessionMu.Lock()
		delete(sessions, reqID)
		sessionMu.Unlock()
		log.Printf("[SESSION] Local connection closed for ReqID: %s. Sending final signal.", reqID)
		sendChunk(context.Background(), client, reqID, 0, 1, 1, postPayload{Final: true})
	}()

	seq := 0
	buffer := make([]byte, 128*1024)

readLoop:
	for {
		conn.SetReadDeadline(time.Now().Add(idleTimeout))
		n, err := conn.Read(buffer)
		if err != nil {
			// Use errors.Is rather than comparing err.Error(): the concrete
			// error may be wrapped (e.g. *net.OpError around io.EOF).
			if !errors.Is(err, io.EOF) {
				log.Printf("[SESSION] Local read error for ReqID %s: %v", reqID, err)
			}
			break
		}

		if n > 0 {
			seq++
			encodedStr := base64.StdEncoding.EncodeToString(buffer[:n])
			totalLen := len(encodedStr)
			totalChunks := (totalLen + chunkSize - 1) / chunkSize

			if DebugMode {
				log.Printf("[LOCAL] Read %d bytes from local connection, splitting into %d chunks (ReqID: %s, Seq: %d)", n, totalChunks, reqID, seq)
			}

			for i := 0; i < totalChunks; i++ {
				start := i * chunkSize
				end := start + chunkSize
				if end > totalLen {
					end = totalLen
				}
				payload := postPayload{Data: encodedStr[start:end]}

				err := sendChunk(ctx, client, reqID, seq, i+1, totalChunks, payload)
				if err != nil {
					log.Printf("[UPLOAD] Fatal chunk send error for %s: %v", reqID, err)
					break readLoop
				}
			}
		}
	}
}

func backgroundCleanup() {
	for {
		time.Sleep(1 * time.Minute)
		downstreamChunksMu.Lock()
		now := time.Now()
		for k, buf := range downstreamChunks {
			if now.Sub(buf.updatedAt) > 2*time.Minute {
				if DebugMode {
					log.Printf("[CLEANUP] Evicted stale downstream chunk buffer: %s", k)
				}
				delete(downstreamChunks, k)
			}
		}
		downstreamChunksMu.Unlock()
	}
}

func main() {
	// ADDED: Testing flag
	testMode := flag.Bool("insecure", false, "Skip TLS verification (Use ONLY for local testing)")
	flag.Parse()

	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	log.Printf("[MAIN] Starting client proxy (ClientID: %s)", myClientID)

	if *testMode {
		log.Println("[MAIN] WARNING: Running in INSECURE mode. TLS certificates will not be verified.")
	}

	go backgroundCleanup()

	// Pass the flag into the HTTP client setup
	httpClient := getUTLSClient(*testMode)
	go runPoller(httpClient)

	ln, err := net.Listen("tcp", LocalListenAddr)
	if err != nil {
		log.Fatalf("[MAIN] Failed to listen: %v", err)
	}
	defer ln.Close()

	log.Printf("[MAIN] Client listening on %s", LocalListenAddr)
	log.Printf("[MAIN] Proxying traffic to: %s", RemoteServerURL)

	for {
		conn, err := ln.Accept()
		if err == nil {
			go handleConnection(conn, httpClient)
		} else {
			log.Printf("[MAIN] Accept error: %v", err)
		}
	}
}
