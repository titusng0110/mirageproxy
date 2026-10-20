package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
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
	"golang.org/x/net/http2"
)

const DebugMode = true

var (
	ProxySecret     = "default"
	RemoteServerURL = "https://127.0.0.1:30001"
)

const (
	LocalListenAddr      = ":30000"
	chunkSize            = 16 * 1024 // max base64 payload per part, and the per-POST batch budget
	idleTimeout          = 15 * time.Minute
	uploadQueueCap       = 8192                 // global upload queue capacity (parts); producers block when full
	dispatcherWorkers    = 4                    // workers draining the global upload queue
	dispatchPollInterval = 7 * time.Millisecond // queue recheck cadence when the queue is empty
	maxInFlightSeqs      = 32                   // per-connection cap on sequences sent but not yet acked
	windowSeqs           = 32                   // downstream reorder window size (sequences)
	maxSendAttempts      = 5                    // per-part retries before the connection is killed
	postAttemptTimeout   = 60 * time.Second     // per-POST attempt deadline
)

var myClientID = fmt.Sprintf("client-%d", time.Now().UnixNano())

// part is the single self-describing unit of transfer in both directions.
// Upstream it rides inside a POST batch; downstream it is one NDJSON line.
// Because every part carries its request/seq/part coordinates, sequences may
// be fired and delivered out of order and be reassembled at the destination.
type part struct {
	ClientID   string `json:"client_id,omitempty"`
	RequestID  string `json:"request_id,omitempty"`
	Seq        int    `json:"seq"`
	Part       int    `json:"part"`
	TotalParts int    `json:"total_parts"`
	Data       string `json:"data,omitempty"`
	Final      bool   `json:"final,omitempty"`
}

// ackPayload is the upload response. Acked is one '0'/'1' bit per uploaded
// part, in batch order: '1' means the server accepted the part (buffered,
// duplicate of already-flushed data, or final marker); '0' means it must be
// retried. Downstream, when present, piggybacks queued downstream parts on
// the response — a second delivery lane alongside the /poll stream.
type ackPayload struct {
	Acked      string `json:"acked"`
	Downstream []part `json:"downstream,omitempty"`
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

// connFlow tracks the upload state of one local connection: how many
// sequences are sent-but-unacked, and whether the connection has been
// condemned (a part exhausted its retries). It is also the backpressure
// point between sslocal and the tunnel: when the window fills, the local
// reader blocks, the TCP receive buffer fills, and sslocal stalls with it.
type connFlow struct {
	mu       sync.Mutex
	cond     *sync.Cond
	conn     net.Conn
	dead     bool
	inflight map[int]int // seq -> parts sent but not yet acked
}

func newConnFlow(conn net.Conn) *connFlow {
	f := &connFlow{conn: conn, inflight: make(map[int]int)}
	f.cond = sync.NewCond(&f.mu)
	return f
}

// reserve blocks until the connection has in-flight window capacity, then
// records a sequence's parts as in-flight. It returns false if the
// connection was condemned while waiting.
func (f *connFlow) reserve(seq, totalParts int) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for !f.dead && len(f.inflight) >= maxInFlightSeqs {
		f.cond.Wait()
	}
	if f.dead {
		return false
	}
	f.inflight[seq] = totalParts
	return true
}

// ack records one acknowledged part of a sequence; the sequence leaves the
// in-flight window once its last part is acknowledged.
func (f *connFlow) ack(seq int) {
	f.mu.Lock()
	if remaining, ok := f.inflight[seq]; ok {
		if remaining > 1 {
			f.inflight[seq] = remaining - 1
		} else {
			delete(f.inflight, seq)
		}
		f.cond.Broadcast()
	}
	f.mu.Unlock()
}

// kill condemns the connection: it wakes any reader waiting for window
// capacity and forces the blocked read to fail.
func (f *connFlow) kill() {
	f.mu.Lock()
	if f.dead {
		f.mu.Unlock()
		return
	}
	f.dead = true
	f.conn.Close()
	f.cond.Broadcast()
	f.mu.Unlock()
}

type chunkBuffer struct {
	total     int
	parts     map[int]string
	updatedAt time.Time
}

// rxWindow is the downstream reorder window for one session: the next
// sequence expected at the head plus buffered future sequences.
type rxWindow struct {
	head    int
	entries map[int]*chunkBuffer
}

var (
	sessionMu sync.RWMutex
	sessions  = make(map[string]*session)

	downstreamMu      sync.Mutex
	downstreamWindows = make(map[string]*rxWindow)

	// Global upload queue. Every local connection feeds it; a fixed pool of
	// dispatcher workers drains it. Items are FIFO; requeued (retried) parts
	// go to the front so gaps fill first.
	uploadMu      sync.Mutex
	uploadNotFull = sync.NewCond(&uploadMu)
	uploadQueue   []uploadItem

	flowsMu sync.Mutex
	flows   = make(map[string]*connFlow)
)

type uploadItem struct {
	p        part
	reqID    string
	encoded  []byte // pre-marshalled JSON for this part
	attempts int
}

func generateSignature(timestamp int64, id string) string {
	msg := fmt.Sprintf("%d:%s", timestamp, id)
	mac := hmac.New(sha256.New, []byte(ProxySecret))
	mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))
}

var ErrALPNFallback = errors.New("server negotiated http/1.1")

type SmartTransport struct {
	H2 *http2.Transport
	H1 *http.Transport

	mu           sync.RWMutex
	fallbackMode bool
	h1Until      time.Time
}

func (t *SmartTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.RLock()
	useH1 := t.fallbackMode && time.Now().Before(t.h1Until)
	t.mu.RUnlock()

	if useH1 {
		return t.H1.RoundTrip(req)
	}

	resp, err := t.H2.RoundTrip(req)

	if err != nil {
		if errors.Is(err, ErrALPNFallback) {
			if DebugMode {
				log.Println("[TLS] ALPN negotiated HTTP/1.1. Instant fallback.")
			}
			return t.H1.RoundTrip(req)
		}

		// RACE CONDITION FIX: Don't penalize H2 if the server just isn't booted yet.
		// If the error is a local dial failure, the GFW didn't block us.
		var opErr *net.OpError
		if errors.As(err, &opErr) && opErr.Op == "dial" {
			return resp, err
		}
		if strings.Contains(err.Error(), "connection refused") {
			return resp, err
		}

		t.mu.Lock()
		t.fallbackMode = true
		t.h1Until = time.Now().Add(5 * time.Minute)
		t.mu.Unlock()

		if DebugMode {
			log.Printf("[TLS] HTTP/2 flow interrupted: %v. Falling back to HTTP/1.1 for 5 mins.", err)
		}
		return resp, err
	}

	return resp, nil
}

func getUTLSClient(skipTLSVerify bool) *http.Client {
	// H2 Dialer: Requires the server to negotiate HTTP/2
	dialH2 := func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
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
			InsecureSkipVerify: skipTLSVerify,
		}
		uConn := utls.UClient(tcpConn, config, utls.HelloChrome_Auto)
		if err := uConn.HandshakeContext(ctx); err != nil {
			return nil, err
		}

		if uConn.ConnectionState().NegotiatedProtocol != "h2" {
			uConn.Close()
			return nil, ErrALPNFallback
		}
		return uConn, nil
	}

	// H1 Dialer: Forces the server into HTTP/1.1 mode
	dialH1 := func(ctx context.Context, network, addr string) (net.Conn, error) {
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
			InsecureSkipVerify: skipTLSVerify,
		}
		uConn := utls.UClient(tcpConn, config, utls.HelloChrome_Auto)

		// ALPN MISMATCH FIX: Build the Chrome ClientHello, then manually overwrite
		// the ALPN extension to ONLY offer http/1.1. This keeps the Chrome fingerprint
		// perfectly intact but forces the server to speak HTTP/1.1.
		if err := uConn.BuildHandshakeState(); err != nil {
			return nil, err
		}
		for _, ext := range uConn.Extensions {
			if alpn, ok := ext.(*utls.ALPNExtension); ok {
				alpn.AlpnProtocols = []string{"http/1.1"}
			}
		}

		if err := uConn.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		return uConn, nil
	}

	tH2 := &http2.Transport{
		DialTLSContext:             dialH2,
		StrictMaxConcurrentStreams: true,
	}

	tH1 := &http.Transport{
		DialTLSContext:      dialH1,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	}

	return &http.Client{
		Transport: &SmartTransport{
			H2: tH2,
			H1: tH1,
		},
	}
}

func mustMarshal(v any) []byte {
	// part contains only strings and ints; marshalling cannot fail.
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func lookupFlow(reqID string) *connFlow {
	flowsMu.Lock()
	defer flowsMu.Unlock()
	return flows[reqID]
}

// enqueueUpload appends an item to the global queue, blocking while it is
// full. Blocking here is what propagates server-side stall back to the
// local reader (and from there to sslocal).
func enqueueUpload(item uploadItem) {
	uploadMu.Lock()
	for len(uploadQueue) >= uploadQueueCap {
		uploadNotFull.Wait()
	}
	uploadQueue = append(uploadQueue, item)
	uploadMu.Unlock()
}

// requeueFront puts failed items back at the head of the queue so gaps fill
// first. It never blocks: the queue just shrank by at least len(items).
func requeueFront(items []uploadItem) {
	if len(items) == 0 {
		return
	}
	uploadMu.Lock()
	uploadQueue = append(items, uploadQueue...)
	uploadMu.Unlock()
	uploadNotFull.Broadcast()
}

// gatherBatch waits for work and takes items from the front of the global
// queue until the batch would exceed the 16KB POST budget. When the queue
// is empty it rechecks every dispatchPollInterval. The returned batch is a
// copy, so callers may hold it across queue mutations.
func gatherBatch() []uploadItem {
	for {
		uploadMu.Lock()
		count := 0
		size := 0
		for count < len(uploadQueue) {
			sz := len(uploadQueue[count].encoded)
			if count > 0 && size+sz > chunkSize {
				break
			}
			size += sz
			count++
		}
		if count == 0 {
			uploadMu.Unlock()
			time.Sleep(dispatchPollInterval)
			continue
		}
		batch := make([]uploadItem, count)
		copy(batch, uploadQueue[:count])
		uploadQueue = uploadQueue[count:]
		uploadMu.Unlock()
		uploadNotFull.Broadcast()
		return batch
	}
}

// fireBatch performs one HTTP POST carrying the batch and returns one ack
// bit per part plus any downstream parts that piggybacked on the response.
// A transport error, non-200 status, or unparseable ack body returns an
// error, which the caller treats as "nothing acked".
func fireBatch(client *http.Client, batch []uploadItem) ([]bool, []part, error) {
	var body bytes.Buffer
	body.WriteString(`{"parts":[`)
	for i := range batch {
		if i > 0 {
			body.WriteByte(',')
		}
		body.Write(batch[i].encoded)
	}
	body.WriteString(`]}`)

	targetURL := fmt.Sprintf("%s/upload?clientid=%s", RemoteServerURL, myClientID)

	ctx, cancel := context.WithTimeout(context.Background(), postAttemptTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(body.Bytes()))
	if err != nil {
		return nil, nil, err
	}

	now := time.Now().Unix()
	req.Header.Set("X-Auth-Time", fmt.Sprintf("%d", now))
	req.Header.Set("X-Auth-Sig", generateSignature(now, "upload-"+myClientID))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36")

	if DebugMode {
		log.Printf("[UPLOAD] POST batch of %d part(s), %d bytes", len(batch), body.Len())
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var ack ackPayload
	if err := json.NewDecoder(resp.Body).Decode(&ack); err != nil {
		return nil, nil, fmt.Errorf("bad ack body: %v", err)
	}

	acks := make([]bool, len(batch))
	for i := range acks {
		acks[i] = i < len(ack.Acked) && ack.Acked[i] == '1'
	}
	return acks, ack.Downstream, nil
}

func maxAttemptsIn(batch []uploadItem) int {
	m := 1
	for i := range batch {
		if batch[i].attempts > m {
			m = batch[i].attempts
		}
	}
	return m
}

// dispatcherWorker drains the global upload queue. Acked parts are retired;
// unacked parts are requeued at the front and retried up to maxSendAttempts
// times, after which their connection is condemned.
func dispatcherWorker(client *http.Client) {
	for {
		batch := gatherBatch()
		acks, riders, err := fireBatch(client, batch)

		hardFail := err != nil
		if hardFail && DebugMode {
			log.Printf("[UPLOAD] Batch failed: %v", err)
		}

		// Deliver downstream parts that piggybacked on this response. Safe
		// to call from any worker: processDownstreamPayload is built for
		// concurrent callers (mutexes on the session registry, windows and
		// socket writes), and per-session order is preserved by the windows
		// regardless of which lane delivered a part.
		for _, p := range riders {
			processDownstreamPayload(p)
		}
		if DebugMode && len(riders) > 0 {
			log.Printf("[UPLOAD] Response carried %d downstream part(s)", len(riders))
		}

		var requeue []uploadItem
		for i := range batch {
			item := batch[i]
			if !hardFail && acks[i] {
				if fl := lookupFlow(item.reqID); fl != nil {
					fl.ack(item.p.Seq)
				}
				continue
			}
			item.attempts++
			if item.attempts >= maxSendAttempts {
				log.Printf("[UPLOAD] Part for %s seq %d exhausted %d attempts; killing connection",
					item.reqID, item.p.Seq, maxSendAttempts)
				if fl := lookupFlow(item.reqID); fl != nil {
					fl.kill()
				}
				continue
			}
			requeue = append(requeue, item)
		}

		if len(requeue) > 0 {
			if hardFail {
				// Back off after a hard failure so a down/unreachable server
				// does not burn through every part's retry budget instantly.
				backoff := time.Duration(maxAttemptsIn(batch)) * 500 * time.Millisecond
				if backoff > 2*time.Second {
					backoff = 2 * time.Second
				}
				time.Sleep(backoff)
			}
			requeueFront(requeue)
		}
	}
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

func handleConnection(conn net.Conn) {
	defer conn.Close()
	reqID := fmt.Sprintf("%d-%d", time.Now().UnixNano(), rand.Intn(1000))
	log.Printf("[SESSION] Accepted local connection %s -> mapped to ReqID: %s", conn.RemoteAddr(), reqID)

	sess := &session{conn: conn, lastActivity: time.Now()}

	sessionMu.Lock()
	sessions[reqID] = sess
	sessionMu.Unlock()

	flow := newConnFlow(conn)
	flowsMu.Lock()
	flows[reqID] = flow
	flowsMu.Unlock()

	defer func() {
		sessionMu.Lock()
		delete(sessions, reqID)
		sessionMu.Unlock()
		flowsMu.Lock()
		delete(flows, reqID)
		flowsMu.Unlock()
		downstreamMu.Lock()
		delete(downstreamWindows, reqID)
		downstreamMu.Unlock()

		log.Printf("[SESSION] Local connection closed for ReqID: %s. Sending final signal.", reqID)
		// The final marker is a regular queue item; being a single producer
		// per connection, FIFO ordering places it after this connection's
		// data parts.
		final := part{ClientID: myClientID, RequestID: reqID, Final: true}
		enqueueUpload(uploadItem{p: final, reqID: reqID, encoded: mustMarshal(final)})
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
		if n == 0 {
			continue
		}

		seq++
		encodedStr := base64.StdEncoding.EncodeToString(buffer[:n])
		totalChunks := (len(encodedStr) + chunkSize - 1) / chunkSize

		if DebugMode {
			log.Printf("[LOCAL] Read %d bytes from local connection, queueing %d parts (ReqID: %s, Seq: %d)", n, totalChunks, reqID, seq)
		}

		// Backpressure point: block while this connection already has
		// maxInFlightSeqs unacked. Wakes on acks or on kill().
		if !flow.reserve(seq, totalChunks) {
			break readLoop
		}

		for i := 0; i < totalChunks; i++ {
			start := i * chunkSize
			end := start + chunkSize
			if end > len(encodedStr) {
				end = len(encodedStr)
			}
			p := part{
				ClientID:   myClientID,
				RequestID:  reqID,
				Seq:        seq,
				Part:       i + 1,
				TotalParts: totalChunks,
				Data:       encodedStr[start:end],
			}
			enqueueUpload(uploadItem{p: p, reqID: reqID, encoded: mustMarshal(p)})
		}
	}
}

func backgroundCleanup() {
	for {
		time.Sleep(1 * time.Minute)
		now := time.Now()

		type flushJob struct {
			sess *session
			data []byte
		}
		var jobs []flushJob

		downstreamMu.Lock()
		for reqID, w := range downstreamWindows {
			sessionMu.RLock()
			sess, alive := sessions[reqID]
			sessionMu.RUnlock()
			if !alive {
				delete(downstreamWindows, reqID)
				continue
			}

			// Slide the head past a sequence that never completed, so a
			// permanently lost part cannot wedge the window forever.
			for {
				mb := w.entries[w.head]
				if mb == nil || now.Sub(mb.updatedAt) <= 2*time.Minute {
					break
				}
				if DebugMode {
					log.Printf("[CLEANUP] Dropping stalled downstream seq %d for %s", w.head, reqID)
				}
				delete(w.entries, w.head)
				w.head++
			}

			// Evict stale buffers anywhere in the window.
			for s, mb := range w.entries {
				if now.Sub(mb.updatedAt) > 2*time.Minute {
					delete(w.entries, s)
				}
			}

			// Flush anything that became complete after sliding. Writes are
			// deferred out of the locked section.
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
				if decoded, err := base64.StdEncoding.DecodeString(combined.String()); err == nil {
					jobs = append(jobs, flushJob{sess: sess, data: decoded})
				}
			}
		}
		downstreamMu.Unlock()

		for _, j := range jobs {
			j.sess.writeMutex.Lock()
			if err := writeFull(j.sess.conn, j.data); err != nil {
				log.Printf("[CLEANUP] Downstream write error: %v", err)
			}
			j.sess.writeMutex.Unlock()
		}
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

	for i := 0; i < dispatcherWorkers; i++ {
		go dispatcherWorker(httpClient)
	}

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
			go handleConnection(conn)
		} else {
			log.Printf("[MAIN] Accept error: %v", err)
		}
	}
}
