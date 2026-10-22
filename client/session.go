package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"mirageproxy/internal/shared"
)

const (
	idleTimeout     = 15 * time.Minute
	maxInFlightSeqs = 32 // per-connection cap on sequences sent but not yet acked
	windowSeqs      = 32 // downstream reorder window size (sequences)
)

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

func lookupFlow(reqID string) *connFlow {
	flowsMu.Lock()
	defer flowsMu.Unlock()
	return flows[reqID]
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
		final := shared.Part{ClientID: myClientID, RequestID: reqID, Final: true}
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
		chunks := shared.Chunk(buffer[:n], chunkSize)

		if DebugMode {
			log.Printf("[LOCAL] Read %d bytes from local connection, queueing %d parts (ReqID: %s, Seq: %d)", n, len(chunks), reqID, seq)
		}

		// Backpressure point: block while this connection already has
		// maxInFlightSeqs unacked. Wakes on acks or on kill().
		if !flow.reserve(seq, len(chunks)) {
			break readLoop
		}

		for i, chunk := range chunks {
			p := shared.Part{
				ClientID:   myClientID,
				RequestID:  reqID,
				Seq:        seq,
				Part:       i + 1,
				TotalParts: len(chunks),
				Data:       chunk,
			}
			enqueueUpload(uploadItem{p: p, reqID: reqID, encoded: mustMarshal(p)})
		}
	}
}

func runPoller(client *http.Client) {
	pollURL := fmt.Sprintf("%s/poll?%s=%s", RemoteServerURL, shared.ParamClientID, myClientID)
	log.Printf("[POLL] Starting downstream poller: %s", pollURL)

	for {
		req, _ := http.NewRequest(http.MethodGet, pollURL, nil)
		shared.SignRequest(req, ProxySecret, shared.PollID(myClientID))
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
			var p shared.Part
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
func processDownstreamPayload(p shared.Part) {
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
	var ready [][]byte
	for {
		mb := w.entries[w.head]
		if mb == nil || len(mb.parts) < mb.total {
			break
		}
		decoded, err := shared.Assemble(mb.parts, mb.total)
		if err != nil {
			log.Printf("[DOWNSTREAM] Base64 decode error for %s: %v", p.RequestID, err)
		}
		delete(w.entries, w.head)
		w.head++
		if err == nil {
			ready = append(ready, decoded)
		}
	}
	downstreamMu.Unlock()

	for _, decoded := range ready {
		sess.writeMutex.Lock()
		writeErr := shared.WriteFull(sess.conn, decoded)
		sess.writeMutex.Unlock()
		if writeErr != nil {
			log.Printf("[DOWNSTREAM] Write error for ReqID %s: %v", p.RequestID, writeErr)
		}
		if DebugMode {
			log.Printf("[DOWNSTREAM] Wrote %d bytes to local connection for ReqID: %s", len(decoded), p.RequestID)
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
				decoded, err := shared.Assemble(mb.parts, mb.total)
				delete(w.entries, w.head)
				w.head++
				if err == nil {
					jobs = append(jobs, flushJob{sess: sess, data: decoded})
				}
			}
		}
		downstreamMu.Unlock()

		for _, j := range jobs {
			j.sess.writeMutex.Lock()
			if err := shared.WriteFull(j.sess.conn, j.data); err != nil {
				log.Printf("[CLEANUP] Downstream write error: %v", err)
			}
			j.sess.writeMutex.Unlock()
		}
	}
}
