package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"time"
)

const DebugMode = false

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
