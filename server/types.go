package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
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
	LocalListenAddr     = ":30001"
	ShadowSocksAddr     = "127.0.0.1:5080"
	readTimeout         = 180 * time.Second
	downstreamChunkSize = 8 * 1024 // server→client part size: small enough to piggyback on POST responses
	piggybackBudget     = 8 * 1024 // max downstream data attached to one upload response
	idleTimeout         = 15 * time.Minute
	downstreamQueueCap  = 8192             // global downstream queue (parts); producers block when full
	groupQueueCap       = 2000             // per-client downstream buffer drained by /poll and upload responses
	windowSeqs          = 32               // per-session upload reorder window (sequences)
	finalGrace          = 10 * time.Second // how long a finalized session waits for its window to drain
	tombstoneTTL        = 2 * time.Minute  // how late parts for a closed session are NAKed instead of recreated

	// Connection rotation: no TCP connection is allowed to live long
	// enough for DPI flow heuristics to single it out as a tunnel. Each
	// connection gets a uniformly random lifetime in this range and is
	// then wound down — HTTP/2 with a graceful GOAWAY, HTTP/1.1 with a
	// plain close — so rotation reads as routine server maintenance.
	rotateMinAge       = 60 * time.Second  // shortest allowed connection lifetime
	rotateMaxAge       = 300 * time.Second // longest allowed connection lifetime
	rotateGrace        = 20 * time.Second  // drain window after GOAWAY before force-close
	rotateSweepEvery   = 5 * time.Second   // rotator sweep cadence
	minAgeBeforeGOAWAY = 5 * time.Second   // never inject GOAWAY before the handshake window settles
	handshakeTimeout   = 10 * time.Second  // bound on the accept-path TLS handshake
	goawayWriteTimeout = 2 * time.Second   // bound on the injected GOAWAY write; a stalled write must not freeze the rotator
)

// part is the single self-describing unit of transfer in both directions.
// Upstream it arrives inside a POST batch; downstream it is one NDJSON line.
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

// postBatch is the upload request body: parts gathered by the client's
// dispatcher workers, totalling at most ~16KB of marshalled payload.
type postBatch struct {
	Parts []part `json:"parts"`
}

// ackPayload is the upload response. Acked is one '0'/'1' bit per uploaded
// part, in batch order: '1' means the part was accepted (buffered, duplicate
// of already-flushed data, or final marker); '0' means the client must
// retry. Downstream, when present, piggybacks queued downstream parts on
// the response so download traffic also moves on upload round-trips.
type ackPayload struct {
	Acked      string `json:"acked"`
	Downstream []part `json:"downstream,omitempty"`
}

type messageBuffer struct {
	totalParts int
	parts      map[int]string
	updatedAt  time.Time
}

// rxWindow is the upload reorder window for one session: the next sequence
// expected at the head plus buffered future sequences. Data is written to
// Shadowsocks only when the head sequence is fully assembled, cascading
// through any complete sequences behind it.
type rxWindow struct {
	head      int
	entries   map[int]*messageBuffer
	updatedAt time.Time
}

type ClientGroup struct {
	DownstreamChan chan part
	LastActive     time.Time
}

type Session struct {
	RequestID    string
	ClientID     string
	Conn         net.Conn
	writeMutex   sync.Mutex
	cancel       context.CancelFunc
	mu           sync.Mutex
	win          *rxWindow
	closed       bool
	finalSeen    bool
	finalizer    bool // finalizer goroutine started
	lastActivity time.Time
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

var (
	stateMu      sync.RWMutex
	sessions     = make(map[string]*Session)
	clientGroups = make(map[string]*ClientGroup)

	tombstonesMu sync.Mutex
	tombstones   = make(map[string]time.Time)

	// Global downstream queue: every session pushes its parts here, and a
	// single router goroutine fans them out to the per-client buffers.
	downstream = make(chan part, downstreamQueueCap)
)

func generateSignature(timestamp int64, id string) string {
	msg := fmt.Sprintf("%d:%s", timestamp, id)
	mac := hmac.New(sha256.New, []byte(ProxySecret))
	mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))
}
