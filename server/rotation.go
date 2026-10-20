package main

import (
	"context"
	"crypto/tls"
	"log"
	"math/rand"
	"net"
	"sync"
	"time"
)

// ============================================================================
// Connection rotation
//
// DPI flow heuristics single out TCP connections that stay up far longer
// than any real browsing session would; a tunnel connection living for
// hours is exactly such a signature. The rotator instead gives every
// accepted connection a uniformly random lifetime and then winds it down:
//
//   - HTTP/2 connections get a graceful GOAWAY(NO_ERROR) injected — the
//     RFC 7540 server-maintenance pattern — followed by a short drain so
//     in-flight streams (upload POSTs collecting their acks, poll streams)
//     finish before the force-close backstop. Clients move to a fresh
//     connection without erroring, so they stay on HTTP/2.
//   - HTTP/1.1 connections are closed outright, indistinguishable from
//     ordinary keep-alive expiry.
// ============================================================================

// connCtxKey is the context key under which handlers find the tracked
// connection serving their request (threaded in via Server.ConnContext).
type connCtxKey struct{}

// trackedConn wraps an accepted TLS connection so the rotator can age it
// out. Write serializes every writer — the HTTP/2 stack's frames and the
// rotator's injected GOAWAY alike — under one mutex, so the injected frame
// is always emitted as a self-contained TLS record between other writes.
//
// Residual (accepted) risk: a >4KB frame written into the HTTP/2 stack's
// non-empty 4KB buffer is flushed in two socket writes, and a GOAWAY can
// in principle land between the halves. The gap between those two writes
// is microseconds, and a rotation happens once every 60-300 seconds, so
// the per-rotation probability is on the order of 1e-7; when it does
// happen the client treats it as a connection error and recovers through
// the existing retry/reconnect paths.
type trackedConn struct {
	net.Conn

	// tlsConn is the underlying TLS connection. The delegating accessors
	// below expose it so net/http's connectionStater and
	// handshakeContexter interfaces keep working through the wrapper —
	// embedding net.Conn alone does NOT promote the concrete type's
	// methods, and losing ConnectionState() makes the server misread the
	// negotiated protocol and serve h2 connections as HTTP/1.
	tlsConn *tls.Conn

	writeMu sync.Mutex // serializes server writes with rotator-injected frames

	stateMu    sync.Mutex
	proto      string // negotiated ALPN: "h2", "http/1.1", or "" pre-handshake
	rotating   bool   // rotation has begun (set exactly once, by the rotator)
	goawaySent bool   // a GOAWAY frame was successfully injected

	created time.Time // accept time (immutable)
	closeAt time.Time // randomized rotation deadline (immutable)

	drainOnce sync.Once
	drainCh   chan struct{} // closed when rotation begins; poll handlers watch this
}

func newTrackedConn(c net.Conn) *trackedConn {
	now := time.Now()
	tc := &trackedConn{
		Conn:    c,
		created: now,
		// Uniformly random lifetime, resampled per connection, so rotation
		// has no observable period.
		closeAt: now.Add(rotateMinAge + time.Duration(rand.Int63n(int64(rotateMaxAge-rotateMinAge)+1))),
		drainCh: make(chan struct{}),
	}
	if tlsConn, ok := c.(*tls.Conn); ok {
		tc.tlsConn = tlsConn
	}
	return tc
}

// Write serializes every socket write — HTTP/2 frames from the server
// stack and the rotator's injected GOAWAY alike — under one mutex, so an
// injected frame can never interleave with server output except between
// complete Write calls.
func (c *trackedConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.Conn.Write(p)
}

// ConnectionState delegates to the underlying TLS connection.
func (c *trackedConn) ConnectionState() tls.ConnectionState {
	if c.tlsConn != nil {
		return c.tlsConn.ConnectionState()
	}
	return tls.ConnectionState{}
}

// HandshakeContext delegates to the underlying TLS connection, so the
// accept-path handshake and net/http's own handshake call serialize on the
// same connection (the second caller returns once the first is done).
func (c *trackedConn) HandshakeContext(ctx context.Context) error {
	if c.tlsConn != nil {
		return c.tlsConn.HandshakeContext(ctx)
	}
	return nil
}

// setProto records the negotiated ALPN protocol; called once from the
// accept-path handshake goroutine.
func (c *trackedConn) setProto(proto string) {
	c.stateMu.Lock()
	c.proto = proto
	c.stateMu.Unlock()
}

func (c *trackedConn) alpn() string {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	return c.proto
}

// label names the protocol for logs, spelling out pre-handshake
// connections instead of printing an empty field.
func (c *trackedConn) label() string {
	if p := c.alpn(); p != "" {
		return p
	}
	return "unidentified"
}

func (c *trackedConn) markRotating() {
	c.stateMu.Lock()
	c.rotating = true
	c.stateMu.Unlock()
}

func (c *trackedConn) isRotating() bool {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	return c.rotating
}

func (c *trackedConn) goawayWasSent() bool {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	return c.goawaySent
}

// beginDrain marks the connection as rotating. Poll handlers watching
// drainCh return immediately, ending their streams cleanly; the client's
// poller then reconnects on a fresh connection instead of seeing a chop.
func (c *trackedConn) beginDrain() {
	c.drainOnce.Do(func() { close(c.drainCh) })
}

// sendGOAWAY injects one minimal GOAWAY frame — error code NO_ERROR, last
// stream ID 2^31-1 — onto an HTTP/2 connection: the RFC 7540 graceful
// shutdown pattern. The peer finishes its in-flight streams and moves new
// ones to a fresh connection; because no stream ID can exceed 2^31-1, the
// promise "I will still process anything already opened" holds even for a
// stream the peer raced past the GOAWAY. Returns true when the frame
// went out.
//
// The write is bounded by goawayWriteTimeout and runs under writeMu (with
// a temporary socket write deadline that is cleared before release): a
// wedged peer can block a socket write indefinitely, and a blocked write
// here would stall the rotator — and with it all future rotation, which
// is the one failure mode this whole feature must not have. Holding
// writeMu across the deadline window also prevents a concurrent server
// frame write from racing the temporary deadline and spuriously failing.
func (c *trackedConn) sendGOAWAY() bool {
	frame := []byte{
		0x00, 0x00, 0x08, // length: 8-byte payload
		0x07,                   // type: GOAWAY
		0x00,                   // flags: none
		0x00, 0x00, 0x00, 0x00, // stream ID: 0 (connection-level)
		0x7f, 0xff, 0xff, 0xff, // last stream ID: 2^31-1
		0x00, 0x00, 0x00, 0x00, // error code: NO_ERROR
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.Conn.SetWriteDeadline(time.Now().Add(goawayWriteTimeout))
	_, err := c.Conn.Write(frame)
	c.Conn.SetWriteDeadline(time.Time{})
	if err != nil {
		// The connection is already dead (peer vanished, handshake
		// never finished) or the write timed out against a wedged peer;
		// the force-close sweep reaps it regardless.
		log.Printf("[ROTATE] GOAWAY write to %s failed: %v", c.RemoteAddr(), err)
		return false
	}
	c.stateMu.Lock()
	c.goawaySent = true
	c.stateMu.Unlock()
	return true
}

var (
	trackedMu sync.Mutex
	tracked   = make(map[*trackedConn]struct{}) // every accepted, not-yet-reaped connection
)

func trackConn(tc *trackedConn) {
	trackedMu.Lock()
	tracked[tc] = struct{}{}
	trackedMu.Unlock()
}

func untrackConn(tc *trackedConn) {
	trackedMu.Lock()
	delete(tracked, tc)
	trackedMu.Unlock()
}

// rotatingListener wraps the TLS listener, registering every accepted
// connection with the rotator and completing the TLS handshake off the
// accept path. The handshake result (the negotiated ALPN protocol) decides
// how the connection is later rotated, and doing it in a goroutine keeps a
// slow or malicious client from stalling the accept loop; net/http's own
// handshake call, if it gets there first, simply waits on the result.
type rotatingListener struct {
	net.Listener
}

func (ln *rotatingListener) Accept() (net.Conn, error) {
	c, err := ln.Listener.Accept()
	if err != nil {
		return nil, err
	}
	tc := newTrackedConn(c)
	trackConn(tc)
	go func() {
		tlsConn, ok := tc.Conn.(*tls.Conn)
		if !ok {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
		defer cancel()
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			// net/http sees the same failure and drops the conn; there
			// is nothing left to rotate.
			untrackConn(tc)
			return
		}
		tc.setProto(tlsConn.ConnectionState().NegotiatedProtocol)
	}()
	return tc, nil
}

// rotateLoop ages every tracked connection out on its randomized deadline.
// Entries are always untracked by closeAt+rotateGrace at the latest, so
// the registry cannot grow without bound even if the peer closes first.
func rotateLoop() {
	for {
		time.Sleep(rotateSweepEvery)
		now := time.Now()

		// Decide under the lock, act outside it: GOAWAY writes and closes
		// can block on a wedged peer and must not stall the next sweep.
		var goaway, closeNow []*trackedConn
		trackedMu.Lock()
		for tc := range tracked {
			if !tc.isRotating() && now.After(tc.closeAt) {
				tc.markRotating()
				if tc.alpn() == "h2" && now.Sub(tc.created) >= minAgeBeforeGOAWAY {
					goaway = append(goaway, tc)
				} else {
					// HTTP/1.1 has no GOAWAY equivalent — a plain close is
					// indistinguishable from ordinary keep-alive expiry.
					// An unidentified protocol (handshake still unsettled)
					// is closed the same way.
					closeNow = append(closeNow, tc)
				}
				continue
			}
			if tc.isRotating() && now.After(tc.closeAt.Add(rotateGrace)) {
				closeNow = append(closeNow, tc)
			}
		}
		trackedMu.Unlock()

		for _, tc := range goaway {
			// GOAWAY first: once the frame is on the wire the client's
			// transport marks this connection as going-away, so the poll
			// handlers' exit (and the client's immediate reconnect) lands
			// on a fresh connection instead of racing back onto this one
			// and getting chopped at the force-close backstop.
			if tc.sendGOAWAY() {
				log.Printf("[ROTATE] GOAWAY(NO_ERROR) sent to %s (%s) at age %s; force-close in %s",
					tc.RemoteAddr(), tc.label(), now.Sub(tc.created).Round(time.Second), rotateGrace)
			}
			tc.beginDrain()
		}
		for _, tc := range closeNow {
			if tc.goawayWasSent() {
				log.Printf("[ROTATE] Force-closed %s %s after drain (age %s)",
					tc.label(), tc.RemoteAddr(), now.Sub(tc.created).Round(time.Second))
			} else {
				log.Printf("[ROTATE] Closed %s %s at age %s",
					tc.label(), tc.RemoteAddr(), now.Sub(tc.created).Round(time.Second))
			}
			tc.Close()
			untrackConn(tc)
		}
	}
}
