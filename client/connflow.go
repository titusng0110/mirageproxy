package main

import (
	"net"
	"sync"
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
