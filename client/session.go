package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"time"
)

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
