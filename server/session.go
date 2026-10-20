package main

import (
	"context"
	"encoding/base64"
	"log"
	"net"
	"strings"
	"time"
)

func getClientGroup(clientID string) *ClientGroup {
	stateMu.Lock()
	defer stateMu.Unlock()
	cg, exists := clientGroups[clientID]
	if !exists {
		cg = &ClientGroup{
			DownstreamChan: make(chan part, groupQueueCap),
			LastActive:     time.Now(),
		}
		clientGroups[clientID] = cg
		log.Printf("[CLIENT] New client group created: %s", clientID)
	}
	cg.LastActive = time.Now()
	return cg
}

// downstreamRouter drains the global downstream queue and fans each part
// out to the owning client's buffer. The send blocks when a client's buffer
// is full, which backs up the global queue and ultimately the sessions
// feeding it — the backpressure path from a stalled /poll reader all the
// way to ssserver.
func downstreamRouter() {
	for p := range downstream {
		cg := getClientGroup(p.ClientID)
		// Blocking send: a full client buffer backs pressure up through the
		// global queue to the sessions producing it. Consumers marshal at
		// delivery time (/poll lines and upload-response piggybacks).
		cg.DownstreamChan <- p
	}
}

func (s *Session) closeSession() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.mu.Unlock()

	if s.cancel != nil {
		s.cancel()
	}
	if s.Conn != nil {
		s.Conn.Close()
	}
	stateMu.Lock()
	delete(sessions, s.RequestID)
	stateMu.Unlock()
	// Tombstone the request so late retried parts are NAKed instead of
	// resurrecting a zombie Shadowsocks connection.
	tombstonesMu.Lock()
	tombstones[s.RequestID] = time.Now()
	tombstonesMu.Unlock()
	// Tell the client the session is gone so its local connection fails
	// fast instead of hanging. Best effort: if the downstream queue is
	// momentarily full the signal is dropped and the client falls back to
	// its own idle handling.
	if s.ClientID != "" {
		select {
		case downstream <- part{ClientID: s.ClientID, RequestID: s.RequestID, Final: true}:
		default:
		}
	}
	log.Printf("[SESSION] Closed session %s", s.RequestID)
}

// beginDrain marks the session as finalized. The session is closed once the
// reorder window has fully drained, or after finalGrace, so the final
// marker can never race past still-in-flight parts. It returns false when
// the session is already closed (the final marker is then NAKed).
func (s *Session) beginDrain() bool {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return false
	}
	s.finalSeen = true
	if s.finalizer {
		s.mu.Unlock()
		return true
	}
	s.finalizer = true
	s.mu.Unlock()

	go func() {
		deadline := time.Now().Add(finalGrace)
		for {
			s.mu.Lock()
			buffered := len(s.win.entries)
			s.mu.Unlock()
			if buffered == 0 || time.Now().After(deadline) {
				if buffered > 0 && DebugMode {
					log.Printf("[SESSION] Final grace expired for %s with %d buffered seq(s)", s.RequestID, buffered)
				}
				s.closeSession()
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()
	return true
}

func (s *Session) startSession(ctx context.Context) {
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
			totalChunks := (totalLen + downstreamChunkSize - 1) / downstreamChunkSize

			if DebugMode {
				log.Printf("[DOWNSTREAM] %s: Read %d bytes from Shadowsocks, queueing %d parts (Seq: %d)", s.RequestID, n, totalChunks, seq)
			}

			// The send into the global queue blocks when it is full: that is
			// the backpressure point between ssserver and the tunnel.
			for i := 0; i < totalChunks; i++ {
				start := i * downstreamChunkSize
				end := start + downstreamChunkSize
				if end > totalLen {
					end = totalLen
				}

				p := part{
					ClientID:   s.ClientID,
					RequestID:  s.RequestID,
					Seq:        seq,
					Part:       i + 1,
					TotalParts: totalChunks,
					Data:       encodedStr[start:end],
				}

				select {
				case downstream <- p:
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

// admit buffers one part into the session's reorder window and flushes to
// Shadowsocks whenever the head sequence completes. It returns true if the
// part was accepted (or is a harmless duplicate of already-flushed data)
// and false when it must be NAKed to the client.
func (s *Session) admit(seq, partNum, total int, data string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastActivity = time.Now()

	w := s.win
	if s.closed {
		return false // session gone; NAK so the client can tear down
	}
	if seq < w.head {
		return true // already flushed; idempotent duplicate
	}
	if seq >= w.head+windowSeqs {
		if DebugMode {
			log.Printf("[UPLOAD] Seq %d outside window for %s (head %d); NAKing", seq, s.RequestID, w.head)
		}
		return false // outside the reorder window
	}

	mb := w.entries[seq]
	if mb == nil {
		mb = &messageBuffer{totalParts: total, parts: make(map[int]string), updatedAt: time.Now()}
		w.entries[seq] = mb
	}
	if _, dup := mb.parts[partNum]; !dup {
		mb.parts[partNum] = data
		mb.updatedAt = time.Now()
		w.updatedAt = time.Now()
	}

	if seq == w.head {
		s.flushLocked()
	}
	return true
}

// flushLocked writes every complete sequence at the head of the window,
// advancing the head and cascading into subsequent sequences.
// Caller must hold s.mu.
func (s *Session) flushLocked() {
	w := s.win
	for {
		mb := w.entries[w.head]
		if mb == nil || len(mb.parts) < mb.totalParts {
			break
		}
		flushedSeq := w.head

		var combined strings.Builder
		for i := 1; i <= mb.totalParts; i++ {
			combined.WriteString(mb.parts[i])
		}
		data, err := base64.StdEncoding.DecodeString(combined.String())

		delete(w.entries, w.head)
		w.head++
		w.updatedAt = time.Now()

		if err != nil {
			log.Printf("[UPLOAD] Error decoding base64 for %s seq %d: %v", s.RequestID, flushedSeq, err)
			continue
		}
		if DebugMode {
			log.Printf("[UPLOAD] Reassembled Seq %d for %s, writing %d bytes to Shadowsocks", flushedSeq, s.RequestID, len(data))
		}
		s.writeMutex.Lock()
		writeErr := writeFull(s.Conn, data)
		s.writeMutex.Unlock()
		if writeErr != nil {
			log.Printf("[UPLOAD] Write error for %s seq %d: %v", s.RequestID, flushedSeq, writeErr)
		}
	}
}

// handleUploadPart processes one part of an upload batch and reports whether
// it was accepted.
func handleUploadPart(p part) bool {
	if p.Final {
		stateMu.RLock()
		sess, exists := sessions[p.RequestID]
		stateMu.RUnlock()
		if !exists {
			// Unknown or tombstoned session: NAK so the client stops
			// retrying instead of resurrecting a dead session.
			return false
		}
		log.Printf("[UPLOAD] Received final payload for session %s, draining...", p.RequestID)
		return sess.beginDrain()
	}

	if p.Data == "" || p.TotalParts <= 0 || p.Part < 1 || p.Part > p.TotalParts {
		return false // malformed part
	}

	stateMu.RLock()
	sess, exists := sessions[p.RequestID]
	stateMu.RUnlock()

	if !exists {
		tombstonesMu.Lock()
		_, dead := tombstones[p.RequestID]
		tombstonesMu.Unlock()
		if dead {
			return false
		}

		log.Printf("[SESSION] Dialing Shadowsocks for new session %s...", p.RequestID)

		conn, err := net.DialTimeout("tcp", ShadowSocksAddr, 5*time.Second)
		if err != nil {
			log.Printf("[SESSION] Failed to connect to Shadowsocks for %s: %v", p.RequestID, err)
			return false // NAK: the client will retry this part
		}

		ctx, cancel := context.WithCancel(context.Background())
		newSess := &Session{
			RequestID:    p.RequestID,
			ClientID:     p.ClientID,
			Conn:         conn,
			cancel:       cancel,
			win:          &rxWindow{head: 1, entries: make(map[int]*messageBuffer), updatedAt: time.Now()},
			lastActivity: time.Now(),
		}

		stateMu.Lock()
		if existingSess, stillExists := sessions[p.RequestID]; stillExists {
			sess = existingSess
			conn.Close()
			cancel()
		} else {
			sessions[p.RequestID] = newSess
			sess = newSess
			go sess.startSession(ctx)
			log.Printf("[SESSION] Successfully connected %s to Shadowsocks", p.RequestID)
		}
		stateMu.Unlock()
	}

	return sess.admit(p.Seq, p.Part, p.TotalParts, p.Data)
}
