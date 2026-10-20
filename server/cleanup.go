package main

import (
	"log"
	"time"
)

func backgroundCleanup() {
	for {
		time.Sleep(1 * time.Minute)
		now := time.Now()
		var expiredSessions []string

		stateMu.RLock()
		for reqID, sess := range sessions {
			sess.mu.Lock()
			inactive := now.Sub(sess.lastActivity) > idleTimeout

			w := sess.win
			if w != nil && len(w.entries) > 0 && now.Sub(w.updatedAt) > 2*time.Minute {
				// The head sequence never completed; slide past the gap so
				// buffered future sequences can flow again.
				minSeq := -1
				for s := range w.entries {
					if minSeq == -1 || s < minSeq {
						minSeq = s
					}
				}
				if minSeq > w.head {
					if DebugMode {
						log.Printf("[CLEANUP] Sliding upload window for %s from seq %d to %d", reqID, w.head, minSeq)
					}
					w.head = minSeq
					sess.flushLocked()
				}
				w.updatedAt = now
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

		tombstonesMu.Lock()
		for id, t := range tombstones {
			if now.Sub(t) > tombstoneTTL {
				delete(tombstones, id)
			}
		}
		tombstonesMu.Unlock()
	}
}
