package main

import (
	"encoding/base64"
	"log"
	"strings"
	"time"
)

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
