package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"mirageproxy/internal/shared"
)

const (
	uploadQueueCap       = 8192                 // global upload queue capacity (parts); producers block when full
	dispatcherWorkers    = 4                    // workers draining the global upload queue
	dispatchPollInterval = 7 * time.Millisecond // queue recheck cadence when the queue is empty
	maxSendAttempts      = 5                    // per-part retries before the connection is killed
	postAttemptTimeout   = 60 * time.Second     // per-POST attempt deadline
)

func mustMarshal(v any) []byte {
	// Part contains only strings and ints; marshalling cannot fail.
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
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
func fireBatch(client *http.Client, batch []uploadItem) ([]bool, []shared.Part, error) {
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

	shared.SignRequest(req, ProxySecret, shared.UploadID(myClientID))
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

	var ack shared.AckPayload
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
