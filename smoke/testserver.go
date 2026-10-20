// Command testserver is a deterministic HTTP target for the MirageProxy smoke
// test. It is reached through the full tunnel chain (curl → sslocal → client
// → server → ssserver), so every byte it exchanges has traversed the tunnel.
//
// Endpoints:
//
//	GET  /health                → "ok"
//	GET  /download?size=N       → N bytes of a deterministic pattern
//	GET  /download?size=N&chunked=1 → same stream, chunked (no Content-Length)
//	GET  /hash?size=N           → sha256 hex of exactly what /download returns
//	POST /echo                  → echoes the request body back verbatim
//
// The download pattern is data[i] = byte(i % 251). The /hash endpoint lets the
// smoke script verify tunnel integrity without re-implementing the generator
// in bash.
package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
)

const patternMod = 251

// fill writes the deterministic pattern for global stream offsets
// [off, off+len(dst)).
func fill(dst []byte, off int64) {
	for j := range dst {
		dst[j] = byte((off + int64(j)) % patternMod)
	}
}

// hash returns the sha256 hex of the stream /download?size would produce.
func hash(size int64) string {
	h := sha256.New()
	buf := make([]byte, 32*1024)
	var i int64
	for i < size {
		n := int64(len(buf))
		if size-i < n {
			n = size - i
		}
		fill(buf[:n], i)
		h.Write(buf[:n])
		i += n
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, "ok")
}

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	size, err := strconv.ParseInt(q.Get("size"), 10, 64)
	if err != nil || size < 0 || size > 64<<20 {
		http.Error(w, "bad size", http.StatusBadRequest)
		return
	}
	chunked := q.Get("chunked") == "1"

	log.Printf("[TESTSRV] %s %s (size=%d chunked=%v)", r.Method, r.URL.Path, size, chunked)
	w.Header().Set("Content-Type", "application/octet-stream")

	if chunked {
		// No Content-Length: forces HTTP chunked transfer encoding, which
		// exercises a different read path through ssserver and the tunnel.
		w.WriteHeader(http.StatusOK)
		fl, _ := w.(http.Flusher)
		buf := make([]byte, 32*1024)
		var i int64
		for i < size {
			n := int64(len(buf))
			if size-i < n {
				n = size - i
			}
			fill(buf[:n], i)
			if _, err := w.Write(buf[:n]); err != nil {
				return
			}
			fl.Flush()
			i += n
		}
		return
	}

	data := make([]byte, size)
	fill(data, 0)
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	_, _ = w.Write(data)
}

func hashHandler(w http.ResponseWriter, r *http.Request) {
	size, err := strconv.ParseInt(r.URL.Query().Get("size"), 10, 64)
	if err != nil || size < 0 || size > 64<<20 {
		http.Error(w, "bad size", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintln(w, hash(size))
}

func echoHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<20))
	if err != nil {
		http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
		return
	}
	log.Printf("[TESTSRV] %s %s (echoing %d bytes)", r.Method, r.URL.Path, len(body))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Bytes-Received", strconv.Itoa(len(body)))
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	_, _ = w.Write(body)
}

func main() {
	addr := flag.String("addr", "127.0.0.1:9000", "listen address")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/download", downloadHandler)
	mux.HandleFunc("/hash", hashHandler)
	mux.HandleFunc("/echo", echoHandler)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	log.Printf("[TESTSRV] listening on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}
