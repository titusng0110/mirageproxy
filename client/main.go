package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"mirageproxy/internal/shared"
)

func main() {
	// ADDED: Testing flag
	testMode := flag.Bool("insecure", false, "Skip TLS verification (Use ONLY for local testing)")
	flag.Parse()

	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	log.Printf("[MAIN] Starting client proxy (ClientID: %s)", myClientID)

	if *testMode {
		log.Println("[MAIN] WARNING: Running in INSECURE mode. TLS certificates will not be verified.")
	}

	go backgroundCleanup()

	// Pass the flag into the HTTP client setup
	httpClient := getUTLSClient(*testMode)
	go runPoller(httpClient)

	for i := 0; i < dispatcherWorkers; i++ {
		go dispatcherWorker(httpClient)
	}

	ln, err := net.Listen("tcp", LocalListenAddr)
	if err != nil {
		log.Fatalf("[MAIN] Failed to listen: %v", err)
	}
	defer ln.Close()

	log.Printf("[MAIN] Client listening on %s", LocalListenAddr)
	log.Printf("[MAIN] Proxying traffic to: %s", RemoteServerURL)

	for {
		conn, err := ln.Accept()
		if err == nil {
			go handleConnection(conn)
		} else {
			log.Printf("[MAIN] Accept error: %v", err)
		}
	}
}

// ============================================================================
// Configuration, types and global state
// ============================================================================

const DebugMode = false

var (
	ProxySecret     = "default"
	RemoteServerURL = "https://127.0.0.1:30001"
)

const (
	LocalListenAddr = ":30000"
	chunkSize       = 16 * 1024 // max base64 payload per part, and the per-POST batch budget
)

var myClientID = fmt.Sprintf("client-%d", time.Now().UnixNano())

type session struct {
	conn         net.Conn
	writeMutex   sync.Mutex
	lastActivity time.Time
	mu           sync.Mutex
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

type uploadItem struct {
	p        shared.Part
	reqID    string
	encoded  []byte // pre-marshalled JSON for this part
	attempts int
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
