package main

import (
	"flag"
	"log"
	"net"
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
