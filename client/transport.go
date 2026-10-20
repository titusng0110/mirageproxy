package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

var ErrALPNFallback = errors.New("server negotiated http/1.1")

type SmartTransport struct {
	H2 *http2.Transport
	H1 *http.Transport

	mu           sync.RWMutex
	fallbackMode bool
	h1Until      time.Time
}

func (t *SmartTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.RLock()
	useH1 := t.fallbackMode && time.Now().Before(t.h1Until)
	t.mu.RUnlock()

	if useH1 {
		return t.H1.RoundTrip(req)
	}

	resp, err := t.H2.RoundTrip(req)

	if err != nil {
		if errors.Is(err, ErrALPNFallback) {
			if DebugMode {
				log.Println("[TLS] ALPN negotiated HTTP/1.1. Instant fallback.")
			}
			return t.H1.RoundTrip(req)
		}

		// RACE CONDITION FIX: Don't penalize H2 if the server just isn't booted yet.
		// If the error is a local dial failure, the GFW didn't block us.
		var opErr *net.OpError
		if errors.As(err, &opErr) && opErr.Op == "dial" {
			return resp, err
		}
		if strings.Contains(err.Error(), "connection refused") {
			return resp, err
		}

		t.mu.Lock()
		t.fallbackMode = true
		t.h1Until = time.Now().Add(5 * time.Minute)
		t.mu.Unlock()

		if DebugMode {
			log.Printf("[TLS] HTTP/2 flow interrupted: %v. Falling back to HTTP/1.1 for 5 mins.", err)
		}
		return resp, err
	}

	return resp, nil
}

func getUTLSClient(skipTLSVerify bool) *http.Client {
	// H2 Dialer: Requires the server to negotiate HTTP/2
	dialH2 := func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		tcpConn, err := net.DialTimeout(network, addr, 10*time.Second)
		if err != nil {
			return nil, err
		}

		config := &utls.Config{
			ServerName:         host,
			InsecureSkipVerify: skipTLSVerify,
		}
		uConn := utls.UClient(tcpConn, config, utls.HelloChrome_Auto)
		if err := uConn.HandshakeContext(ctx); err != nil {
			return nil, err
		}

		if uConn.ConnectionState().NegotiatedProtocol != "h2" {
			uConn.Close()
			return nil, ErrALPNFallback
		}
		return uConn, nil
	}

	// H1 Dialer: Forces the server into HTTP/1.1 mode
	dialH1 := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		tcpConn, err := net.DialTimeout(network, addr, 10*time.Second)
		if err != nil {
			return nil, err
		}

		config := &utls.Config{
			ServerName:         host,
			InsecureSkipVerify: skipTLSVerify,
		}
		uConn := utls.UClient(tcpConn, config, utls.HelloChrome_Auto)

		// ALPN MISMATCH FIX: Build the Chrome ClientHello, then manually overwrite
		// the ALPN extension to ONLY offer http/1.1. This keeps the Chrome fingerprint
		// perfectly intact but forces the server to speak HTTP/1.1.
		if err := uConn.BuildHandshakeState(); err != nil {
			return nil, err
		}
		for _, ext := range uConn.Extensions {
			if alpn, ok := ext.(*utls.ALPNExtension); ok {
				alpn.AlpnProtocols = []string{"http/1.1"}
			}
		}

		if err := uConn.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		return uConn, nil
	}

	tH2 := &http2.Transport{
		DialTLSContext:             dialH2,
		StrictMaxConcurrentStreams: true,
	}

	tH1 := &http.Transport{
		DialTLSContext:      dialH1,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	}

	return &http.Client{
		Transport: &SmartTransport{
			H2: tH2,
			H1: tH1,
		},
	}
}
