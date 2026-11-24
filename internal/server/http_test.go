package server

import (
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestHTTPServer_Timeouts(t *testing.T) {
	t.Run("defaults when unset", func(t *testing.T) {
		s := NewServer(nil, Config{Port: 8080})
		hs := s.httpServer(":8080", http.NotFoundHandler())
		if hs.ReadHeaderTimeout != defaultReadHeaderTimeout ||
			hs.ReadTimeout != defaultReadTimeout ||
			hs.WriteTimeout != defaultWriteTimeout ||
			hs.IdleTimeout != defaultIdleTimeout {
			t.Errorf("Unexpected timeouts: header=%v read=%v write=%v idle=%v",
				hs.ReadHeaderTimeout, hs.ReadTimeout, hs.WriteTimeout, hs.IdleTimeout)
		}
	})

	t.Run("configured values are used", func(t *testing.T) {
		s := NewServer(nil, Config{Port: 8080, ReadTimeout: 5 * time.Second, WriteTimeout: 7 * time.Second})
		hs := s.httpServer(":8080", http.NotFoundHandler())
		if hs.ReadTimeout != 5*time.Second || hs.WriteTimeout != 7*time.Second {
			t.Errorf("Expected read 5s and write 7s, got read=%v write=%v", hs.ReadTimeout, hs.WriteTimeout)
		}
		if hs.ReadHeaderTimeout != 5*time.Second {
			t.Errorf("Header timeout should not exceed the read timeout, got %v", hs.ReadHeaderTimeout)
		}
	})
}

// A client that sends part of a request and then stalls must not hold the
// connection open forever.
func TestHTTPServer_SlowClientIsDisconnected(t *testing.T) {
	s := NewServer(nil, Config{ReadTimeout: 200 * time.Millisecond})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	hs := s.httpServer(ln.Addr().String(), http.NotFoundHandler())
	go hs.Serve(ln)
	t.Cleanup(func() { hs.Close() })

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("GET /metrics HTTP/1.1\r\nHost: localhost\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}

	// The server should close the connection once the header timeout passes
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	_, err = io.ReadAll(conn)
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("Connection was still open after %v", time.Since(start))
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("Server took %v to drop a stalled client", elapsed)
	}
}
