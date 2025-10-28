package tcp_test

import (
	"net"
	"strconv"
	"testing"

	"github.com/TheManticoreProject/Manticore/network/tcp"
)

func TestTCPTransport_Connect(t *testing.T) {
	t.Run("Connect succeeds to running IPv4 server", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to start IPv4 test server: %v", err)
		}
		defer ln.Close()

		// Accept a single connection in background
		go func() {
			c, err := ln.Accept()
			if err == nil {
				c.Close()
			}
		}()

		host, portStr, err := net.SplitHostPort(ln.Addr().String())
		if err != nil {
			t.Fatalf("failed to parse listener address: %v", err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			t.Fatalf("failed to parse port: %v", err)
		}

		tr := tcp.NewTCPTransport()
		if err := tr.Connect(net.ParseIP(host), port); err != nil {
			t.Fatalf("TCPTransport.Connect() error = %v, want no error", err)
		}
		_ = tr.Close()
	})

	t.Run("Connect succeeds to running IPv6 server (if available)", func(t *testing.T) {
		ln, err := net.Listen("tcp", "[::1]:0")
		if err != nil {
			t.Skipf("IPv6 loopback not available: %v", err)
		}
		defer ln.Close()

		go func() {
			c, err := ln.Accept()
			if err == nil {
				c.Close()
			}
		}()

		host, portStr, err := net.SplitHostPort(ln.Addr().String())
		if err != nil {
			t.Fatalf("failed to parse listener address: %v", err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			t.Fatalf("failed to parse port: %v", err)
		}

		tr := tcp.NewTCPTransport()
		if err := tr.Connect(net.ParseIP(host), port); err != nil {
			t.Fatalf("TCPTransport.Connect() error = %v, want no error", err)
		}
		_ = tr.Close()
	})

	t.Run("Invalid IP returns error", func(t *testing.T) {
		tr := tcp.NewTCPTransport()
		if err := tr.Connect(nil, 445); err == nil {
			t.Error("TCPTransport.Connect() should return error when IP is nil")
		}
		_ = tr.Close()
	})
}

func TestTCPTransport_Send(t *testing.T) {
	tr := tcp.NewTCPTransport()

	// Test sending without connection
	_, err := tr.Send([]byte("test"))
	if err == nil {
		t.Error("TCPTransport.Send() should return error when not connected")
	}
}

func TestTCPTransport_Close(t *testing.T) {
	tr := tcp.NewTCPTransport()

	// Test closing without connection
	err := tr.Close()
	if err != nil {
		t.Error("TCPTransport.Close() should not return error when not connected")
	}
}
