package tcp_test

import (
	"net"
	"testing"

	"github.com/TheManticoreProject/Manticore/network/tcp"
)

func TestTCPTransport_Connect(t *testing.T) {
	tests := []struct {
		name    string
		ip      net.IP
		port    int
		wantErr bool
	}{
		{
			name:    "Valid IPv4 connection with default port",
			ip:      net.ParseIP("127.0.0.1"),
			port:    0,
			wantErr: true, // Will fail since no server is running
		},
		{
			name:    "Valid IPv4 connection with custom port",
			ip:      net.ParseIP("127.0.0.1"),
			port:    8445,
			wantErr: true,
		},
		{
			name:    "Valid IPv6 connection",
			ip:      net.ParseIP("::1"),
			port:    445,
			wantErr: true,
		},
		{
			name:    "Invalid IP",
			ip:      nil,
			port:    445,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := tcp.NewTCPTransport()
			err := tr.Connect(tt.ip, tt.port)
			if (err != nil) != tt.wantErr {
				t.Errorf("TCPTransport.Connect() error = %v, wantErr %v", err, tt.wantErr)
			}
			tr.Close()
		})
	}
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
