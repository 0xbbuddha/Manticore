package client_test

import (
	"net"
	"testing"

	"github.com/TheManticoreProject/Manticore/network/winrm/client"
)

func TestNewClient(t *testing.T) {
	host := net.ParseIP("127.0.0.1")
	c := client.NewClient(host, 5985)

	if c == nil {
		t.Fatal("NewClient() returned nil")
	}

	if !c.GetHost().Equal(host) {
		t.Errorf("GetHost() = %v, want %v", c.GetHost(), host)
	}

	if c.GetPort() != 5985 {
		t.Errorf("GetPort() = %d, want 5985", c.GetPort())
	}
}

func TestNewClientDefaultPort(t *testing.T) {
	host := net.ParseIP("192.168.1.1")
	c := client.NewClient(host, 0)

	if c == nil {
		t.Fatal("NewClient() returned nil")
	}

	if c.GetPort() != 5985 {
		t.Errorf("GetPort() = %d, want 5985 (default)", c.GetPort())
	}
}

func TestClientGetSetHost(t *testing.T) {
	host1 := net.ParseIP("10.0.0.1")
	host2 := net.ParseIP("10.0.0.2")
	c := client.NewClient(host1, 5985)

	c.SetHost(host2)
	if !c.GetHost().Equal(host2) {
		t.Errorf("GetHost() after SetHost() = %v, want %v", c.GetHost(), host2)
	}
}

func TestClientGetSetPort(t *testing.T) {
	host := net.ParseIP("10.0.0.1")
	c := client.NewClient(host, 5985)

	c.SetPort(5986)
	if c.GetPort() != 5986 {
		t.Errorf("GetPort() after SetPort() = %d, want 5986", c.GetPort())
	}
}
