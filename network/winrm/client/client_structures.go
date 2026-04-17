package client

import (
	"net"

	"github.com/TheManticoreProject/Manticore/network/winrm/transport"
)

// Client represents a WinRM client capable of executing commands on a remote Windows host.
type Client struct {
	// Transport is the HTTP transport layer for the client.
	Transport transport.Transport

	// Session holds the authentication state for the current connection.
	Session *Session

	// Connection holds the connection parameters for the client.
	Connection *Connection
}

// Connection represents the connection state between the client and the remote WinRM server.
type Connection struct {
	// Server holds the remote server's address information.
	Server *Server
}

// Server represents the remote WinRM server endpoint.
type Server struct {
	// Host is the IP address of the remote WinRM server.
	Host net.IP

	// Port is the TCP port of the remote WinRM server.
	Port int
}
