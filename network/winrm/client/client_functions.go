package client

import (
	"fmt"
	"net"

	"github.com/TheManticoreProject/Manticore/network/winrm/transport"
	"github.com/TheManticoreProject/Manticore/network/winrm/types"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
)

// NewClient creates a new WinRM client targeting the given host and port.
//
// Parameters:
//   - host (net.IP): The IP address of the remote WinRM server.
//   - port (int): The TCP port of the remote WinRM server (use 0 for default 5985).
//
// Returns:
//   - *Client: A pointer to the initialised Client.
func NewClient(host net.IP, port int) *Client {
	if port == 0 {
		port = types.DefaultHTTPPort
	}
	return &Client{
		Transport: transport.NewHTTPTransport(),
		Connection: &Connection{
			Server: &Server{
				Host: host,
				Port: port,
			},
		},
		Session: nil,
	}
}

// Connect establishes the TCP connection to the remote WinRM server.
//
// Returns:
//   - error: An error if the connection cannot be established.
func (c *Client) Connect() error {
	err := c.Transport.Connect(c.Connection.Server.Host, c.Connection.Server.Port)
	if err != nil {
		return fmt.Errorf("failed to connect to WinRM server: %v", err)
	}
	return nil
}

// SessionSetup authenticates the client against the WinRM server using the supplied credentials.
//
// It performs the full NTLM negotiate-challenge-authenticate handshake. A nil return value
// confirms the credentials are valid and the session is ready.
//
// Parameters:
//   - creds (*credentials.Credentials): The Windows credentials to authenticate with.
//
// Returns:
//   - error: An error if the session cannot be set up or if authentication fails.
func (c *Client) SessionSetup(creds *credentials.Credentials) error {
	if c.Session == nil {
		c.Session = &Session{
			Client:      c,
			Credentials: creds,
		}
	}
	c.Session.Client = c

	return c.Session.SessionSetup()
}

// SetHost sets the remote server IP address.
//
// Parameters:
//   - host (net.IP): The new IP address.
func (c *Client) SetHost(host net.IP) {
	c.Connection.Server.Host = host
}

// GetHost returns the remote server IP address.
//
// Returns:
//   - net.IP: The current IP address.
func (c *Client) GetHost() net.IP {
	return c.Connection.Server.Host
}

// SetPort sets the remote server TCP port.
//
// Parameters:
//   - port (int): The new port number.
func (c *Client) SetPort(port int) {
	c.Connection.Server.Port = port
}

// GetPort returns the remote server TCP port.
//
// Returns:
//   - int: The current port number.
func (c *Client) GetPort() int {
	return c.Connection.Server.Port
}
