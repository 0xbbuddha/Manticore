package transport

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"

	"github.com/TheManticoreProject/Manticore/network/winrm/types"
)

// Transport defines the interface for sending WS-Management HTTP requests.
//
// WinRM uses an atomic HTTP request-response model, so the transport exposes a
// single Post method rather than separate Send/Receive calls. Because NTLM
// authentication in HTTP/1.1 is connection-bound, implementations must keep the
// underlying TCP connection alive across multiple Post calls.
type Transport interface {
	// Connect establishes the underlying TCP connection to the WinRM endpoint.
	Connect(ipaddr net.IP, port int) error

	// Close terminates the underlying TCP connection.
	Close() error

	// IsConnected reports whether the transport currently has an active connection.
	IsConnected() bool

	// Post sends an HTTP POST request with the given additional headers and body,
	// and returns the HTTP status code, response headers, and response body.
	//
	// Parameters:
	//   - headers (map[string]string): Additional HTTP headers to include in the request.
	//   - body ([]byte): The SOAP XML request body.
	//
	// Returns:
	//   - int: The HTTP response status code.
	//   - map[string][]string: The HTTP response headers.
	//   - []byte: The HTTP response body.
	//   - error: An error if the request could not be sent or the response could not be read.
	Post(headers map[string]string, body []byte) (int, map[string][]string, []byte, error)
}

// HTTPTransport implements the Transport interface using a persistent raw TCP connection.
//
// Keeping the same net.Conn alive is required so that NTLM authentication tokens,
// which are scoped to the underlying HTTP/1.1 connection, remain valid across the
// two-step negotiate/authenticate handshake and subsequent WS-Management calls.
type HTTPTransport struct {
	conn   net.Conn
	reader *bufio.Reader
	host   string
	path   string
}

// NewHTTPTransport creates a new HTTPTransport targeting the default WS-Management path.
//
// Returns:
//   - *HTTPTransport: A pointer to the initialised HTTPTransport.
func NewHTTPTransport() *HTTPTransport {
	return &HTTPTransport{
		path: types.WSManPath,
	}
}

// Connect establishes a TCP connection to the WinRM HTTP endpoint.
//
// Parameters:
//   - ipaddr (net.IP): The IP address of the remote WinRM server.
//   - port (int): The TCP port to connect to (use 0 for the default HTTP port 5985).
//
// Returns:
//   - error: An error if the connection cannot be established.
func (t *HTTPTransport) Connect(ipaddr net.IP, port int) error {
	if port == 0 {
		port = types.DefaultHTTPPort
	}

	var address string
	if ipaddr.To4() != nil {
		address = fmt.Sprintf("%s:%d", ipaddr.String(), port)
	} else {
		address = fmt.Sprintf("[%s]:%d", ipaddr.String(), port)
	}

	conn, err := net.Dial("tcp", address)
	if err != nil {
		return fmt.Errorf("failed to connect to WinRM endpoint: %v", err)
	}

	t.conn = conn
	t.reader = bufio.NewReader(conn)
	t.host = address

	return nil
}

// Close terminates the underlying TCP connection.
//
// Returns:
//   - error: An error if the connection cannot be closed.
func (t *HTTPTransport) Close() error {
	if t.conn != nil {
		err := t.conn.Close()
		t.conn = nil
		t.reader = nil
		return err
	}
	return nil
}

// IsConnected reports whether the transport currently has an active connection.
//
// Returns:
//   - bool: True if connected, false otherwise.
func (t *HTTPTransport) IsConnected() bool {
	return t.conn != nil
}

// Post sends an HTTP POST request over the persistent connection and returns the response.
//
// The Content-Type is always set to the WS-Management SOAP type. The Connection header
// is set to keep-alive to ensure NTLM connection-binding is preserved.
//
// Parameters:
//   - headers (map[string]string): Additional HTTP headers to include (e.g. Authorization).
//   - body ([]byte): The SOAP XML request body bytes.
//
// Returns:
//   - int: The HTTP response status code.
//   - map[string][]string: The HTTP response headers.
//   - []byte: The HTTP response body bytes.
//   - error: An error if the transport is not connected, or if sending or reading fails.
func (t *HTTPTransport) Post(headers map[string]string, body []byte) (int, map[string][]string, []byte, error) {
	if !t.IsConnected() {
		return 0, nil, nil, fmt.Errorf("transport is not connected")
	}

	req, err := http.NewRequest(http.MethodPost, "http://"+t.host+t.path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, fmt.Errorf("failed to build HTTP request: %v", err)
	}

	req.Header.Set("Content-Type", types.ContentType)
	req.Header.Set("Connection", "keep-alive")
	req.ContentLength = int64(len(body))

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	if err := req.Write(t.conn); err != nil {
		return 0, nil, nil, fmt.Errorf("failed to send HTTP request: %v", err)
	}

	resp, err := http.ReadResponse(t.reader, req)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("failed to read HTTP response: %v", err)
	}
	defer resp.Body.Close()

	var response_body bytes.Buffer
	if _, err := response_body.ReadFrom(resp.Body); err != nil {
		return 0, nil, nil, fmt.Errorf("failed to read HTTP response body: %v", err)
	}

	return resp.StatusCode, map[string][]string(resp.Header), response_body.Bytes(), nil
}
