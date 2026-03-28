package transport_test

import (
	"net"
	"testing"

	"github.com/TheManticoreProject/Manticore/network/winrm/transport"
)

// MockTransport implements the Transport interface for testing.
type MockTransport struct {
	connected      bool
	lastHeaders    map[string]string
	lastBody       []byte
	responseCode   int
	responseHeader map[string][]string
	responseBody   []byte
	postErr        error
}

func (m *MockTransport) Connect(ipaddr net.IP, port int) error {
	m.connected = true
	return nil
}

func (m *MockTransport) Close() error {
	m.connected = false
	return nil
}

func (m *MockTransport) IsConnected() bool {
	return m.connected
}

func (m *MockTransport) Post(headers map[string]string, body []byte) (int, map[string][]string, []byte, error) {
	if m.postErr != nil {
		return 0, nil, nil, m.postErr
	}
	m.lastHeaders = headers
	m.lastBody = body
	return m.responseCode, m.responseHeader, m.responseBody, nil
}

func TestNewHTTPTransport(t *testing.T) {
	tr := transport.NewHTTPTransport()
	if tr == nil {
		t.Fatal("NewHTTPTransport() returned nil")
	}
	if tr.IsConnected() {
		t.Errorf("IsConnected() = true, want false before Connect()")
	}
}

func TestTransportInterface(t *testing.T) {
	mock := &MockTransport{
		responseCode: 200,
		responseHeader: map[string][]string{
			"Content-Type": {"application/soap+xml;charset=UTF-8"},
		},
		responseBody: []byte("<Envelope/>"),
	}

	// Test Connect
	err := mock.Connect(net.ParseIP("127.0.0.1"), 5985)
	if err != nil {
		t.Errorf("Connect() error = %v", err)
	}
	if !mock.IsConnected() {
		t.Errorf("IsConnected() = false, want true after Connect()")
	}

	// Test Post
	test_headers := map[string]string{
		"Authorization": "Negotiate dGVzdA==",
	}
	test_body := []byte("<Envelope/>")

	status, resp_headers, resp_body, err := mock.Post(test_headers, test_body)
	if err != nil {
		t.Errorf("Post() error = %v", err)
	}
	if status != 200 {
		t.Errorf("Post() status = %d, want 200", status)
	}
	if resp_headers == nil {
		t.Errorf("Post() resp_headers = nil")
	}
	if string(resp_body) != "<Envelope/>" {
		t.Errorf("Post() resp_body = %q, want %q", resp_body, "<Envelope/>")
	}

	// Test Close
	err = mock.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}
	if mock.IsConnected() {
		t.Errorf("IsConnected() = true, want false after Close()")
	}
}
