// Package kerberos provides a native Kerberos client implementation for
// Active Directory authentication, without external dependencies.
// It supports RC4-HMAC and AES-CTS-HMAC-SHA1-96 encryption types.
package kerberos

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// defaultKDCPort is the standard Kerberos port.
const defaultKDCPort = 88

// defaultTimeout is the TCP dial and I/O timeout for KDC connections.
const defaultTimeout = 10 * time.Second

// kdcSend sends a Kerberos message to the KDC over TCP and returns the response.
// Kerberos over TCP uses a 4-byte big-endian length prefix followed by the message body.
// Per RFC 4120 Section 7.2.2.
func kdcSend(kdc_host string, kdc_port int, msg []byte) ([]byte, error) {
	addr := net.JoinHostPort(kdc_host, fmt.Sprintf("%d", kdc_port))
	conn, err := net.DialTimeout("tcp", addr, defaultTimeout)
	if err != nil {
		return nil, fmt.Errorf("kerberos: connect to KDC %s: %w", addr, err)
	}
	defer conn.Close()

	// Set I/O deadline for the entire exchange
	conn.SetDeadline(time.Now().Add(defaultTimeout))

	// Write: 4-byte big-endian length prefix || message body
	len_buf := make([]byte, 4)
	binary.BigEndian.PutUint32(len_buf, uint32(len(msg)))

	packet := make([]byte, 4+len(msg))
	copy(packet[:4], len_buf)
	copy(packet[4:], msg)

	if _, err := conn.Write(packet); err != nil {
		return nil, fmt.Errorf("kerberos: send to KDC: %w", err)
	}

	// Read the 4-byte response length
	resp_len_buf := make([]byte, 4)
	if err := readFull(conn, resp_len_buf); err != nil {
		return nil, fmt.Errorf("kerberos: read response length: %w", err)
	}
	resp_len := binary.BigEndian.Uint32(resp_len_buf)

	// Sanity-check the response size (16 MB max)
	if resp_len > 16*1024*1024 {
		return nil, fmt.Errorf("kerberos: KDC response too large: %d bytes", resp_len)
	}

	// Read the response body
	resp_buf := make([]byte, resp_len)
	if err := readFull(conn, resp_buf); err != nil {
		return nil, fmt.Errorf("kerberos: read response body: %w", err)
	}

	return resp_buf, nil
}

// readFull reads exactly len(buf) bytes from conn, retrying on partial reads.
func readFull(conn net.Conn, buf []byte) error {
	_, err := io.ReadFull(conn, buf)
	return err
}
