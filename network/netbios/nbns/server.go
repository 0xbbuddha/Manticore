package nbns

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

const (
	// Default ports for NetBIOS name service
	DefaultNBNSPort = 137

	// Timeouts and retry counts
	ReadTimeout  = 5 * time.Second
	WriteTimeout = 5 * time.Second
)

// Server represents a NetBIOS Name Server
type Server struct {
	nbns     *NetBIOSNameServer
	listener *net.UDPConn
	addr     *net.UDPAddr
	wg       sync.WaitGroup
	quit     chan struct{}
	handlers *PacketHandler
}

// NewServer creates a new NBNS server instance
func NewServer(addr string, secured bool) (*Server, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve address: %v", err)
	}

	nbns := NewNetBIOSNameServer(secured)
	return &Server{
		nbns:     nbns,
		addr:     udpAddr,
		quit:     make(chan struct{}),
		handlers: NewPacketHandler(nbns),
	}, nil
}

// Start begins listening for NBNS requests
func (s *Server) Start() error {
	var err error
	s.listener, err = net.ListenUDP("udp", s.addr)
	if err != nil {
		return fmt.Errorf("failed to start listener: %v", err)
	}

	s.nbns.StartCleanup()

	s.wg.Add(1)
	go s.serve()

	log.Printf("NBNS server listening on %s", s.addr)
	return nil
}

// Stop gracefully shuts down the server
func (s *Server) Stop() {
	close(s.quit)
	if s.listener != nil {
		s.listener.Close()
	}
	s.wg.Wait()
	s.nbns.StopCleanup()
}

// serve handles incoming NBNS requests
func (s *Server) serve() {
	defer s.wg.Done()

	buf := make([]byte, 1024)
	for {
		select {
		case <-s.quit:
			return
		default:
			if err := s.listener.SetReadDeadline(time.Now().Add(ReadTimeout)); err != nil {
				log.Printf("Failed to set read deadline: %v", err)
				continue
			}

			n, remoteAddr, err := s.listener.ReadFromUDP(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				log.Printf("Failed to read UDP packet: %v", err)
				continue
			}

			// Handle the packet in a separate goroutine
			go s.handlePacket(buf[:n], remoteAddr)
		}
	}
}

// handlePacket processes a single NBNS packet
func (s *Server) handlePacket(data []byte, remoteAddr *net.UDPAddr) {
	var packet NBNSPacket
	bytesRead, err := packet.Unmarshal(data)
	if err != nil {
		log.Printf("Failed to unmarshal packet: %v", err)
		return
	}

	if bytesRead != len(data) {
		log.Printf("Truncated packet: expected %d bytes, got %d", len(data), bytesRead)
		return
	}

	// Create response packet
	response := &NBNSPacket{
		Header: NBNSHeader{
			TransactionID: packet.Header.TransactionID,
			Flags:         FlagResponse | FlagAuthoritative,
			Questions:     0,
		},
	}

	// Process based on operation code
	switch packet.Header.Flags & 0xF000 {
	case OpNameQuery:
		s.handlers.handleNameQuery(&packet, response)
	case OpRegistration:
		s.handlers.handleRegistration(&packet, response)
	case OpRelease:
		s.handlers.handleRelease(&packet, response)
	case OpRefresh:
		s.handlers.handleRefresh(&packet, response)
	default:
		response.Header.Flags |= RcodeNotImpl
	}

	// Send response
	responseData, err := response.Marshal()
	if err != nil {
		log.Printf("Failed to marshal response: %v", err)
		return
	}

	if err := s.listener.SetWriteDeadline(time.Now().Add(WriteTimeout)); err != nil {
		log.Printf("Failed to set write deadline: %v", err)
		return
	}

	if _, err := s.listener.WriteToUDP(responseData, remoteAddr); err != nil {
		log.Printf("Failed to send response: %v", err)
	}
}
