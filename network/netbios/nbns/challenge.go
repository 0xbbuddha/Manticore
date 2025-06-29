package nbns

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

const (
	// Challenge timeouts and retries
	ChallengeTimeout = 2 * time.Second
	ChallengeRetries = 3
)

// NameChallenger handles name conflict detection and resolution
type NameChallenger struct {
	nbns     *NetBIOSNameServer
	handlers *PacketHandler
}

// NewNameChallenger creates a new name challenger instance
func NewNameChallenger(nbns *NetBIOSNameServer, handlers *PacketHandler) *NameChallenger {
	return &NameChallenger{
		nbns:     nbns,
		handlers: handlers,
	}
}

// ChallengeOwnership verifies if a node still owns a name
func (c *NameChallenger) ChallengeOwnership(name string, owner net.IP) (bool, error) {
	// Create challenge packet
	request := &NBNSPacket{
		Header: NBNSHeader{
			TransactionID: generateTransactionID(),
			Flags:         OpNameQuery,
			Questions:     1,
		},
		Questions: []NBNSQuestion{
			{
				Name: &NetBIOSName{Name: name},
				Type: 0x20, // NB record
			},
		},
	}

	// Create UDP connection for challenge
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: owner, Port: DefaultNBNSUDPPort})
	if err != nil {
		return false, fmt.Errorf("failed to create UDP connection: %v", err)
	}
	defer conn.Close()

	// Send challenge and wait for response
	for i := 0; i < ChallengeRetries; i++ {
		if err := conn.SetDeadline(time.Now().Add(ChallengeTimeout)); err != nil {
			return false, fmt.Errorf("failed to set deadline: %v", err)
		}

		// Send challenge
		data, err := request.Marshal()
		if err != nil {
			return false, fmt.Errorf("failed to marshal challenge: %v", err)
		}

		if _, err := conn.Write(data); err != nil {
			return false, fmt.Errorf("failed to send challenge: %v", err)
		}

		// Wait for response
		buf := make([]byte, MaxUDPSize)
		n, err := conn.Read(buf)
		if err != nil {
			continue // Try again on timeout
		}

		// Parse response
		var response NBNSPacket
		bytesRead, err := response.Unmarshal(buf[:n])
		if err != nil {
			continue
		}

		if bytesRead != n {
			continue
		}

		// Verify response
		if response.Header.TransactionID != request.Header.TransactionID {
			continue
		}

		// Check if name is still owned
		if response.Header.Flags&RcodeNameError != 0 {
			return false, nil
		}

		// Verify owner IP in response
		for _, rr := range response.Answers {
			if net.IP(rr.RData).Equal(owner) {
				return true, nil
			}
		}
	}

	return false, nil // Consider name released after all retries fail
}

// DefendName actively defends a name against challenges
func (c *NameChallenger) DefendName(packet *NBNSPacket, response *NBNSPacket) {
	// Only defend against queries
	if packet.Header.Flags&0xF000 != OpNameQuery {
		return
	}

	for _, q := range packet.Questions {
		// Check if we own this name
		owners, nameType, err := c.nbns.QueryName(q.Name.Name)
		if err != nil {
			continue
		}

		// Create defense response
		response.Header.Flags = FlagResponse | FlagAuthoritative
		if nameType == Group {
			response.Header.Flags |= 0x0080 // Group name bit
		}

		// Add resource records for all owners
		for _, ip := range owners {
			owner := ADDR_ENTRY{
				Address: binary.BigEndian.Uint32(ip.To4()),
				Flags:   0x0000,
			}
			rr := NBNSResourceRecord{
				Name:     q.Name,
				Type:     q.Type,
				Class:    q.Class,
				TTL:      uint32(24 * time.Hour.Seconds()),
				RDLength: uint16(owner.Length()),
				RData:    owner.Marshal(),
			}
			response.Answers = append(response.Answers, rr)
		}

		response.Header.Answers = uint16(len(response.Answers))
	}
}

// generateTransactionID creates a random transaction ID
func generateTransactionID() uint16 {
	// Simple implementation - could be made more random
	return uint16(time.Now().UnixNano() & 0xFFFF)
}
