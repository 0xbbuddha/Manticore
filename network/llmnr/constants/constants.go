package constants

import "time"

const (
	// LLMNR uses port 5355 as specified in RFC 4795
	ListenPort = 5355

	// Multicast addresses for LLMNR
	IPv4MulticastAddr = "224.0.0.252"
	IPv6MulticastAddr = "FF02::1:3"

	MaxLabelLength  = 63  // Maximum length of a single label
	MaxDomainLength = 255 // Maximum length of entire domain name

	// DNS wire format related constants
	LabelPointer  = 0xC0
	MaxPacketSize = 512

	// 7.  Constants
	// The following timing constants are used in this protocol; they are
	// not intended to be user configurable.

	JitterInterval = 100 * time.Millisecond
	LLMNRTimeout   = 1 * time.Second
)
