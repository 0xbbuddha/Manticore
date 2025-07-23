package message

// NTLMSSPMessage is the interface that all NTLM messages must implement
type NTLMSSPMessage interface {
	// Marshal serializes the message into a byte slice
	Marshal() ([]byte, error)

	// Unmarshal deserializes a byte slice into the message
	Unmarshal(data []byte) (int, error)

	// GetMessageType returns the message type
	GetMessageType() uint32
}
