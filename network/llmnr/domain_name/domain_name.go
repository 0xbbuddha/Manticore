package domain_name

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/TheManticoreProject/Manticore/network/llmnr/constants"
	"github.com/TheManticoreProject/Manticore/network/llmnr/errors"
)

type DomainName string

func (d *DomainName) Validate() error {
	if len(*d) > constants.MaxDomainLength {
		return errors.ErrNameTooLong
	}

	labels := strings.Split(string(*d), ".")
	for _, label := range labels {
		if len(label) > constants.MaxLabelLength {
			return errors.ErrLabelTooLong
		}
	}
	return nil
}

func (d *DomainName) Marshal() ([]byte, error) {
	return EncodeDomainName(string(*d))
}

// Unmarshal decodes a domain name from data starting at offset 0 and sets the receiver.
// It returns the number of bytes consumed from data.
func (d *DomainName) Unmarshal(data []byte) (int, error) {
	name, n, err := DecodeDomainName(data, 0)
	if err != nil {
		return 0, err
	}
	*d = DomainName(name)
	return n, nil
}

// ValidateDomainName validates a domain name according to LLMNR/DNS label rules.
func ValidateDomainName(name string) error {
	d := DomainName(name)
	return d.Validate()
}

// EncodeDomainName serializes a domain name into LLMNR/DNS wire format.
// Labels are length-prefixed and the sequence is terminated by a zero-length label.
func EncodeDomainName(name string) ([]byte, error) {
	// Root or empty name encodes to 0x00
	if name == "" || name == "." {
		return []byte{0}, nil
	}

	trimmed := strings.TrimSuffix(name, ".")
	if len(trimmed) > constants.MaxDomainLength {
		return nil, errors.ErrNameTooLong
	}

	var buf []byte
	for _, label := range strings.Split(trimmed, ".") {
		if len(label) > constants.MaxLabelLength {
			return nil, errors.ErrLabelTooLong
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0) // terminating root label
	return buf, nil
}

// DecodeDomainName parses a domain name from LLMNR/DNS wire format starting at offset.
// It returns the decoded name, the new offset (past the encoded name in the original stream),
// and an error if decoding fails.
func DecodeDomainName(data []byte, offset int) (string, int, error) {
	if offset < 0 || offset >= len(data) {
		return "", offset, fmt.Errorf("offset out of bounds")
	}

	originalOffset := offset
	consumed := 0
	jumped := false
	labels := []string{}

	// To avoid infinite loops on malformed data with pointer cycles
	maxSteps := 256

	for steps := 0; steps < maxSteps; steps++ {
		if offset >= len(data) {
			return "", originalOffset, fmt.Errorf("truncated name")
		}

		length := int(data[offset])

		// End of name
		if length == 0 {
			if !jumped {
				consumed++ // account for the zero byte only when not following a pointer
			}
			break
		}

		// Pointer (11xxxxxx)
		if length&constants.LabelPointer == constants.LabelPointer {
			// Need one more byte for the pointer
			if offset+1 >= len(data) {
				return "", originalOffset, fmt.Errorf("truncated pointer")
			}
			ptr := int(binary.BigEndian.Uint16(data[offset:]) & 0x3FFF)
			if ptr >= len(data) {
				return "", originalOffset, fmt.Errorf("invalid pointer")
			}
			if !jumped {
				// We consume two bytes from the original stream for the pointer
				consumed += 2
			}
			// Follow the pointer
			offset = ptr
			jumped = true
			continue
		}

		// Regular label
		offset++
		if offset+length > len(data) {
			return "", originalOffset, fmt.Errorf("truncated label")
		}
		label := string(data[offset : offset+length])
		labels = append(labels, label)
		offset += length
		if !jumped {
			consumed += 1 + length
		}
	}

	if len(labels) == 0 {
		return ".", originalOffset + consumed, nil
	}
	return strings.Join(labels, "."), originalOffset + consumed, nil
}
