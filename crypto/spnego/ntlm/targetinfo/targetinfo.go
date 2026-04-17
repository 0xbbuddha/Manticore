package targetinfo

import (
	"encoding/binary"
	"errors"

	"github.com/TheManticoreProject/Manticore/crypto/spnego/ntlm/avpair"
)

// ParseTargetInfo parses the target info from a challenge message
func ParseTargetInfo(targetInfo []byte) (map[avpair.AvId][]byte, error) {
	result := make(map[avpair.AvId][]byte)

	offset := 0
	for offset < len(targetInfo) {
		// Need at least 4 bytes for the AV_PAIR header
		if offset+4 > len(targetInfo) {
			return nil, errors.New("target info truncated")
		}

		avId := avpair.AvId(binary.LittleEndian.Uint16(targetInfo[offset : offset+2]))
		offset += 2

		avLen := binary.LittleEndian.Uint16(targetInfo[offset : offset+2])
		offset += 2

		// Check if we have enough bytes for the value
		if offset+int(avLen) > len(targetInfo) {
			return nil, errors.New("target info value truncated")
		}

		// Extract the value
		if avId != avpair.MsvAvEOL {
			result[avId] = targetInfo[offset : offset+int(avLen)]
		}

		offset += int(avLen)

		// If we reached the end of list marker, we're done
		if avId == avpair.MsvAvEOL {
			break
		}
	}

	return result, nil
}

// HasTimestamp reports whether MsvAvTimestamp is present in the TargetInfo.
func HasTimestamp(targetInfo []byte) bool {
	pairs, err := ParseTargetInfo(targetInfo)
	if err != nil {
		return false
	}
	_, ok := pairs[avpair.MsvAvTimestamp]
	return ok
}

// GetTimestamp returns the raw 8-byte Windows FILETIME from TargetInfo, or nil if absent.
func GetTimestamp(targetInfo []byte) []byte {
	pairs, err := ParseTargetInfo(targetInfo)
	if err != nil {
		return nil
	}
	ts, ok := pairs[avpair.MsvAvTimestamp]
	if !ok {
		return nil
	}
	return ts
}

// BuildBlobTargetInfo constructs the modified TargetInfo to embed in the NTLMv2 blob.
//
// It copies all AVPairs from the challenge TargetInfo, inserting or replacing MsvAvFlags
// (AvId=0x0006) before the EOL marker. When needsMIC is true, MsvAvFlags is set to
// 0x00000002 (MIC present bit), as required by MS-NLMP 3.1.5.1.2.
func BuildBlobTargetInfo(targetInfo []byte, needsMIC bool) []byte {
	result := make([]byte, 0, len(targetInfo)+8)

	avFlags := uint32(0)
	if needsMIC {
		avFlags = 0x00000002
	}
	avFlagsBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(avFlagsBytes, avFlags)

	i := 0
	for i+4 <= len(targetInfo) {
		currentID := avpair.AvId(binary.LittleEndian.Uint16(targetInfo[i : i+2]))
		avLen := binary.LittleEndian.Uint16(targetInfo[i+2 : i+4])

		switch currentID {
		case avpair.MsvAvEOL:
			// Insert MsvAvFlags before EOL, then append EOL
			result = append(result, 0x06, 0x00, 0x04, 0x00)
			result = append(result, avFlagsBytes...)
			result = append(result, targetInfo[i:i+4]...)
			return result
		case avpair.MsvAvFlags:
			// Replace existing MsvAvFlags value
			result = append(result, 0x06, 0x00, 0x04, 0x00)
			result = append(result, avFlagsBytes...)
		default:
			result = append(result, targetInfo[i:i+4+int(avLen)]...)
		}

		i += 4 + int(avLen)
	}

	return result
}
