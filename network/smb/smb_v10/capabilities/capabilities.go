package capabilities

import (
	"sort"
	"strings"
)

// Capabilities (4 bytes): A 32-bit field providing a set of server capability indicators.
// This bit field is used to indicate to the client which features are supported by the server.
// Any value not listed in the following table is unused. The server MUST set the unused bits
// to 0 in a response, and the client MUST ignore these bits.
// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/a4229e1a-8a4e-489a-a2eb-11b7f360e60c
type Capabilities uint32

const (
	// CAP_RAW_MODE indicates the server supports SMB_COM_READ_RAW and SMB_COM_WRITE_RAW requests.
	// Raw mode is not supported over connectionless transports.
	CAP_RAW_MODE Capabilities = 1

	// CAP_MPX_MODE indicates the server supports SMB_COM_READ_MPX and SMB_COM_WRITE_MPX requests.
	// MPX mode is supported only over connectionless transports.
	CAP_MPX_MODE Capabilities = 1 << 1

	// CAP_UNICODE indicates the server supports UTF-16LE Unicode strings.
	CAP_UNICODE Capabilities = 1 << 2

	// CAP_LARGE_FILES indicates the server supports 64-bit file offsets.
	CAP_LARGE_FILES Capabilities = 1 << 3

	// CAP_NT_SMBS indicates the server supports SMB commands particular to the NT LAN Manager dialect.
	CAP_NT_SMBS Capabilities = 1 << 4

	// CAP_RPC_REMOTE_APIS indicates the server supports the use of Microsoft remote procedure call (MS-RPC) for remote API calls.
	CAP_RPC_REMOTE_APIS Capabilities = 1 << 5

	// CAP_STATUS32 indicates the server is capable of responding with 32-bit status codes in the Status field of the SMB Header.
	// CAP_STATUS32 is also sometimes referred to as CAP_NT_STATUS.
	CAP_STATUS32  Capabilities = 1 << 6
	CAP_NT_STATUS Capabilities = 1 << 6

	// CAP_LEVEL_II_OPLOCKS indicates the server supports level II opportunistic locks (OpLocks).
	CAP_LEVEL_II_OPLOCKS Capabilities = 1 << 7

	// CAP_LOCK_AND_READ indicates the server supports the SMB_COM_LOCK_AND_READ command request.
	CAP_LOCK_AND_READ Capabilities = 1 << 8

	// CAP_NT_FIND indicates the server supports the TRANS2_FIND_FIRST2, TRANS2_FIND_NEXT2, and FIND_CLOSE2 command requests.
	CAP_NT_FIND Capabilities = 1 << 9

	// CAP_R10
	CAP_R10 Capabilities = 1 << 10

	// CAP_R11
	CAP_R11 Capabilities = 1 << 11

	// CAP_DFS indicates the server is aware of the DFS Referral Protocol and can respond to Microsoft DFS referral requests.
	CAP_DFS Capabilities = 1 << 12

	// CAP_QUADWORD_ALIGNED indicates a reserved capability that was not implemented and MUST be zero.
	CAP_QUADWORD_ALIGNED Capabilities = 1 << 13

	// CAP_INFOLEVEL_PASSTHROUGH indicates the server supports the INFOLEVEL_PASSTHROUGH capability.
	CAP_INFOLEVEL_PASSTHROUGH Capabilities = 1 << 13

	// CAP_LARGE_READX indicates the server supports large read operations.
	// This capability affects the maximum size, in bytes, of the server buffer for sending an SMB_COM_READ_ANDX response to the client.
	CAP_LARGE_READX Capabilities = 1 << 14

	// CAP_LARGE_WRITEX indicates the server supports large write operations.
	// This capability affects the maximum size, in bytes, of the server buffer for sending an SMB_COM_WRITE_ANDX response to the client.
	CAP_LARGE_WRITEX Capabilities = 1 << 15

	// CAP_LWIO indicates the server supports the LWIO capability.
	CAP_LWIO Capabilities = 1 << 16

	// CAP_R17
	CAP_R17 Capabilities = 1 << 17

	// CAP_R18
	CAP_R18 Capabilities = 1 << 18

	// CAP_R19
	CAP_R19 Capabilities = 1 << 19

	// CAP_R20
	CAP_R20 Capabilities = 1 << 20

	// CAP_R21
	CAP_R21 Capabilities = 1 << 21

	// CAP_R22
	CAP_R22 Capabilities = 1 << 22

	// CAP_UNIX indicates the server supports the UNIX capability.
	CAP_UNIX Capabilities = 1 << 23

	// CAP_R24
	CAP_R24 Capabilities = 1 << 24

	// CAP_COMPRESSED_DATA indicates the server supports compressed data.
	CAP_COMPRESSED_DATA Capabilities = 1 << 25

	// CAP_R26
	CAP_R26 Capabilities = 1 << 26

	// CAP_R27
	CAP_R27 Capabilities = 1 << 27

	// CAP_R28
	CAP_R28 Capabilities = 1 << 28

	// CAP_DYNAMIC_REAUTH indicates the server supports dynamic reauthentication.
	CAP_DYNAMIC_REAUTH Capabilities = 1 << 29

	// CAP_R30
	CAP_R30 Capabilities = 1 << 30

	// CAP_EXTENDED_SECURITY indicates the server supports the extended security protocol.
	CAP_EXTENDED_SECURITY Capabilities = 1 << 31
)

// CapabilityMap maps capability values to their string representations
var CapabilityMap = map[Capabilities]string{
	CAP_RAW_MODE:              "CAP_RAW_MODE",
	CAP_MPX_MODE:              "CAP_MPX_MODE",
	CAP_UNICODE:               "CAP_UNICODE",
	CAP_LARGE_FILES:           "CAP_LARGE_FILES",
	CAP_NT_SMBS:               "CAP_NT_SMBS",
	CAP_RPC_REMOTE_APIS:       "CAP_RPC_REMOTE_APIS",
	CAP_NT_STATUS:             "CAP_NT_STATUS",
	CAP_LEVEL_II_OPLOCKS:      "CAP_LEVEL_II_OPLOCKS",
	CAP_LOCK_AND_READ:         "CAP_LOCK_AND_READ",
	CAP_NT_FIND:               "CAP_NT_FIND",
	CAP_R10:                   "CAP_R10",
	CAP_R11:                   "CAP_R11",
	CAP_DFS:                   "CAP_DFS",
	CAP_INFOLEVEL_PASSTHROUGH: "CAP_INFOLEVEL_PASSTHROUGH",
	CAP_LARGE_READX:           "CAP_LARGE_READX",
	CAP_LARGE_WRITEX:          "CAP_LARGE_WRITEX",
	CAP_LWIO:                  "CAP_LWIO",
	CAP_R17:                   "CAP_R17",
	CAP_R18:                   "CAP_R18",
	CAP_R19:                   "CAP_R19",
	CAP_R20:                   "CAP_R20",
	CAP_R21:                   "CAP_R21",
	CAP_R22:                   "CAP_R22",
	CAP_UNIX:                  "CAP_UNIX",
	CAP_R24:                   "CAP_R24",
	CAP_COMPRESSED_DATA:       "CAP_COMPRESSED_DATA",
	CAP_R26:                   "CAP_R26",
	CAP_R27:                   "CAP_R27",
	CAP_R28:                   "CAP_R28",
	CAP_DYNAMIC_REAUTH:        "CAP_DYNAMIC_REAUTH",
	CAP_R30:                   "CAP_R30",
	CAP_EXTENDED_SECURITY:     "CAP_EXTENDED_SECURITY",
}

// String returns a string representation of the capabilities.
// The string is a bitmask of the capabilities that are set.
// The capabilities are listed in alphabetical order.
func (c Capabilities) String() string {
	var flagList []string

	// Get all keys from the map and sort them
	var keys []Capabilities
	for k := range CapabilityMap {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	// Check each capability flag in sorted order
	for _, capability := range keys {
		if c.HasCapability(capability) {
			flagList = append(flagList, CapabilityMap[capability])
		}
	}

	if len(flagList) == 0 {
		return "NONE"
	}

	return strings.Join(flagList, "|")
}

// HasCapability checks if the Capabilities has a specific capability flag set
//
// Parameters:
// - capability: The capability flag to check for
//
// Returns:
// - bool: True if the capability is set, false otherwise
func (c Capabilities) HasCapability(capability Capabilities) bool {
	return c&capability == capability
}
