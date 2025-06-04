package negotiate_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/TheManticoreProject/Manticore/network/smb/smb_v10/spnego/ntlm/message/negotiate"
	"github.com/TheManticoreProject/Manticore/network/smb/smb_v10/spnego/ntlm/message/negotiate/flags"
)

func TestMarshalUnmarshal(t *testing.T) {

	tests := []struct {
		name        string
		domain      string
		workstation string
		useUnicode  bool
		flags       flags.NegotiateFlags
	}{
		{
			name:        "Basic Unicode Message",
			domain:      "MANTICORE",
			workstation: "DC01",
			useUnicode:  true,
			flags:       flags.NTLMSSP_NEGOTIATE_UNICODE | flags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY,
		},
		{
			name:        "Basic OEM Message",
			domain:      "MANTICORE",
			workstation: "DC01",
			useUnicode:  false,
			flags:       flags.NTLMSSP_NEGOTIATE_OEM | flags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY,
		},
		{
			name:        "Empty Domain",
			domain:      "",
			workstation: "DC01",
			useUnicode:  true,
			flags:       flags.NTLMSSP_NEGOTIATE_UNICODE | flags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY,
		},
		{
			name:        "Empty Workstation",
			domain:      "MANTICORE",
			workstation: "",
			useUnicode:  true,
			flags:       flags.NTLMSSP_NEGOTIATE_UNICODE | flags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create message
			msg, err := negotiate.CreateNegotiateMessage(tt.domain, tt.workstation, tt.useUnicode)
			if err != nil {
				t.Fatalf("Failed to create negotiate message: %v", err)
			}

			msg.NegotiateFlags = tt.flags

			// Marshal
			data, err := msg.Marshal()
			if err != nil {
				t.Fatalf("Failed to marshal: %v", err)
			}

			fmt.Printf("Marshaled NegotiateMessage: %s\n", hex.EncodeToString(data))

			// Unmarshal
			unmarshaledMsg := &negotiate.NegotiateMessage{}
			_, err = unmarshaledMsg.Unmarshal(data)
			if err != nil {
				t.Fatalf("Failed to unmarshal: %v", err)
			}

			// Compare fields
			if !bytes.Equal(msg.DomainName, unmarshaledMsg.DomainName) {
				t.Error("DomainName mismatch")
				t.Errorf("msg.DomainName: %s", string(msg.DomainName))
				t.Errorf("unmarshaledMsg.DomainName: %s", string(unmarshaledMsg.DomainName))
			}
			if !bytes.Equal(msg.Workstation, unmarshaledMsg.Workstation) {
				t.Error("Workstation mismatch")
				t.Errorf("msg.Workstation: %s", string(msg.Workstation))
				t.Errorf("unmarshaledMsg.Workstation: %s", string(unmarshaledMsg.Workstation))
			}
			if msg.NegotiateFlags != unmarshaledMsg.NegotiateFlags {
				t.Error("NegotiateFlags mismatch")
			}

			// Compare DataFields
			if !msg.DomainNameFields.Equal(&unmarshaledMsg.DomainNameFields) {
				t.Error("DomainNameFields mismatch")
			}
			if !msg.WorkstationFields.Equal(&unmarshaledMsg.WorkstationFields) {
				t.Error("WorkstationFields mismatch")
			}
		})
	}
}
