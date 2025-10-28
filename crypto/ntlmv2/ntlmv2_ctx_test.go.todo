package ntlmv2_test

import (
	"encoding/hex"
	"testing"

	"github.com/TheManticoreProject/Manticore/crypto/ntlmv2"
)

func TestNTLMv2HashToHashcatString(t *testing.T) {
	testCases := []struct {
		testName string
		domain   string
		username string
		password string

		serverChallenge [8]byte
		clientChallenge [8]byte

		expectedUsername           string
		expectedHostname           string
		expexpectedServerChallenge string
		expexpectedClientChallenge string
		expexpectedNTLMv2Hash      string
	}{
		{
			testName:                   "Domain username and password to NTLMv2 hashcat string",
			domain:                     "LAB",
			username:                   "Podalirius",
			password:                   "Admin123!",
			serverChallenge:            [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
			clientChallenge:            [8]byte{0x14, 0x78, 0x18, 0x65, 0x59, 0x40, 0x07, 0x4B},
			expectedUsername:           "Podalirius",
			expectedHostname:           "LAB",
			expexpectedServerChallenge: "1122334455667788",
			expexpectedClientChallenge: "147818655940074BBB99DA222104F182",
			expexpectedNTLMv2Hash:      "0101000000000000EDC8BDBFD3AADB014B40D4784E921B03000000000200080034004B003200490001001E00570049004E002D00360050004C0059004E003500350045004400420032000400140034004B00320049002E004C004F00430041004C0003003400570049004E002D00360050004C0059004E003500350045004400420032002E0034004B00320049002E004C004F00430041004C000500140034004B00320049002E004C004F00430041004C000800300030000000000000000100000000200000512F465482D41399998EA0D3D7E64F2D0C26B6CF64F7E9CDDA71B01B0574A47F0A001000000000000000000000000000000000000900280048005400540050002F00770069006E002D00360070006C0079006E003500350065006400620032000000000000000000",
		},
	}

	for _, tc := range testCases {
		tc := tc // capture range variable
		t.Run(tc.testName, func(t *testing.T) {
			t.Parallel()
			ntlmv2Ctx, err := ntlmv2.NewNTLMv2CtxWithPassword(tc.domain, tc.username, tc.password, tc.serverChallenge, tc.clientChallenge)
			if err != nil {
				t.Fatalf("Expected no error, got %v", err)
			}

			ntlmv2Response, err := ntlmv2Ctx.NTResponse()
			if err != nil {
				t.Fatalf("Expected no error, got %v", err)
			}

			if hex.EncodeToString(ntlmv2Response) != tc.expexpectedNTLMv2Hash {
				t.Errorf("For domain %s, username %s: expected hash %s, got %s", tc.domain, tc.username, tc.expexpectedNTLMv2Hash, hex.EncodeToString(ntlmv2Response))
			}
		})
	}
}

// Sun Jul 27 09:12:41 PM CEST 2025
// [SMB] NTLMv2-SSP Client   : 192.168.56.101
// [SMB] NTLMv2-SSP Username : MANTICORE\Administrator
// [SMB] NTLMv2-SSP Password : Admin123!
// [SMB] NTLMv2-SSP Hash     : Administrator::MANTICORE:1122334455667788:AA31E2B37DB70FBC52DE09FFCFE55CB3:010100000000000080D8F1103BFFDB0146F915A565948FCE00000000020008004F0035003700480001001E00570049004E002D00570054004700550050005600310050004B004200420004003400570049004E002D00570054004700550050005600310050004B00420042002E004F003500370048002E004C004F00430041004C00030014004F003500370048002E004C004F00430041004C00050014004F003500370048002E004C004F00430041004C000700080080D8F1103BFFDB01060004000200000008003000300000000000000000000000003000007948367A40E04B952E2A37C76F46258B0A49A6DC558216F56760316E45BC84D50A001000000000000000000000000000000000000900220063006900660073002F003100390032002E003100360038002E00350036002E0031000000000000000000
