package main

import (
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	kerbcrypto "github.com/TheManticoreProject/Manticore/network/kerberos/crypto"
	"github.com/TheManticoreProject/Manticore/network/kerberos/messages"
)

func main() {
	if len(os.Args) < 5 {
		fmt.Fprintf(os.Stderr, "usage: %s <kdc-host> <username> <realm> <password>\n", os.Args[0])
		os.Exit(1)
	}
	kdc := os.Args[1]
	user := os.Args[2]
	realm := strings.ToUpper(os.Args[3])
	password := os.Args[4]

	reqBytes, err := buildASReqBytes(user, realm, password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] build AS-REQ: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[*] AS-REQ built: %d bytes\n", len(reqBytes))
	fmt.Printf("[*] AS-REQ hex:\n%s\n", hexDump(reqBytes))

	// ── TCP ──────────────────────────────────────────────────────────────────
	fmt.Printf("\n=== TCP ===\n")
	tcpRaw, tcpLenBytes, err := sendTCP(kdc, reqBytes)
	if err != nil {
		fmt.Printf("[-] TCP error: %v\n", err)
	} else {
		fmt.Printf("[*] TCP framing length bytes: %s (= %d)\n",
			hex.EncodeToString(tcpLenBytes), binary.BigEndian.Uint32(tcpLenBytes))
		analyzeResponse("TCP", tcpRaw)
	}

	// ── UDP ──────────────────────────────────────────────────────────────────
	fmt.Printf("\n=== UDP ===\n")
	udpRaw, err := sendUDP(kdc, reqBytes)
	if err != nil {
		fmt.Printf("[-] UDP error: %v\n", err)
	} else {
		analyzeResponse("UDP", udpRaw)
	}
}

func analyzeResponse(proto string, raw []byte) {
	fmt.Printf("[*] %s response: %d bytes\n", proto, len(raw))
	if len(raw) == 0 {
		fmt.Printf("[!] Empty response on %s\n", proto)
		return
	}
	fmt.Printf("[*] First bytes: %s\n", hex.EncodeToString(raw[:min(16, len(raw))]))
	fmt.Printf("[*] Full response hex:\n%s\n", hexDump(raw))

	// Outer tag
	tag := raw[0]
	switch tag {
	case 0x6B:
		fmt.Printf("[*] Tag 0x6B = APPLICATION[11] → AS-REP\n")
	case 0x7E:
		fmt.Printf("[*] Tag 0x7E = APPLICATION[30] → KRB-ERROR\n")
	default:
		fmt.Printf("[!] Unknown tag: 0x%02X\n", tag)
	}

	// Raw asn1
	var rv asn1.RawValue
	rest, err := asn1.Unmarshal(raw, &rv)
	if err != nil {
		fmt.Printf("[-] asn1.Unmarshal(RawValue): %v\n", err)
	} else {
		fmt.Printf("[+] asn1.Unmarshal OK: Class=%d Tag=%d Bytes=%d Rest=%d\n",
			rv.Class, rv.Tag, len(rv.Bytes), len(rest))
	}

	// KRBError
	var krbErr messages.KRBError
	if _, err := krbErr.Unmarshal(raw); err != nil {
		fmt.Printf("[-] KRBError.Unmarshal: %v\n", err)
	} else {
		fmt.Printf("[+] KRBError OK: ErrorCode=%d EText=%q\n", krbErr.ErrorCode, krbErr.EText)
	}

	// ASRep
	var asRep messages.ASRep
	if _, err := asRep.Unmarshal(raw); err != nil {
		fmt.Printf("[-] ASRep.Unmarshal: %v\n", err)
	} else {
		fmt.Printf("[+] ASRep OK: CRealm=%s\n", asRep.CRealm)
	}
}

func buildASReqBytes(username, realm, password string) ([]byte, error) {
	etype := messages.ETypeAES256CTSHMACSHA196
	salt := realm + username

	key, err := kerbcrypto.StringToKey(etype, password, salt, nil)
	if err != nil {
		return nil, fmt.Errorf("StringToKey: %w", err)
	}
	fmt.Printf("[*] AES256 key: %s\n", hex.EncodeToString(key))

	now := time.Now().UTC()
	ts := &messages.PAEncTSEnc{PATimestamp: now, PAUSec: now.Nanosecond() / 1000}
	ts_bytes, err := ts.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal PA-ENC-TS-ENC: %w", err)
	}
	fmt.Printf("[*] PA-ENC-TS-ENC plaintext: %s\n", hex.EncodeToString(ts_bytes))

	enc_ts, err := kerbcrypto.Encrypt(etype, key, kerbcrypto.KeyUsageASReqPAEncTimestamp, ts_bytes)
	if err != nil {
		return nil, fmt.Errorf("encrypt PA-ENC-TIMESTAMP: %w", err)
	}

	pa_enc_ts := messages.EncryptedData{EType: etype, Cipher: enc_ts}
	pa_enc_ts_bytes, err := asn1.Marshal(pa_enc_ts)
	if err != nil {
		return nil, fmt.Errorf("marshal EncryptedData: %w", err)
	}
	fmt.Printf("[*] PA-ENC-TIMESTAMP EncryptedData: %s\n", hex.EncodeToString(pa_enc_ts_bytes))

	req := &messages.ASReq{
		PVNO:    5,
		MsgType: 10,
		PAData: []messages.PAData{
			{PADataType: 128, PADataValue: []byte{0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0xff}},
			{PADataType: messages.PAEncTimestamp, PADataValue: pa_enc_ts_bytes},
		},
		ReqBody: messages.KDCReqBody{
			KDCOptions: asn1.BitString{Bytes: []byte{0x40, 0x00, 0x00, 0x00}, BitLength: 32},
			CName:      messages.PrincipalName{NameType: 1, NameString: []string{username}},
			Realm:      realm,
			SName:      messages.PrincipalName{NameType: 2, NameString: []string{"krbtgt", realm}},
			Till:       time.Now().UTC().Add(24 * time.Hour),
			Nonce:      0x12345678,
			EType:      []int{18, 17, 23},
		},
	}
	return req.Marshal()
}

func sendTCP(kdc string, reqBytes []byte) (resp []byte, lenBytes []byte, err error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(kdc, "88"), 10*time.Second)
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(reqBytes)))
	if _, err := conn.Write(append(lenBuf, reqBytes...)); err != nil {
		return nil, nil, fmt.Errorf("write: %w", err)
	}

	respLenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, respLenBuf); err != nil {
		return nil, respLenBuf, fmt.Errorf("read length: %w", err)
	}
	respLen := binary.BigEndian.Uint32(respLenBuf)

	respBuf := make([]byte, respLen)
	if respLen > 0 {
		if _, err := io.ReadFull(conn, respBuf); err != nil {
			return nil, respLenBuf, fmt.Errorf("read body (%d bytes): %w", respLen, err)
		}
	}
	return respBuf, respLenBuf, nil
}

func sendUDP(kdc string, reqBytes []byte) ([]byte, error) {
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(kdc, "88"))
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err := conn.Write(reqBytes); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}

	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	return buf[:n], nil
}

func hexDump(b []byte) string {
	var sb strings.Builder
	for i := 0; i < len(b); i += 16 {
		end := i + 16
		if end > len(b) {
			end = len(b)
		}
		sb.WriteString(fmt.Sprintf("%04x  ", i))
		for j := i; j < end; j++ {
			sb.WriteString(fmt.Sprintf("%02x ", b[j]))
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
