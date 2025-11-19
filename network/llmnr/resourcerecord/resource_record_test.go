package resourcerecord_test

import (
	"github.com/TheManticoreProject/Manticore/network/llmnr/class"
	"github.com/TheManticoreProject/Manticore/network/llmnr/domain_name"
	"github.com/TheManticoreProject/Manticore/network/llmnr/llmnr_type"
	"github.com/TheManticoreProject/Manticore/network/llmnr/resourcerecord"

	"bytes"
	"testing"
)

func TestIPToRData(t *testing.T) {
	tests := []struct {
		ip       string
		expected []byte
	}{
		{"192.168.1.1", []byte{192, 168, 1, 1}},
		{"2001:0db8:85a3:0000:0000:8a2e:0370:7334", []byte{32, 1, 13, 184, 133, 163, 0, 0, 0, 0, 138, 46, 3, 112, 115, 52}},
		{"invalid_ip", nil},
	}

	for _, test := range tests {
		t.Run(test.ip, func(t *testing.T) {
			result := resourcerecord.IPToRData(test.ip)
			if result == nil && test.expected == nil {
				return
			} else if !bytes.Equal(result, test.expected) {
				t.Errorf("IPToRData(%s) = %v; want %v", test.ip, result, test.expected)
			}
		})
	}
}

func TestIPv4ToRData(t *testing.T) {
	tests := []struct {
		ip       string
		expected []byte
	}{
		{"192.168.1.1", []byte{192, 168, 1, 1}},
		{"0.0.0.0", []byte{0, 0, 0, 0}},
		{"255.255.255.255", []byte{255, 255, 255, 255}},
		{"127.0.0.1", []byte{127, 0, 0, 1}},
		{"", nil},
		{"256.256.256.256", nil},
		{"invalid_ip", nil},
	}

	for _, test := range tests {
		t.Run(test.ip, func(t *testing.T) {
			result := resourcerecord.IPv4ToRData(test.ip)
			if result == nil && test.expected == nil {
				return
			} else if !bytes.Equal(result, test.expected) {
				t.Errorf("IPv4ToRData(%s) = %v; want %v", test.ip, result, test.expected)
			}
		})
	}
}

func TestIPv6ToRData(t *testing.T) {
	tests := []struct {
		ip       string
		expected []byte
	}{
		{"::1", []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}},
		{"::", []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{"2001:db8::", []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{"2001:db8::1", []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}},
		{"2001:db8:0:0:0:0:2:1", []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01}},
		{"2001:db8:0:0:0:0:0:1", []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}},
		{"2001:db8::2:1", []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01}},
		{"2001:0db8:85a3:0000:0000:8a2e:0370:7334", []byte{0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34}},
		{"invalid_ip", nil},
	}

	for _, test := range tests {
		t.Run(test.ip, func(t *testing.T) {
			result := resourcerecord.IPv6ToRData(test.ip)
			if result == nil && test.expected == nil {
				return
			} else if !bytes.Equal(result, test.expected) {
				t.Errorf("IPv6ToRData(%s) = %v; want %v", test.ip, result, test.expected)
			}
		})
	}
}

func TestMarshalUnmarshalResourceRecord(t *testing.T) {
	type args struct {
		name  string
		rtype uint16
		class uint16
		ttl   uint32
		rdata []byte
	}
	tests := []struct {
		desc string
		args args
	}{
		{
			desc: "A record, IPv4",
			args: args{
				name:  "host1.example.com",
				rtype: 1, // TypeA
				class: 1, // ClassIN
				ttl:   60,
				rdata: []byte{192, 168, 1, 1},
			},
		},
		{
			desc: "AAAA record, IPv6",
			args: args{
				name:  "host2.example.com",
				rtype: 28, // TypeAAAA
				class: 1,
				ttl:   120,
				rdata: []byte{0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			},
		},
		{
			desc: "empty rdata",
			args: args{
				name:  "nodata.example.com",
				rtype: 16, // TXT
				class: 1,
				ttl:   60,
				rdata: []byte{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			rr := resourcerecord.ResourceRecord{}
			rr.Name.Unmarshal([]byte{
				byte(len(tt.args.name)), // hack: single label only
			})
			rr.Name = domain_name.DomainName(tt.args.name)
			rr.Type = llmnr_type.Type(tt.args.rtype)
			rr.Class = class.Class(tt.args.class)
			rr.TTL = tt.args.ttl
			rr.RData = tt.args.rdata

			data, err := rr.Marshal()
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}

			var rr2 resourcerecord.ResourceRecord
			n, err := rr2.Unmarshal(data)
			if err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}
			if n != len(data) {
				t.Errorf("expected bytes read %d, got %d", len(data), n)
			}

			// Compare fields
			if rr2.Name != rr.Name {
				t.Errorf("Name: got %q, want %q", rr2.Name, rr.Name)
			}
			if rr2.Type != rr.Type {
				t.Errorf("Type: got %v, want %v", rr2.Type, rr.Type)
			}
			if rr2.Class != rr.Class {
				t.Errorf("Class: got %v, want %v", rr2.Class, rr.Class)
			}
			if rr2.TTL != rr.TTL {
				t.Errorf("TTL: got %v, want %v", rr2.TTL, rr.TTL)
			}
			if rr2.RDLength != uint16(len(rr2.RData)) {
				t.Errorf("RDLength: got %v, want %v", rr2.RDLength, len(rr2.RData))
			}
			if !bytes.Equal(rr2.RData, rr.RData) {
				t.Errorf("RData: got %v, want %v", rr2.RData, rr.RData)
			}
		})
	}
}
