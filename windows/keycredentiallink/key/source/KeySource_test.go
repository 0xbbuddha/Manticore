package source_test

import (
	"testing"

	"github.com/TheManticoreProject/Manticore/windows/keycredentiallink/key/source"
)

func TestKeySource_String(t *testing.T) {
	tests := []struct {
		name     string
		ks       source.KeySource
		expected string
	}{
		{
			name:     "AD Key Source",
			ks:       source.KeySource{Value: source.KeySource_AD},
			expected: "Active Directory (AD)",
		},
		{
			name:     "Azure AD Key Source",
			ks:       source.KeySource{Value: source.KeySource_AzureAD},
			expected: "Azure Active Directory (AAD)",
		},
		{
			name:     "Unknown Key Source",
			ks:       source.KeySource{Value: 0xFF},
			expected: "Unknown KeySource: 255",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ks.String(); got != tt.expected {
				t.Errorf("KeySource.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestKeySource_Unmarshal(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    uint8
		wantErr bool
	}{
		{
			name:    "Valid AD Source",
			data:    []byte{source.KeySource_AD},
			want:    source.KeySource_AD,
			wantErr: false,
		},
		{
			name:    "Valid Azure AD Source",
			data:    []byte{source.KeySource_AzureAD},
			want:    source.KeySource_AzureAD,
			wantErr: false,
		},
		{
			name:    "Empty Data",
			data:    []byte{},
			want:    0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ks source.KeySource
			_, err := ks.Unmarshal(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("KeySource.Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && ks.Value != tt.want {
				t.Errorf("KeySource.Unmarshal() = %v, want %v", ks.Value, tt.want)
			}
		})
	}
}

func TestKeySource_Marshal(t *testing.T) {
	tests := []struct {
		name    string
		ks      source.KeySource
		want    []byte
		wantErr bool
	}{
		{
			name:    "Marshal AD Source",
			ks:      source.KeySource{Value: source.KeySource_AD},
			want:    []byte{source.KeySource_AD},
			wantErr: false,
		},
		{
			name:    "Marshal Azure AD Source",
			ks:      source.KeySource{Value: source.KeySource_AzureAD},
			want:    []byte{source.KeySource_AzureAD},
			wantErr: false,
		},
		{
			name:    "Marshal Unknown Source",
			ks:      source.KeySource{Value: 0xFF},
			want:    []byte{0xFF},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.ks.Marshal()
			if (err != nil) != tt.wantErr {
				t.Errorf("KeySource.Marshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(got) != len(tt.want) {
				t.Errorf("KeySource.Marshal() = %v, want %v", got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("KeySource.Marshal()[%d] = %v, want %v", i, got[i], tt.want[i])
				}
			}
		})
	}
}
