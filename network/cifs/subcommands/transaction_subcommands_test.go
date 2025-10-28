package subcommands_test

import (
	"testing"

	cifs "github.com/TheManticoreProject/Manticore/network/cifs/subcommands"
)

func TestTransactionSubcommandString(t *testing.T) {
	tests := []struct {
		name     string
		subCmd   cifs.TransactionSubcommand
		expected string
	}{
		{
			name:     "SET_NMPIPE_STATE",
			subCmd:   cifs.TRANS_SET_NMPIPE_STATE,
			expected: "SET_NMPIPE_STATE",
		},
		{
			name:     "RAW_READ_NMPIPE",
			subCmd:   cifs.TRANS_RAW_READ_NMPIPE,
			expected: "RAW_READ_NMPIPE",
		},
		{
			name:     "QUERY_NMPIPE_STATE",
			subCmd:   cifs.TRANS_QUERY_NMPIPE_STATE,
			expected: "QUERY_NMPIPE_STATE",
		},
		{
			name:     "QUERY_NMPIPE_INFO",
			subCmd:   cifs.TRANS_QUERY_NMPIPE_INFO,
			expected: "QUERY_NMPIPE_INFO",
		},
		{
			name:     "PEEK_NMPIPE",
			subCmd:   cifs.TRANS_PEEK_NMPIPE,
			expected: "PEEK_NMPIPE",
		},
		{
			name:     "TRANSACT_NMPIPE",
			subCmd:   cifs.TRANS_TRANSACT_NMPIPE,
			expected: "TRANSACT_NMPIPE",
		},
		{
			name:     "RAW_WRITE_NMPIPE",
			subCmd:   cifs.TRANS_RAW_WRITE_NMPIPE,
			expected: "RAW_WRITE_NMPIPE",
		},
		{
			name:     "READ_NMPIPE",
			subCmd:   cifs.TRANS_READ_NMPIPE,
			expected: "READ_NMPIPE",
		},
		{
			name:     "WRITE_NMPIPE",
			subCmd:   cifs.TRANS_WRITE_NMPIPE,
			expected: "WRITE_NMPIPE",
		},
		{
			name:     "WAIT_NMPIPE",
			subCmd:   cifs.TRANS_WAIT_NMPIPE,
			expected: "WAIT_NMPIPE",
		},
		{
			name:     "CALL_NMPIPE",
			subCmd:   cifs.TRANS_CALL_NMPIPE,
			expected: "CALL_NMPIPE",
		},
		{
			name:     "Unknown subcommand",
			subCmd:   cifs.TransactionSubcommand(0xFFFF),
			expected: "UNKNOWN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.subCmd.String()
			if result != tt.expected {
				t.Errorf("String() = %v, want %v", result, tt.expected)
			}
		})
	}
}
