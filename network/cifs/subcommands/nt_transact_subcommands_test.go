package subcommands_test

import (
	"testing"

	cifs "github.com/TheManticoreProject/Manticore/network/cifs/subcommands"
)

func TestNtTransactSubcommandString(t *testing.T) {
	tests := []struct {
		name     string
		subCmd   cifs.NtTransactSubcommand
		expected string
	}{
		{
			name:     "CREATE",
			subCmd:   cifs.NT_TRANSACT_CREATE,
			expected: "CREATE",
		},
		{
			name:     "IOCTL",
			subCmd:   cifs.NT_TRANSACT_IOCTL,
			expected: "IOCTL",
		},
		{
			name:     "SET_SECURITY_DESC",
			subCmd:   cifs.NT_TRANSACT_SET_SECURITY_DESC,
			expected: "SET_SECURITY_DESC",
		},
		{
			name:     "NOTIFY_CHANGE",
			subCmd:   cifs.NT_TRANSACT_NOTIFY_CHANGE,
			expected: "NOTIFY_CHANGE",
		},
		{
			name:     "RENAME",
			subCmd:   cifs.NT_TRANSACT_RENAME,
			expected: "RENAME",
		},
		{
			name:     "QUERY_SECURITY_DESC",
			subCmd:   cifs.NT_TRANSACT_QUERY_SECURITY_DESC,
			expected: "QUERY_SECURITY_DESC",
		},
		{
			name:     "QUERY_QUOTA",
			subCmd:   cifs.NT_TRANSACT_QUERY_QUOTA,
			expected: "QUERY_QUOTA",
		},
		{
			name:     "SET_QUOTA",
			subCmd:   cifs.NT_TRANSACT_SET_QUOTA,
			expected: "SET_QUOTA",
		},
		{
			name:     "Unknown subcommand",
			subCmd:   cifs.NtTransactSubcommand(0xFFFF),
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
