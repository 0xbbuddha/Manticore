package utils_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/TheManticoreProject/Manticore/utils"
)

func TestPathSafeString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "no unsafe characters",
			input:    "safe_filename_123",
			expected: "safe_filename_123",
		},
		{
			name:     "common unsafe characters",
			input:    "file/name\\with:bad*chars?\"<>|",
			expected: "file_name_with_bad_chars_____",
		},
		{
			name:     "whitespace characters",
			input:    "file name\nwith\rspaces\t",
			expected: "file_name_with_spaces_",
		},
		{
			name:     "mixed safe and unsafe",
			input:    "My Document (v1.0)/part_A.txt",
			expected: "My_Document_(v1.0)_part_A.txt",
		},
		{
			name:     "all unsafe characters",
			input:    "/:*?\"<>| \n\r\t",
			expected: "____________",
		},
		{
			name:     "multiple occurrences of same unsafe char",
			input:    "path//to\\file",
			expected: "path__to_file",
		},
		{
			name:     "leading/trailing unsafe chars",
			input:    " /file.txt ",
			expected: "__file.txt_",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := utils.PathSafeString(tt.input)
			if got != tt.expected {
				t.Errorf("PathSafeString(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestEnsureDirExists(t *testing.T) {
	baseTempDir := filepath.Join(os.TempDir(), "test_ensure_dir_exists")
	// Ensure cleanup for all tests in this function
	defer func() {
		if err := os.RemoveAll(baseTempDir); err != nil {
			t.Logf("Failed to clean up base temp directory %q: %v", baseTempDir, err)
		}
	}()

	t.Run("directory does not exist", func(t *testing.T) {
		dirPath := filepath.Join(baseTempDir, "new_dir")
		// Ensure it doesn't exist before the test
		_ = os.RemoveAll(dirPath)

		err := utils.EnsureDirExists(dirPath)
		if err != nil {
			t.Fatalf("EnsureDirExists(%q) returned an error: %v", dirPath, err)
		}

		if _, err := os.Stat(dirPath); os.IsNotExist(err) {
			t.Errorf("EnsureDirExists(%q) failed to create directory", dirPath)
		}
	})

	t.Run("directory already exists", func(t *testing.T) {
		dirPath := filepath.Join(baseTempDir, "existing_dir")
		err := os.MkdirAll(dirPath, 0755)
		if err != nil {
			t.Fatalf("Failed to create pre-existing directory: %v", err)
		}

		err = utils.EnsureDirExists(dirPath)
		if err != nil {
			t.Errorf("EnsureDirExists(%q) returned an error for existing directory: %v", dirPath, err)
		}
	})

	t.Run("nested directories", func(t *testing.T) {
		dirPath := filepath.Join(baseTempDir, "parent", "child", "grandchild")
		// Ensure parent doesn't exist before the test
		_ = os.RemoveAll(filepath.Join(baseTempDir, "parent"))

		err := utils.EnsureDirExists(dirPath)
		if err != nil {
			t.Fatalf("EnsureDirExists(%q) returned an error for nested directories: %v", dirPath, err)
		}

		if _, err := os.Stat(dirPath); os.IsNotExist(err) {
			t.Errorf("EnsureDirExists(%q) failed to create nested directories", dirPath)
		}
	})

	t.Run("path exists as file returns error", func(t *testing.T) {
		filePath := filepath.Join(baseTempDir, "somefile")
		// Ensure fresh base dir
		_ = os.RemoveAll(baseTempDir)
		if err := os.MkdirAll(baseTempDir, 0755); err != nil {
			t.Fatalf("failed to create base temp dir: %v", err)
		}
		// Create a file at the path
		f, err := os.Create(filePath)
		if err != nil {
			t.Fatalf("failed to create file for test: %v", err)
		}
		_ = f.Close()

		err = utils.EnsureDirExists(filePath)
		if err == nil {
			t.Fatalf("EnsureDirExists(%q) did not return error when path is an existing file", filePath)
		}
	})
}
