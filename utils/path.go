package utils

import (
	"fmt"
	"os"
	"strings"
)

// PathSafeString returns a string that is safe to use in file paths by replacing unsafe characters.
//
// Parameters:
// - input: The input string to be sanitized.
//
// Returns:
// - A string that is safe to use in file paths.
func PathSafeString(input string) string {
	unsafeChars := []string{"/", "\\", ":", "*", "?", "\"", "<", ">", "|", " ", "\n", "\r", "\t", "\v", "\f", "\b", " "}
	safeString := input
	for _, char := range unsafeChars {
		safeString = strings.ReplaceAll(safeString, char, "_")
	}
	return safeString
}

// EnsureDirExists checks if a directory exists and creates it if it doesn't.
// It uses os.MkdirAll, so it can create parent directories as needed.
//
// Parameters:
// - dirPath: The path of the directory to ensure existence.
//
// Returns:
// - An error if the directory could not be created or if there was an issue checking its existence.
func EnsureDirExists(dirPath string) error {
	info, err := os.Stat(dirPath)
	if err == nil {
		if info.IsDir() {
			return nil
		}
		return fmt.Errorf("path exists and is not a directory: %s", dirPath)
	}
	if os.IsNotExist(err) {
		return os.MkdirAll(dirPath, 0755) // 0755 is a common permission for directories
	}
	return err
}
