package utils

// ReadUntilNullTerminator reads bytes from a byte slice until it encounters a null byte
// and returns the data up to (but not including) the null byte.
//
// Parameters:
// - data: The byte slice to read from
//
// Returns:
// - A byte slice containing the data up to the first null byte
// - The number of bytes read (including the null byte)
func ReadUntilNullTerminator(data []byte) ([]byte, int) {
	bytesReadExcludingNullTerminator := 0

	for i, b := range data {
		if b == 0 {
			bytesReadIncludingNullTerminator := bytesReadExcludingNullTerminator + 1
			return data[:i], bytesReadIncludingNullTerminator
		}
		bytesReadExcludingNullTerminator++
	}

	return data, bytesReadExcludingNullTerminator
}

// ReadUntilNullTerminatorUTF16 reads bytes from a byte slice until it encounters a UTF-16 null terminator
// and returns the data up to (but not including) the null terminator.
//
// Parameters:
// - data: The byte slice to read from
//
// Returns:
// - A byte slice containing the data up to the first null terminator
// - The number of bytes read (including the null terminator)
func ReadUntilNullTerminatorUTF16(data []byte) ([]byte, int) {
	bytesReadExcludingNullTerminator := 0

	for i := 0; i < len(data)-1; i += 2 {
		if data[i] == 0 && data[i+1] == 0 {
			bytesReadIncludingNullTerminator := bytesReadExcludingNullTerminator + 2
			return data[:i], bytesReadIncludingNullTerminator
		}
		bytesReadExcludingNullTerminator += 2
	}

	if len(data)%2 == 1 {
		bytesReadIncludingNullTerminator := bytesReadExcludingNullTerminator + 1
		return data, bytesReadIncludingNullTerminator
	} else {
		return data, bytesReadExcludingNullTerminator
	}
}
