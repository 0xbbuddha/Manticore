package ntlmv1

// ParityBit calculates the parity bit for a given integer.
// It returns 1 if the number of set bits (1s) in the binary representation
// of the input is even, and 0 if the number is odd.
// This is used in DES key generation to ensure each byte has odd parity.
func ParityBit(n int) int {
	parity := 1
	for n != 0 {
		if (n & 1) == 1 {
			parity ^= 1
		}
		n >>= 1
	}
	return parity
}

// ParityAdjust takes a byte slice as input and adjusts it for DES key parity.
// For each 7 bits of the input, it adds a parity bit as the 8th bit to ensure
// odd parity (each byte has an odd number of 1 bits).
// This is required for DES key generation in NTLM authentication.
//
// The function processes the input in 7-bit chunks, adding a parity bit to each chunk
// to form 8-bit bytes in the output. If the input length is not a multiple of 7 bits,
// it pads with zeros.
//
// Returns the parity-adjusted byte slice and any error encountered during processing.
func ParityAdjust(key []byte) ([]byte, error) {
	// Get a stream of bits from the key
	keyBits := []byte{}
	for _, b := range key {
		for i := 7; i >= 0; i-- {
			keyBits = append(keyBits, (b>>i)&1)
		}
	}
	keyBits = keyBits[:len(keyBits)-len(keyBits)%7]

	// Adjust the key for parity
	parityAdjustedKey := []byte{}
	for i := 0; i < len(keyBits); i += 7 {
		parityAdjustedByte := byte(0)
		for offset, bit := range keyBits[i : i+7] {
			if bit == 1 {
				parityAdjustedByte |= (1 << (7 - offset))
			}
		}
		parityAdjustedByte = parityAdjustedByte | byte(ParityBit(int(parityAdjustedByte)))
		parityAdjustedKey = append(parityAdjustedKey, parityAdjustedByte)
	}

	return parityAdjustedKey, nil
}
