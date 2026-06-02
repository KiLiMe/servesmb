package kdf

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

// CounterMode implements NIST SP800-108 KDF in Counter Mode with HMAC-SHA256
// Inputs:
// - ki: Key derivation key
// - label: Purpose string (e.g., "SMB2AESCMAC")
// - context: Context string (e.g., "SmbSign")
// - l: Output length in bits (e.g., 128)
func CounterMode(ki, label, context []byte, l uint32) []byte {
	// r = 32 (length of loop counter in bits) -> 4 bytes
	// k = HMAC-SHA256(ki, [i]2 || Label || 0x00 || Context || [L]2)

	n := (l + 255) / 256 // Number of iterations needed
	result := make([]byte, 0, n*32)

	h := hmac.New(sha256.New, ki)

	for i := uint32(1); i <= n; i++ {
		h.Reset()

		// SP800-108 Standard: Big Endian
		binary.Write(h, binary.BigEndian, i)

		h.Write(label)
		// Explicit 0x00 separator
		h.Write([]byte{0x00})

		h.Write(context)

		binary.Write(h, binary.BigEndian, l)

		result = append(result, h.Sum(nil)...)
	}

	return result[:l/8]
}
