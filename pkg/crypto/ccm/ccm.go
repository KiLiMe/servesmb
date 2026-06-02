// Package ccm implements AES-CCM (Counter with CBC-MAC) authenticated encryption
// as defined in NIST SP 800-38C and RFC 3610.
// Used by SMB 3.0/3.0.2 for message encryption.
package ccm

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"math"
)

type ccm struct {
	cipher   cipher.Block
	tagSize  int
	nonceSize int
}

// New creates a new AES-CCM AEAD with the specified tag size and nonce size.
// For SMB3: tagSize=16, nonceSize=11.
func New(block cipher.Block, tagSize, nonceSize int) (cipher.AEAD, error) {
	if block.BlockSize() != 16 {
		return nil, errors.New("ccm: block cipher must have 16-byte blocks")
	}
	if tagSize < 4 || tagSize > 16 || tagSize%2 != 0 {
		return nil, errors.New("ccm: invalid tag size")
	}
	if nonceSize < 7 || nonceSize > 13 {
		return nil, errors.New("ccm: invalid nonce size")
	}
	return &ccm{cipher: block, tagSize: tagSize, nonceSize: nonceSize}, nil
}

func (c *ccm) NonceSize() int { return c.nonceSize }
func (c *ccm) Overhead() int  { return c.tagSize }

// Seal encrypts and authenticates plaintext with associated data.
// Returns ciphertext || tag.
func (c *ccm) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != c.nonceSize {
		panic("ccm: incorrect nonce length")
	}

	// Compute CBC-MAC tag
	tag := c.cbcMAC(nonce, plaintext, additionalData)

	// CTR encrypt: encrypt tag first (counter=0), then plaintext (counter=1,2,...)
	ret, out := sliceForAppend(dst, len(plaintext)+c.tagSize)

	// Counter block: Flags(1) || Nonce || Counter
	q := 15 - c.nonceSize // length of Q field
	a0 := make([]byte, 16)
	a0[0] = byte(q - 1)
	copy(a0[1:1+c.nonceSize], nonce)
	// Counter = 0 for tag encryption
	s0 := make([]byte, 16)
	c.cipher.Encrypt(s0, a0)

	// Encrypt tag
	encTag := make([]byte, c.tagSize)
	for i := 0; i < c.tagSize; i++ {
		encTag[i] = tag[i] ^ s0[i]
	}

	// CTR encrypt plaintext starting at counter=1
	ctr := make([]byte, 16)
	copy(ctr, a0)
	for i := 0; i < len(plaintext); i += 16 {
		// Increment counter
		incrementCounter(ctr, q)
		var keystream [16]byte
		c.cipher.Encrypt(keystream[:], ctr)
		end := i + 16
		if end > len(plaintext) {
			end = len(plaintext)
		}
		for j := i; j < end; j++ {
			out[j] = plaintext[j] ^ keystream[j-i]
		}
	}

	// Append encrypted tag
	copy(out[len(plaintext):], encTag)
	return ret
}

// Open decrypts and authenticates ciphertext (which includes the tag at the end).
func (c *ccm) Open(dst, nonce, ciphertextAndTag, additionalData []byte) ([]byte, error) {
	if len(nonce) != c.nonceSize {
		return nil, errors.New("ccm: incorrect nonce length")
	}
	if len(ciphertextAndTag) < c.tagSize {
		return nil, errors.New("ccm: ciphertext too short")
	}

	ciphertext := ciphertextAndTag[:len(ciphertextAndTag)-c.tagSize]
	encTag := ciphertextAndTag[len(ciphertextAndTag)-c.tagSize:]

	q := 15 - c.nonceSize
	a0 := make([]byte, 16)
	a0[0] = byte(q - 1)
	copy(a0[1:1+c.nonceSize], nonce)

	// Decrypt tag: CTR counter=0
	s0 := make([]byte, 16)
	c.cipher.Encrypt(s0, a0)
	tag := make([]byte, c.tagSize)
	for i := 0; i < c.tagSize; i++ {
		tag[i] = encTag[i] ^ s0[i]
	}

	// CTR decrypt plaintext starting at counter=1
	plaintext := make([]byte, len(ciphertext))
	ctr := make([]byte, 16)
	copy(ctr, a0)
	for i := 0; i < len(ciphertext); i += 16 {
		incrementCounter(ctr, q)
		var keystream [16]byte
		c.cipher.Encrypt(keystream[:], ctr)
		end := i + 16
		if end > len(ciphertext) {
			end = len(ciphertext)
		}
		for j := i; j < end; j++ {
			plaintext[j] = ciphertext[j] ^ keystream[j-i]
		}
	}

	// Verify CBC-MAC
	expectedTag := c.cbcMAC(nonce, plaintext, additionalData)
	if subtle.ConstantTimeCompare(tag, expectedTag[:c.tagSize]) != 1 {
		return nil, errors.New("ccm: authentication failed")
	}

	ret, out := sliceForAppend(dst, len(plaintext))
	copy(out, plaintext)
	return ret, nil
}

// cbcMAC computes the CBC-MAC tag per RFC 3610 / SP 800-38C.
func (c *ccm) cbcMAC(nonce, plaintext, additionalData []byte) []byte {
	q := 15 - c.nonceSize
	t := (c.tagSize - 2) / 2
	hasAD := len(additionalData) > 0

	// First block B0
	b0 := make([]byte, 16)
	var flags byte
	if hasAD {
		flags |= 1 << 6
	}
	flags |= byte(t) << 3
	flags |= byte(q - 1)
	b0[0] = flags
	copy(b0[1:1+c.nonceSize], nonce)
	// Encode message length Q in q bytes (big-endian)
	msgLen := len(plaintext)
	for i := 0; i < q; i++ {
		b0[15-i] = byte(msgLen >> (8 * i))
	}

	// CBC-MAC: X = E(K, B0)
	x := make([]byte, 16)
	c.cipher.Encrypt(x, b0)

	// Process additional data
	if hasAD {
		var adHeader []byte
		adLen := len(additionalData)
		if adLen < (1<<16 - 1<<8) {
			adHeader = make([]byte, 2)
			binary.BigEndian.PutUint16(adHeader, uint16(adLen))
		} else if uint64(adLen) < math.MaxUint32 {
			adHeader = make([]byte, 6)
			adHeader[0] = 0xFF
			adHeader[1] = 0xFE
			binary.BigEndian.PutUint32(adHeader[2:], uint32(adLen))
		}

		adBlock := append(adHeader, additionalData...)
		// Pad to 16-byte boundary
		if len(adBlock)%16 != 0 {
			adBlock = append(adBlock, make([]byte, 16-len(adBlock)%16)...)
		}
		for i := 0; i < len(adBlock); i += 16 {
			for j := 0; j < 16; j++ {
				x[j] ^= adBlock[i+j]
			}
			c.cipher.Encrypt(x, x)
		}
	}

	// Process plaintext
	padded := plaintext
	if len(padded)%16 != 0 {
		padded = make([]byte, len(plaintext)+16-len(plaintext)%16)
		copy(padded, plaintext)
	}
	for i := 0; i < len(padded); i += 16 {
		for j := 0; j < 16; j++ {
			x[j] ^= padded[i+j]
		}
		c.cipher.Encrypt(x, x)
	}

	return x[:c.tagSize]
}

func incrementCounter(ctr []byte, q int) {
	for i := 15; i >= 16-q; i-- {
		ctr[i]++
		if ctr[i] != 0 {
			break
		}
	}
}

func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}
