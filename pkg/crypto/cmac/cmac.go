package cmac

import (
	"crypto/aes"
	"crypto/cipher"
	"hash"
)

const (
	BlockSize = 16
)

type cmac struct {
	k1, k2 []byte
	block  cipher.Block
	x      []byte
	buf    []byte
}

// New returns a new CMAC-AES-128 hash using the given cipher.Block.
func New(c cipher.Block) hash.Hash {
	if c.BlockSize() != BlockSize {
		panic("cmac: block size must be 16")
	}

	k1, k2 := generateSubkeys(c)

	return &cmac{
		k1:    k1,
		k2:    k2,
		block: c,
		x:     make([]byte, BlockSize),
		buf:   make([]byte, 0, BlockSize),
	}
}

func (d *cmac) Write(p []byte) (nn int, err error) {
	nn = len(p)
	d.buf = append(d.buf, p...)

	// Process complete blocks only if we have MORE than one block buffered.
	// We must reserve the last block (or partial block) for Sum() because logic differs.
	// Actually, we process full blocks immediately, but we must keep at least one byte?
	// No, we process all complete blocks except the very last one potentially?
	// Standard strategy: buffer. If buffer >= BlockSize, process (buffer - remainder).
	// But we don't know if this is the last write.
	// We MUST always keep at least a potential partial block?
	//
	// No, checking standard implementations:
	// Process as many full blocks as possible, but if input is exactly multiple of block size,
	// we still don't know if there is more data coming.
	// Wait, Sum() is called at the end.

	for len(d.buf) > BlockSize {
		// Process one block
		xor(d.x, d.buf[:BlockSize])
		d.block.Encrypt(d.x, d.x)
		d.buf = d.buf[BlockSize:]
	}
	// Post-condition: len(d.buf) <= BlockSize
	// But we might have processed the "last" block if stream ended here?
	// If stream ends, d.buf is the last block (could be full or partial).
	// If d.buf is FULL block (16 bytes), and we call Sum():
	// It treats it as a complete block (xor k1).
	// If d.buf is PARTIAL (or empty), it treats as incomplete (padding + xor k2).

	// Issue: If we have exactly 16 bytes in buf, and Write comes with 0 bytes (eof?),
	// effectively we finish.
	// If Write comes with more bytes, the 16 bytes in buf were NOT the last block.
	// So we can safely process blocks as long as we leave SOMETHING in buffer?
	// Or we just buffer everything? No, inefficient.
	// The standard way: Only process `len(buf) / BlockSize` blocks?
	// We need to keep the "leftover".
	// If `len(buf) > BlockSize`, we can process `len(buf) - BlockSize`?
	// To ensure we always have the potential last chunk in `buf`.
	// Simple approach:

	return nn, nil
}

func (d *cmac) Sum(in []byte) []byte {
	// Make a copy of state to verify without modifying
	// But Sum usually appends to `in` and returns.
	// We need to finish calculation.
	// Copy D state?
	// For SMB signing, we usually discard the hasher after Sum.
	// But hash.Hash says Sum "does not change the underlying state".
	// So we need to copy.

	x := make([]byte, BlockSize)
	copy(x, d.x)

	// Last block logic
	lastBlock := make([]byte, BlockSize)

	// If buf is full block (16 bytes) -> It's a complete last block?
	// RFC 4493: "If Mn* is a complete block... XOR K1"
	// "If Mn* is incomplete... Padding... XOR K2"
	// Wait. If input length was 0?
	// Then n=1, incomplete (consisting of padding).

	// How do we know if "buf" is complete?
	// If len(buf) == 16, it is complete.
	// IF len(buf) < 16, it is incomplete.

	if len(d.buf) == BlockSize {
		copy(lastBlock, d.buf)
		xor(lastBlock, d.k1)
	} else {
		copy(lastBlock, d.buf)
		lastBlock[len(d.buf)] = 0x80 // Padding
		xor(lastBlock, d.k2)
	}

	xor(x, lastBlock)
	d.block.Encrypt(x, x)

	return append(in, x...)
}

func (d *cmac) Reset() {
	d.x = make([]byte, BlockSize)
	d.buf = make([]byte, 0, BlockSize)
}

func (d *cmac) Size() int {
	return BlockSize
}

func (d *cmac) BlockSize() int {
	return BlockSize
}

// generateSubkeys derived from RFC 4493
func generateSubkeys(block cipher.Block) ([]byte, []byte) {
	const rb = 0x87

	l := make([]byte, BlockSize)
	block.Encrypt(l, make([]byte, BlockSize))

	k1 := make([]byte, BlockSize)
	shiftLeft(k1, l)
	if l[0]&0x80 != 0 {
		k1[BlockSize-1] ^= rb
	}

	k2 := make([]byte, BlockSize)
	shiftLeft(k2, k1)
	if k1[0]&0x80 != 0 {
		k2[BlockSize-1] ^= rb
	}

	return k1, k2
}

func shiftLeft(dst, src []byte) {
	var overflow byte
	for i := len(src) - 1; i >= 0; i-- {
		b := src[i]
		dst[i] = (b << 1) | overflow
		overflow = (b & 0x80) >> 7
	}
}

func xor(dst, src []byte) {
	for i := 0; i < len(dst); i++ {
		dst[i] ^= src[i]
	}
}

// One-shot
func Sum(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	h := New(block)
	h.Write(data)
	return h.Sum(nil), nil
}
