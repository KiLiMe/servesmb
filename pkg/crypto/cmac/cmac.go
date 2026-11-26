package cmac

import (
	"crypto/aes"
	"crypto/cipher"
	"hash"
)

const (
	BlockSize = 16
)

// cmac 是 AES-CMAC（RFC 4493）。原来是「先把整条报文 append 进 buf，再逐块
// 从 buf 里切片」——每个 SMB 应答 1 MiB，那一次 append 就是多拷一份，逐块
// 处理还要再走一遍切片与 16 字节循环异或。这里改成直接扫调用者的 p，异或用
// 两个 64 位字，状态放定长数组。行为与 RFC 4493 一致。
type cmac struct {
	k1, k2 [BlockSize]byte
	block  cipher.Block
	x      [BlockSize]byte
	buf    [BlockSize]byte
	nbuf   int
}

// New returns a new CMAC-AES-128 hash using the given cipher.Block.
func New(c cipher.Block) hash.Hash {
	if c.BlockSize() != BlockSize {
		panic("cmac: block size must be 16")
	}

	k1, k2 := generateSubkeys(c)

	return &cmac{k1: k1, k2: k2, block: c}
}

func (d *cmac) Write(p []byte) (nn int, err error) {
	nn = len(p)

	// 先把上次剩下的半块凑满
	if d.nbuf > 0 {
		need := BlockSize - d.nbuf
		// 正好凑满也不急着算：它可能就是最后一块，得留给 Sum 决定要不要异或 K1。
		if len(p) <= need {
			d.nbuf += copy(d.buf[d.nbuf:], p)
			return nn, nil
		}
		copy(d.buf[d.nbuf:], p[:need])
		d.processBlock(d.buf[:])
		d.nbuf = 0
		p = p[need:]
	}

	// 中间整块直接扫入参，不落缓冲；最后一块（可能正好整块）留在 buf 里等 Sum
	for len(p) > BlockSize {
		d.processBlock(p[:BlockSize])
		p = p[BlockSize:]
	}
	d.nbuf = copy(d.buf[:], p)

	return nn, nil
}

// processBlock 做 x = E(x XOR block)。
func (d *cmac) processBlock(b []byte) {
	xorBlock(&d.x, b)
	d.block.Encrypt(d.x[:], d.x[:])
}

func (d *cmac) Sum(in []byte) []byte {
	x := d.x // 拷一份：Sum 不许动状态

	var lastBlock [BlockSize]byte
	copy(lastBlock[:], d.buf[:d.nbuf]) // 尾巴必须是 0：buf 是定长数组，会留上一块的残渣
	if d.nbuf == BlockSize {
		xorBlock(&lastBlock, d.k1[:])
	} else {
		lastBlock[d.nbuf] = 0x80 // 填充
		xorBlock(&lastBlock, d.k2[:])
	}

	xorBlock(&x, lastBlock[:])
	d.block.Encrypt(x[:], x[:])

	return append(in, x[:]...)
}

func (d *cmac) Reset() {
	d.x = [BlockSize]byte{}
	d.buf = [BlockSize]byte{}
	d.nbuf = 0
}

func (d *cmac) Size() int { return BlockSize }

func (d *cmac) BlockSize() int { return BlockSize }

// generateSubkeys derived from RFC 4493
func generateSubkeys(block cipher.Block) (k1, k2 [BlockSize]byte) {
	var l [BlockSize]byte
	block.Encrypt(l[:], l[:])

	shiftLeft(&k1, l[:])
	if l[0]&0x80 != 0 {
		k1[BlockSize-1] ^= 0x87
	}
	shiftLeft(&k2, k1[:])
	if k1[0]&0x80 != 0 {
		k2[BlockSize-1] ^= 0x87
	}
	return k1, k2
}

func shiftLeft(dst *[BlockSize]byte, src []byte) {
	var overflow byte
	for i := BlockSize - 1; i >= 0; i-- {
		b := src[i]
		dst[i] = (b << 1) | overflow
		overflow = (b & 0x80) >> 7
	}
}

// xorBlock 按两个 64 位字异或：16 字节循环在热路径上要跑 65536 次/MiB。
func xorBlock(dst *[BlockSize]byte, src []byte) {
	d0 := le64(dst[0:8]) ^ le64(src[0:8])
	d1 := le64(dst[8:16]) ^ le64(src[8:16])
	put64(dst[0:8], d0)
	put64(dst[8:16], d1)
}

func le64(b []byte) uint64 {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}

func put64(b []byte, v uint64) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
	b[4] = byte(v >> 32)
	b[5] = byte(v >> 40)
	b[6] = byte(v >> 48)
	b[7] = byte(v >> 56)
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
