package auth

// Minimal MD4 implementation sufficient for NT hash

type md4 struct {
	s   [4]uint32
	x   [16]uint32
	nx  int
	len uint64
}

func newMD4() *md4 {
	d := new(md4)
	d.Reset()
	return d
}

func (d *md4) Reset() {
	d.s[0] = 0x67452301
	d.s[1] = 0xEFCDAB89
	d.s[2] = 0x98BADCFE
	d.s[3] = 0x10325476
	d.nx = 0
	d.len = 0
}

func (d *md4) Write(p []byte) (n int, err error) {
	n = len(p)
	d.len += uint64(n)
	if d.nx > 0 {
		i := 0
		for i < len(p) && d.nx < 64 {
			d.x[d.nx>>2] |= uint32(p[i]) << (8 * (d.nx & 3))
			d.nx++
			i++
		}
		if d.nx == 64 {
			d.block()
			d.nx = 0
		}
		p = p[i:]
	}
	for len(p) >= 64 {
		for i := 0; i < 16; i++ {
			d.x[i] = uint32(p[4*i]) | uint32(p[4*i+1])<<8 | uint32(p[4*i+2])<<16 | uint32(p[4*i+3])<<24
		}
		d.block()
		p = p[64:]
	}
	for i := 0; i < len(p); i++ {
		d.x[d.nx>>2] |= uint32(p[i]) << (8 * (d.nx & 3))
		d.nx++
	}
	return
}

func (d *md4) Sum(in []byte) []byte {
	// Make a copy of d so that caller can keep writing and summing.
	dd := *d
	tmp := make([]byte, 0, 64)
	// Padding. Add a 1 bit and 0 bits until 56 bytes mod 64.
	tmp = append(tmp, 0x80)
	for (dd.nx+len(tmp))%64 != 56 {
		tmp = append(tmp, 0x00)
	}
	// Length in bits.
	bits := dd.len << 3
	for i := 0; i < 8; i++ {
		tmp = append(tmp, byte(bits>>(8*i)))
	}
	dd.Write(tmp)
	// Output
	out := make([]byte, 16)
	for i, s := range dd.s {
		out[4*i] = byte(s)
		out[4*i+1] = byte(s >> 8)
		out[4*i+2] = byte(s >> 16)
		out[4*i+3] = byte(s >> 24)
	}
	return append(in, out...)
}

func f(x, y, z uint32) uint32 { return (x & y) | (^x & z) }
func g(x, y, z uint32) uint32 { return (x & y) | (x & z) | (y & z) }
func h(x, y, z uint32) uint32 { return x ^ y ^ z }

func rol(x uint32, s uint) uint32 { return (x << s) | (x >> (32 - s)) }

func (d *md4) block() {
	a, b, c, e := d.s[0], d.s[1], d.s[2], d.s[3]
	// Round 1
	a = rol(a+f(b, c, e)+d.x[0], 3)
	e = rol(e+f(a, b, c)+d.x[1], 7)
	c = rol(c+f(e, a, b)+d.x[2], 11)
	b = rol(b+f(c, e, a)+d.x[3], 19)
	a = rol(a+f(b, c, e)+d.x[4], 3)
	e = rol(e+f(a, b, c)+d.x[5], 7)
	c = rol(c+f(e, a, b)+d.x[6], 11)
	b = rol(b+f(c, e, a)+d.x[7], 19)
	a = rol(a+f(b, c, e)+d.x[8], 3)
	e = rol(e+f(a, b, c)+d.x[9], 7)
	c = rol(c+f(e, a, b)+d.x[10], 11)
	b = rol(b+f(c, e, a)+d.x[11], 19)
	a = rol(a+f(b, c, e)+d.x[12], 3)
	e = rol(e+f(a, b, c)+d.x[13], 7)
	c = rol(c+f(e, a, b)+d.x[14], 11)
	b = rol(b+f(c, e, a)+d.x[15], 19)

	// Round 2
	a = rol(a+g(b, c, e)+d.x[0]+0x5a827999, 3)
	e = rol(e+g(a, b, c)+d.x[4]+0x5a827999, 5)
	c = rol(c+g(e, a, b)+d.x[8]+0x5a827999, 9)
	b = rol(b+g(c, e, a)+d.x[12]+0x5a827999, 13)
	a = rol(a+g(b, c, e)+d.x[1]+0x5a827999, 3)
	e = rol(e+g(a, b, c)+d.x[5]+0x5a827999, 5)
	c = rol(c+g(e, a, b)+d.x[9]+0x5a827999, 9)
	b = rol(b+g(c, e, a)+d.x[13]+0x5a827999, 13)
	a = rol(a+g(b, c, e)+d.x[2]+0x5a827999, 3)
	e = rol(e+g(a, b, c)+d.x[6]+0x5a827999, 5)
	c = rol(c+g(e, a, b)+d.x[10]+0x5a827999, 9)
	b = rol(b+g(c, e, a)+d.x[14]+0x5a827999, 13)
	a = rol(a+g(b, c, e)+d.x[3]+0x5a827999, 3)
	e = rol(e+g(a, b, c)+d.x[7]+0x5a827999, 5)
	c = rol(c+g(e, a, b)+d.x[11]+0x5a827999, 9)
	b = rol(b+g(c, e, a)+d.x[15]+0x5a827999, 13)

	// Round 3
	a = rol(a+h(b, c, e)+d.x[0]+0x6ed9eba1, 3)
	e = rol(e+h(a, b, c)+d.x[8]+0x6ed9eba1, 9)
	c = rol(c+h(e, a, b)+d.x[4]+0x6ed9eba1, 11)
	b = rol(b+h(c, e, a)+d.x[12]+0x6ed9eba1, 15)
	a = rol(a+h(b, c, e)+d.x[2]+0x6ed9eba1, 3)
	e = rol(e+h(a, b, c)+d.x[10]+0x6ed9eba1, 9)
	c = rol(c+h(e, a, b)+d.x[6]+0x6ed9eba1, 11)
	b = rol(b+h(c, e, a)+d.x[14]+0x6ed9eba1, 15)
	a = rol(a+h(b, c, e)+d.x[1]+0x6ed9eba1, 3)
	e = rol(e+h(a, b, c)+d.x[9]+0x6ed9eba1, 9)
	c = rol(c+h(e, a, b)+d.x[5]+0x6ed9eba1, 11)
	b = rol(b+h(c, e, a)+d.x[13]+0x6ed9eba1, 15)
	a = rol(a+h(b, c, e)+d.x[3]+0x6ed9eba1, 3)
	e = rol(e+h(a, b, c)+d.x[11]+0x6ed9eba1, 9)
	c = rol(c+h(e, a, b)+d.x[7]+0x6ed9eba1, 11)
	b = rol(b+h(c, e, a)+d.x[15]+0x6ed9eba1, 15)

	d.s[0] += a
	d.s[1] += b
	d.s[2] += c
	d.s[3] += e
	for i := range d.x {
		d.x[i] = 0
	}
}
