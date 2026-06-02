package ntlm

import (
	"encoding/binary"
)

func parseAvPairs(bs []byte) (map[uint16][]byte, bool) {
	m := make(map[uint16][]byte)
	off := 0
	for off+4 <= len(bs) {
		id := binary.LittleEndian.Uint16(bs[off : off+2])
		ln := binary.LittleEndian.Uint16(bs[off+2 : off+4])
		off += 4
		if id == 0 { // MsvAvEOL
			return m, true
		}
		if off+int(ln) > len(bs) {
			return nil, false
		}
		m[id] = bs[off : off+int(ln)]
		off += int(ln)
	}
	return nil, false
}
