package cmac

import (
	"crypto/aes"
	"encoding/hex"
	"testing"
)

// RFC 4493 的四个测试向量。摘掉这些断言，CMAC 改快改错都没人知道。
func TestRFC4493(t *testing.T) {
	key, _ := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct{ msg, want string }{
		{"", "bb1d6929e95937287fa37d129b756746"},
		{"6bc1bee22e409f96e93d7e117393172a", "070a16b46b4d4144f79bdd9dd04a287c"},
		{"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51" +
			"30c81c46a35ce411", "dfa66747de9ae63030ca32611497c827"},
		{"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51" +
			"30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
			"51f0bebf7e3b9d92fc49741779363cfe"},
	}
	for i, c := range cases {
		msg, _ := hex.DecodeString(c.msg)
		h := New(block)
		// 分片喂，验证跨 Write 的缓冲逻辑
		for j := 0; j < len(msg); j += 7 {
			end := j + 7
			if end > len(msg) {
				end = len(msg)
			}
			h.Write(msg[j:end])
		}
		got := hex.EncodeToString(h.Sum(nil))
		if got != c.want {
			t.Fatalf("第 %d 例：得到 %s，想要 %s", i+1, got, c.want)
		}
	}
}

func BenchmarkCMAC1MiB(b *testing.B) {
	key := make([]byte, 16)
	block, _ := aes.NewCipher(key)
	data := make([]byte, 1<<20)
	b.SetBytes(int64(len(data)))
	for i := 0; i < b.N; i++ {
		h := New(block)
		h.Write(data)
		h.Sum(nil)
	}
}
