package smb2

import (
	"testing"
	"unicode/utf16"
)

// 中文名的每个字符都是 3 字节 UTF-8、1 个 UTF-16 单元：手写编码当时把字节偏移
// 当成单元下标，写出 "中\x00\x00\x00..." 这种，客户端读名字遇到 NUL 就停。
func TestEncodeUTF16LECJKNames(t *testing.T) {
	for _, s := range []string{"中文文件.txt", "简体说明.md", "ascii.txt", "混合 name 与空格"} {
		got := encodeUTF16LE(s)
		want := utf16.Encode([]rune(s))
		if len(got) != len(want)*2 {
			t.Fatalf("%q: 长度 %d 字节，want %d", s, len(got), len(want)*2)
		}
		for i, u := range want {
			gotU := uint16(got[i*2]) | uint16(got[i*2+1])<<8
			if gotU != u {
				t.Fatalf("%q: 第 %d 个单元是 %#x，want %#x", s, i, gotU, u)
			}
		}
		if back := string(utf16.Decode(want)); back != s {
			t.Fatalf("往返不一致：%q → %q", s, back)
		}
	}
}

// BMP 之外的字符必须编成代理对（4 字节），否则客户端读出来是乱码。
func TestEncodeUTF16LESurrogatePair(t *testing.T) {
	const s = "a𝄞b" // U+1D11E
	got := encodeUTF16LE(s)
	if len(got) != 8 {
		t.Fatalf("got %d 字节，want 8：% x", len(got), got)
	}
	units := make([]uint16, len(got)/2)
	for i := range units {
		units[i] = uint16(got[i*2]) | uint16(got[i*2+1])<<8
	}
	if back := string(utf16.Decode(units)); back != s {
		t.Fatalf("往返不一致：%q → %q", s, back)
	}
}
