package ntlm

import (
	"bytes"
	"crypto/rc4"
	"errors"

	"github.com/3xport/servesmb/pkg/utf16le"
)

type Session struct {
	isClientSide bool

	user string
	guest bool

	negotiateFlags     uint32
	exportedSessionKey []byte
	clientSigningKey   []byte
	serverSigningKey   []byte
	clientSealKey      []byte
	serverSealKey      []byte

	clientHandle *rc4.Cipher
	serverHandle *rc4.Cipher

	infoMap map[uint16][]byte
}

// NegotiateFlags returns the NTLMSSP flags negotiated for this session.
func (s *Session) NegotiateFlags() uint32 { return s.negotiateFlags }

// ServerMechListMIC computes the SPNEGO mechListMIC the server returns in its
// final NegTokenResp (server-to-client direction, sequence number 0) over the
// DER-encoded MechTypeList. Returns nil if signing keys were not established
// (e.g. an anonymous/null session).
func (s *Session) ServerMechListMIC(mechList []byte) []byte {
	if len(s.serverSigningKey) == 0 {
		return nil
	}
	return computeMIC(s.negotiateFlags, s.serverSealKey, s.serverSigningKey, 0, mechList)
}

// VerifyClientMechListMIC verifies the mechListMIC the client sent in its
// NTLM AUTHENTICATE leg (client-to-server direction, sequence number 0).
func (s *Session) VerifyClientMechListMIC(sig, mechList []byte) bool {
	if len(s.clientSigningKey) == 0 || len(sig) != 16 {
		return false
	}
	want := computeMIC(s.negotiateFlags, s.clientSealKey, s.clientSigningKey, 0, mechList)
	return bytes.Equal(sig, want)
}

func (s *Session) User() string {
	return s.user
}

func (s *Session) IsGuest() bool {
	return s.guest
}

func (s *Session) SessionKey() []byte {
	return s.exportedSessionKey
}

type InfoMap struct {
	NbComputerName  string
	NbDomainName    string
	DnsComputerName string
	DnsDomainName   string
	DnsTreeName     string
}

func (s *Session) InfoMap() *InfoMap {
	return &InfoMap{
		NbComputerName:  utf16le.DecodeToString(s.infoMap[MsvAvNbComputerName]),
		NbDomainName:    utf16le.DecodeToString(s.infoMap[MsvAvNbDomainName]),
		DnsComputerName: utf16le.DecodeToString(s.infoMap[MsvAvDnsComputerName]),
		DnsDomainName:   utf16le.DecodeToString(s.infoMap[MsvAvDnsDomainName]),
		DnsTreeName:     utf16le.DecodeToString(s.infoMap[MsvAvDnsTreeName]),
	}
}

func (s *Session) Overhead() int { return 16 }

func (s *Session) Sum(plaintext []byte, seqNum uint32) ([]byte, uint32) {
	if s.negotiateFlags&NTLMSSP_NEGOTIATE_SIGN == 0 {
		return nil, 0
	}
	if s.isClientSide {
		return mac(nil, s.negotiateFlags, s.clientHandle, s.clientSigningKey, seqNum, plaintext)
	}
	return mac(nil, s.negotiateFlags, s.serverHandle, s.serverSigningKey, seqNum, plaintext)
}

func (s *Session) CheckSum(sum, plaintext []byte, seqNum uint32) (bool, uint32) {
	if s.negotiateFlags&NTLMSSP_NEGOTIATE_SIGN == 0 {
		if sum == nil {
			return true, 0
		}
		return false, 0
	}
	if s.isClientSide {
		ret, next := mac(nil, s.negotiateFlags, s.serverHandle, s.serverSigningKey, seqNum, plaintext)
		if !bytes.Equal(sum, ret) {
			return false, 0
		}
		return true, next
	}
	ret, next := mac(nil, s.negotiateFlags, s.clientHandle, s.clientSigningKey, seqNum, plaintext)
	if !bytes.Equal(sum, ret) {
		return false, 0
	}
	return true, next
}

func (s *Session) Seal(dst, plaintext []byte, seqNum uint32) ([]byte, uint32) {
	ret := make([]byte, len(plaintext)+16)
	ciphertext := ret
	switch {
	case s.negotiateFlags&NTLMSSP_NEGOTIATE_SEAL != 0:
		s.clientHandle.XORKeyStream(ciphertext[16:], plaintext)
		if s.isClientSide {
			_, seqNum = mac(ciphertext[:0], s.negotiateFlags, s.clientHandle, s.clientSigningKey, seqNum, plaintext)
		} else {
			_, seqNum = mac(ciphertext[:0], s.negotiateFlags, s.serverHandle, s.serverSigningKey, seqNum, plaintext)
		}
	case s.negotiateFlags&NTLMSSP_NEGOTIATE_SIGN != 0:
		copy(ciphertext[16:], plaintext)
		if s.isClientSide {
			_, seqNum = mac(ciphertext[:0], s.negotiateFlags, s.clientHandle, s.clientSigningKey, seqNum, plaintext)
		} else {
			_, seqNum = mac(ciphertext[:0], s.negotiateFlags, s.serverHandle, s.serverSigningKey, seqNum, plaintext)
		}
	}
	return ret, seqNum
}

func (s *Session) Unseal(dst, ciphertext []byte, seqNum uint32) ([]byte, uint32, error) {
	ret := make([]byte, len(ciphertext)-16)
	plaintext := ret
	switch {
	case s.negotiateFlags&NTLMSSP_NEGOTIATE_SEAL != 0:
		s.serverHandle.XORKeyStream(plaintext, ciphertext[16:])
		var sum []byte
		if s.isClientSide {
			sum, seqNum = mac(nil, s.negotiateFlags, s.serverHandle, s.serverSigningKey, seqNum, plaintext)
		} else {
			sum, seqNum = mac(nil, s.negotiateFlags, s.clientHandle, s.clientSigningKey, seqNum, plaintext)
		}
		if !bytes.Equal(ciphertext[:16], sum) {
			return nil, 0, errors.New("signature mismatch")
		}
	case s.negotiateFlags&NTLMSSP_NEGOTIATE_SIGN != 0:
		copy(plaintext, ciphertext[16:])
		var sum []byte
		if s.isClientSide {
			sum, seqNum = mac(nil, s.negotiateFlags, s.serverHandle, s.serverSigningKey, seqNum, plaintext)
		} else {
			sum, seqNum = mac(nil, s.negotiateFlags, s.clientHandle, s.clientSigningKey, seqNum, plaintext)
		}
		if !bytes.Equal(ciphertext[:16], sum) {
			return nil, 0, errors.New("signature mismatch")
		}
	default:
		copy(plaintext, ciphertext[16:])
		for _, s := range ciphertext[:16] {
			if s != 0x0 {
				return nil, 0, errors.New("signature mismatch")
			}
		}
	}
	return ret, seqNum, nil
}
