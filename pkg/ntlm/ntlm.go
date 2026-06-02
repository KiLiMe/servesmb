package ntlm

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"hash"
	"hash/crc32"

	"golang.org/x/crypto/md4"
)

var zero [16]byte

var version = []byte{
	0: WINDOWS_MAJOR_VERSION_6,
	1: WINDOWS_MINOR_VERSION_1,
	7: NTLMSSP_REVISION_W2K3,
}

// defaultFlags is the mask of client-offered NTLMSSP flags the server is
// willing to echo back in the CHALLENGE. NTLMSSP_NEGOTIATE_SEAL must be
// included: clients that request sealing (e.g. Samba with SMB encryption
// required) treat a missing SEAL bit in the challenge as a downgrade attack
// (SEC_E_DOWNGRADE_DETECTED, 0x80090302) and abort the session setup.
const defaultFlags = NTLMSSP_NEGOTIATE_56 | NTLMSSP_NEGOTIATE_KEY_EXCH | NTLMSSP_NEGOTIATE_128 | NTLMSSP_NEGOTIATE_TARGET_INFO | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY | NTLMSSP_NEGOTIATE_ALWAYS_SIGN | NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_SIGN | NTLMSSP_NEGOTIATE_SEAL | NTLMSSP_REQUEST_TARGET | NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_NEGOTIATE_VERSION

var le = binary.LittleEndian

const (
	NtLmNegotiate    = 0x00000001
	NtLmChallenge    = 0x00000002
	NtLmAuthenticate = 0x00000003
)

const (
	NTLMSSP_NEGOTIATE_UNICODE = 1 << iota
	NTLM_NEGOTIATE_OEM
	NTLMSSP_REQUEST_TARGET
	_
	NTLMSSP_NEGOTIATE_SIGN
	NTLMSSP_NEGOTIATE_SEAL
	NTLMSSP_NEGOTIATE_DATAGRAM
	NTLMSSP_NEGOTIATE_LM_KEY
	_
	NTLMSSP_NEGOTIATE_NTLM
	_
	NTLMSSP_ANONYMOUS
	NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED
	NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED
	_
	NTLMSSP_NEGOTIATE_ALWAYS_SIGN
	NTLMSSP_TARGET_TYPE_DOMAIN
	NTLMSSP_TARGET_TYPE_SERVER
	_
	NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
	NTLMSSP_NEGOTIATE_IDENTIFY
	_
	NTLMSSP_REQUEST_NON_NT_SESSION_KEY
	NTLMSSP_NEGOTIATE_TARGET_INFO
	_
	NTLMSSP_NEGOTIATE_VERSION
	_
	_
	_
	NTLMSSP_NEGOTIATE_128
	NTLMSSP_NEGOTIATE_KEY_EXCH
	NTLMSSP_NEGOTIATE_56
)

const (
	MsvAvEOL = iota
	MsvAvNbComputerName
	MsvAvNbDomainName
	MsvAvDnsComputerName
	MsvAvDnsDomainName
	MsvAvDnsTreeName
	MsvAvFlags
	MsvAvTimestamp
	MsvAvSingleHost
	MsvAvTargetName
	MsvAvChannelBindings
)

type addr struct {
	typ uint32
	val []byte
}

// channelBindings represents gss_channel_bindings_struct
type channelBindings struct {
	InitiatorAddress addr
	AcceptorAddress  addr
	AppData          []byte
}

var signature = []byte("NTLMSSP\x00")

//      Version
// 0-1: ProductMajorVersion
// 1-2: ProductMinorVersion
// 2-4: ProductBuild
// 4-7: Reserved
// 7-8: NTLMRevisionCurrent

const (
	WINDOWS_MAJOR_VERSION_5  = 0x05
	WINDOWS_MAJOR_VERSION_6  = 0x06
	WINDOWS_MAJOR_VERSION_10 = 0x0a
)

const (
	WINDOWS_MINOR_VERSION_0 = 0x00
	WINDOWS_MINOR_VERSION_1 = 0x01
	WINDOWS_MINOR_VERSION_2 = 0x02
	WINDOWS_MINOR_VERSION_3 = 0x03
)

const (
	NTLMSSP_REVISION_W2K3 = 0x0f
)

func ntowfv2(USER, password, domain []byte) []byte {
	h := md4.New()
	h.Write(password)
	hash := h.Sum(nil)
	return ntowfv2Hash(USER, hash, domain)
}

func ntowfv2Hash(USER, hash, domain []byte) []byte {
	hm := hmac.New(md5.New, hash)
	hm.Write(USER)
	hm.Write(domain)
	return hm.Sum(nil)
}

func encodeNtlmv2Response(dst []byte, h hash.Hash, serverChallenge, clientChallenge, timeStamp []byte, targetInfo encoder) {
	//        NTLMv2Response
	//  0-16: Response
	//   16-: NTLMv2ClientChallenge

	ntlmv2ClientChallenge := dst[16:]

	//        NTLMv2ClientChallenge
	//   0-1: RespType
	//   1-2: HiRespType
	//   2-4: _
	//   4-8: _
	//  8-16: TimeStamp
	// 16-24: ChallengeFromClient
	// 24-28: _
	//   28-: AvPairs

	ntlmv2ClientChallenge[0] = 1
	ntlmv2ClientChallenge[1] = 1
	copy(ntlmv2ClientChallenge[8:16], timeStamp)
	copy(ntlmv2ClientChallenge[16:24], clientChallenge)
	targetInfo.encode(ntlmv2ClientChallenge[28:])

	h.Write(serverChallenge)
	h.Write(ntlmv2ClientChallenge)
	h.Sum(dst[:0]) // ntChallengeResponse.Response
}

type encoder interface {
	size() int
	encode(bs []byte)
}

type bytesEncoder []byte

func (b bytesEncoder) size() int {
	return len(b)
}

func (b bytesEncoder) encode(bs []byte) {
	copy(bs, b)
}

type targetInfoEncoder struct {
	Info    []byte
	SPN     []byte
	InfoMap map[uint16][]byte
}

func newTargetInfoEncoder(info, spn []byte) *targetInfoEncoder {
	infoMap, ok := parseAvPairs(info)
	if !ok {
		return nil
	}
	return &targetInfoEncoder{
		Info:    info,
		SPN:     spn,
		InfoMap: infoMap,
	}
}

func (i *targetInfoEncoder) size() int {
	size := len(i.Info)
	if _, ok := i.InfoMap[MsvAvFlags]; !ok {
		size += 8
	}
	size += 20
	if len(i.SPN) != 0 {
		size += 4 + len(i.SPN)
	}
	return size
}

func (i *targetInfoEncoder) encode(bs []byte) {
	var off int
	copy(bs[off:], i.Info)
	off += len(i.Info)
	if _, ok := i.InfoMap[MsvAvFlags]; !ok {
		le.PutUint16(bs[off:off+2], MsvAvFlags)
		le.PutUint16(bs[off+2:off+4], 4)
		le.PutUint32(bs[off+4:off+8], 2)
		off += 8
	}
	if len(i.SPN) != 0 {
		le.PutUint16(bs[off:off+2], MsvAvTargetName)
		le.PutUint16(bs[off+2:off+4], uint16(len(i.SPN)))
		copy(bs[off+4:off+4+len(i.SPN)], i.SPN)
		off += 4 + len(i.SPN)
	}
	le.PutUint32(bs[off:off+4], 0)
}

// signKey derives the NTLMSSP signing key per MS-NLMP 3.4.5.2: with Extended
// Session Security it is MD5(ExportedSessionKey || magic-constant || 0x00),
// directional by mode. (The previous implementation used HMAC_MD5 with a short
// constant, which does not match Windows/Samba and broke the mechListMIC.)
func signKey(flags uint32, key []byte, isClient bool) []byte {
	if flags&NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY == 0 {
		return key
	}
	h := md5.New()
	h.Write(key)
	if isClient {
		h.Write([]byte("session key to client-to-server signing key magic constant\x00"))
	} else {
		h.Write([]byte("session key to server-to-client signing key magic constant\x00"))
	}
	return h.Sum(nil)
}

// sealKey derives the NTLMSSP sealing key per MS-NLMP 3.4.5.3: with Extended
// Session Security it is MD5(KeyMaterial || magic-constant || 0x00) where
// KeyMaterial is the session key truncated to the negotiated key strength.
func sealKey(flags uint32, key []byte, isClient bool) []byte {
	if flags&NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY != 0 {
		base := key
		if flags&NTLMSSP_NEGOTIATE_128 != 0 {
			base = key[:16]
		} else if flags&NTLMSSP_NEGOTIATE_56 != 0 {
			base = key[:7]
		} else {
			base = key[:5]
		}
		h := md5.New()
		h.Write(base)
		if isClient {
			h.Write([]byte("session key to client-to-server sealing key magic constant\x00"))
		} else {
			h.Write([]byte("session key to server-to-client sealing key magic constant\x00"))
		}
		return h.Sum(nil)
	}
	// Legacy (non-extended) sealing key; unused by modern SMB clients.
	if flags&NTLMSSP_NEGOTIATE_128 != 0 {
		return key
	}
	if flags&NTLMSSP_NEGOTIATE_56 != 0 {
		return key[:7]
	}
	return key[:5]
}

func mac(dst []byte, flags uint32, handle *rc4.Cipher, signingKey []byte, seqNum uint32, plaintext []byte) ([]byte, uint32) {
	sig := dst
	if l := len(sig); l < 16 {
		sig = make([]byte, 16)
	} else {
		sig = sig[:16]
	}

	sum := crc32.Update(0, crc32.IEEETable, plaintext)

	ms := make([]byte, 16)
	le.PutUint32(ms, sum)
	le.PutUint32(ms[4:8], seqNum)

	seqNum++

	if flags&NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY != 0 {
		h := hmac.New(md5.New, signingKey)
		h.Write(ms)
		ms = h.Sum(nil)
	}

	handle.XORKeyStream(sig[8:], ms)

	sig[0] = 'N'
	sig[1] = 'T'
	sig[2] = 'M'
	sig[3] = 'S'
	sig[4] = 1
	sig[5] = 0
	sig[6] = 0
	sig[7] = 0
	return sig, seqNum
}

// computeMIC implements the NTLMSSP MAC (MS-NLMP 3.4.4) and is used to produce
// or verify a SPNEGO mechListMIC. Unlike the legacy mac() above it follows the
// specification exactly: with Extended Session Security the checksum is the
// first 8 bytes of HMAC_MD5(SigningKey, ConcatenationOf(SeqNum, Message)),
// RC4-encrypted with a freshly keyed seal cipher when key exchange was
// negotiated. A fresh RC4 cipher is created on every call so the result is
// independent of any prior sealing state — the mechListMIC is the only
// NTLM-sealed message exchanged during an SMB SPNEGO handshake.
//
// The 16-byte signature layout (MS-NLMP 2.2.2.9) is:
//
//	Version(4) || Checksum(8) || SeqNum(4)   (Extended Session Security)
//	Version(4) || RandomPad(4) || Checksum(4) || SeqNum(4)   (legacy)
func computeMIC(flags uint32, sealKeyBytes, signingKey []byte, seqNum uint32, message []byte) []byte {
	sig := make([]byte, 16)
	le.PutUint32(sig[0:4], 1) // Version = 0x00000001
	le.PutUint32(sig[12:16], seqNum)
	if flags&NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY != 0 {
		var seqBuf [4]byte
		le.PutUint32(seqBuf[:], seqNum)
		h := hmac.New(md5.New, signingKey)
		h.Write(seqBuf[:])
		h.Write(message)
		checksum := h.Sum(nil)[:8]
		if flags&NTLMSSP_NEGOTIATE_KEY_EXCH != 0 && len(sealKeyBytes) > 0 {
			if c, err := rc4.NewCipher(sealKeyBytes); err == nil {
				c.XORKeyStream(checksum, checksum)
			}
		}
		copy(sig[4:12], checksum)
	} else {
		// Legacy signature: RandomPad(0) || CRC32 || SeqNum. Modern SMB clients
		// always negotiate Extended Session Security, so this path is unused in
		// practice and left without sealing for simplicity.
		le.PutUint32(sig[8:12], crc32.ChecksumIEEE(message))
	}
	return sig
}
