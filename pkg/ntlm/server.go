package ntlm

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"

	"time"

	"github.com/3xport/servesmb/pkg/utf16le"
)

// NTLM v2 server
type Server struct {
	targetName string
	nbName     string
	nbDomain   string
	dnsName    string
	dnsDomain  string
	accounts   map[string]string // User: Password
	hashes     map[string][]byte // User: NTHash
	allowGuest bool

	nmsg    []byte
	cmsg    []byte
	session *Session

	staticChallenge []byte
	logHash         bool
	enableMIC       bool // Enable NTLM MIC request (default false)
}

func NewServer(targetName, nbName, nbDomain, dnsName, dnsDomain string) *Server {
	if nbName == "" {
		nbName = targetName
	}
	if dnsName == "" {
		dnsName = targetName
	}
	return &Server{targetName: targetName, nbName: nbName, nbDomain: nbDomain, dnsName: dnsName, dnsDomain: dnsDomain, accounts: make(map[string]string), hashes: make(map[string][]byte)}
}

func (s *Server) AddAccount(user, password string) { s.accounts[user] = password }

func (s *Server) AddAccountWithHash(user string, hash []byte) { s.hashes[user] = hash }

func (s *Server) AllowGuest() { s.allowGuest = true }

func (s *Server) SetStaticChallenge(challenge []byte) {
	if len(challenge) == 8 {
		s.staticChallenge = challenge
	}
}

func (s *Server) SetLogHash(enable bool) {
	s.logHash = enable
}

func (s *Server) SetEnableMIC(enable bool) {
	s.enableMIC = enable
}

func (s *Server) Challenge(nmsg []byte) (cmsg []byte, err error) {
	s.nmsg = nmsg
	if len(nmsg) < 32 {
		return nil, errors.New("message length is too short")
	}
	if !bytes.Equal(nmsg[:8], signature) {
		return nil, errors.New("invalid signature")
	}
	if le.Uint32(nmsg[8:12]) != NtLmNegotiate {
		return nil, errors.New("invalid message type")
	}
	// Base on client flags but ensure NTLMv2-required bits are present
	flags := le.Uint32(nmsg[12:16]) & defaultFlags
	flags |= NTLMSSP_REQUEST_TARGET | NTLMSSP_NEGOTIATE_TARGET_INFO | NTLMSSP_NEGOTIATE_VERSION | NTLMSSP_TARGET_TYPE_SERVER

	off := 48
	if flags&NTLMSSP_NEGOTIATE_VERSION != 0 {
		off += 8
	}

	targetName := utf16le.EncodeStringToBytes(s.targetName)
	// Build TargetInfo AV pairs
	av := buildTargetInfo(s)
	cmsg = make([]byte, off+len(targetName)+len(av))
	copy(cmsg[:8], signature)
	le.PutUint32(cmsg[8:12], NtLmChallenge)
	le.PutUint32(cmsg[20:24], flags)

	if targetName != nil { // Always include TargetName for NTLMv2
		l := copy(cmsg[off:], targetName)
		le.PutUint16(cmsg[12:14], uint16(l))
		le.PutUint16(cmsg[14:16], uint16(l))
		le.PutUint32(cmsg[16:20], uint32(off))
		off += l
	}
	// Always include TargetInfo AV pairs for NTLMv2
	l := copy(cmsg[off:], av)
	le.PutUint16(cmsg[40:42], uint16(l))
	le.PutUint16(cmsg[42:44], uint16(l))
	le.PutUint32(cmsg[44:48], uint32(off))
	le.PutUint32(cmsg[44:48], uint32(off))
	off += l

	if s.staticChallenge != nil {
		copy(cmsg[24:32], s.staticChallenge)
	} else {
		_, err = rand.Read(cmsg[24:32])
		if err != nil {
			return nil, err
		}
	}

	if flags&NTLMSSP_NEGOTIATE_VERSION != 0 {
		copy(cmsg[48:56], version)
	}
	s.cmsg = cmsg
	return cmsg, nil
}

func (s *Server) Authenticate(amsg []byte) (err error) {
	if len(amsg) < 64 {
		return errors.New("message length is too short")
	}
	if !bytes.Equal(amsg[:8], signature) {
		return errors.New("invalid signature")
	}
	if le.Uint32(amsg[8:12]) != NtLmAuthenticate {
		return errors.New("invalid message type")
	}
	flags := le.Uint32(amsg[60:64])

	ntRespLen := le.Uint16(amsg[20:22])
	ntRespMax := le.Uint16(amsg[22:24])
	if ntRespMax < ntRespLen {
		return errors.New("invalid LM challenge format")
	}
	ntRespOff := le.Uint32(amsg[24:28])
	if len(amsg) < int(ntRespOff+uint32(ntRespLen)) {
		return errors.New("invalid LM challenge format")
	}
	ntResp := amsg[ntRespOff : ntRespOff+uint32(ntRespLen)]

	domLen := le.Uint16(amsg[28:30])
	domMax := le.Uint16(amsg[30:32])
	if domMax < domLen {
		return errors.New("invalid domain name format")
	}
	domOff := le.Uint32(amsg[32:36])
	if len(amsg) < int(domOff+uint32(domLen)) {
		return errors.New("invalid domain name format")
	}
	domainName := amsg[domOff : domOff+uint32(domLen)]

	userLen := le.Uint16(amsg[36:38])
	userMax := le.Uint16(amsg[38:40])
	if userMax < userLen {
		return errors.New("invalid user name format")
	}
	userOff := le.Uint32(amsg[40:44])
	if len(amsg) < int(userOff+uint32(userLen)) {
		return errors.New("invalid user name format")
	}
	userName := amsg[userOff : userOff+uint32(userLen)]

	if s.logHash {
		// Log the NTLMv2 response details before verification/decoding
		// Re-extract necessary fields explicitly for logging context if needed,
		// or just log what we have.
		// Note: user/domain might be unicode here, need decoding for log.
		uName := utf16le.DecodeToString(userName)
		dName := utf16le.DecodeToString(domainName)

		ntRespExtract := []byte{}
		if len(amsg) >= int(ntRespOff+uint32(ntRespLen)) {
			ntRespExtract = amsg[ntRespOff : ntRespOff+uint32(ntRespLen)]
		}

		// Server Challenge is in s.cmsg[24:32]
		srvChall := []byte{}
		if len(s.cmsg) >= 32 {
			srvChall = s.cmsg[24:32]
		}

		fmt.Printf("\n[+] NETNTLMv2 Hash Components:\n")
		fmt.Printf("User: %s\n", uName)
		fmt.Printf("Domain: %s\n", dName)
		fmt.Printf("ServerChallenge: %x\n", srvChall)
		fmt.Printf("NTResp: %x\n", ntRespExtract)

		if len(ntRespExtract) >= 16 {
			hmac := ntRespExtract[:16]
			blob := ntRespExtract[16:]
			fmt.Printf("Hashcat Format:\n%s::%s:%x:%x:%x\n\n",
				uName, dName, srvChall, hmac, blob)
		}
	}

	encKeyLen := le.Uint16(amsg[52:54])
	encKeyMax := le.Uint16(amsg[54:56])
	if encKeyMax < encKeyLen {
		return errors.New("invalid user name format")
	}
	encKeyOff := le.Uint32(amsg[56:60])
	if len(amsg) < int(encKeyOff+uint32(encKeyLen)) {
		return errors.New("invalid user name format")
	}
	encRandSessionKey := amsg[encKeyOff : encKeyOff+uint32(encKeyLen)]

	// Anonymous/null or guest session handling
	decodedUser := utf16le.DecodeToString(userName)
	if s.allowGuest {
		// Accept explicit guest username or empty username as guest, regardless of NT response
		if decodedUser == "" || strings.EqualFold(decodedUser, "guest") {
			session := new(Session)
			session.isClientSide = false
			session.user = decodedUser
			session.guest = true
			session.negotiateFlags = flags
			if len(ntResp) >= 16 {
				// The client sent a full NTLMv2 response. Derive the same
				// session key it did (using the guest account password, which
				// defaults to empty) so that signing, SMB3 encryption and the
				// SPNEGO mechListMIC work for guest sessions instead of being
				// pinned to an all-zero key the client never agreed to.
				guestPw := ""
				if pw, ok := s.accounts[decodedUser]; ok {
					guestPw = pw
				} else if pw, ok := s.accounts["guest"]; ok {
					guestPw = pw
				}
				USER := utf16le.EncodeStringToBytes(strings.ToUpper(decodedUser))
				v2Hash := ntowfv2(USER, utf16le.EncodeStringToBytes(guestPw), domainName)
				deriveSessionKeys(session, flags, v2Hash, ntResp[:16], encRandSessionKey)
			} else {
				// True anonymous/null session: no key material.
				session.exportedSessionKey = make([]byte, 16)
			}
			s.session = session
			return nil
		}
	} else {
		// Strict anonymous: both fields must be empty
		if len(userName) == 0 && len(ntResp) == 0 {
			return errors.New("guest access not allowed")
		}
	}

	if len(userName) != 0 || len(ntResp) != 0 {
		user := decodedUser
		// Check both accounts (password) and hashes
		_, hasPassword := s.accounts[user]
		_, hasHash := s.hashes[user]

		if !hasPassword && !hasHash && !s.allowGuest {
			return errors.New("no such user " + user)
		}
		if len(ntResp) < 16 {
			// Treat as guest if allowed and mapped
			if s.allowGuest {
				log.Printf("[DEBUG][NTLM] Short NT response (len=%d) for user=%q; mapping to guest", len(ntResp), user)
				session := new(Session)
				session.isClientSide = false
				session.user = user
				session.guest = true
				session.negotiateFlags = flags
				session.exportedSessionKey = make([]byte, 16)
				s.session = session
				return nil
			}
			return errors.New("invalid NT response length")
		}
		ntlmv2ClientChallenge := ntResp[16:]
		USER := utf16le.EncodeStringToBytes(strings.ToUpper(user))

		// Derive V2 Hash
		var v2Hash []byte
		if hasHash {
			v2Hash = ntowfv2Hash(USER, s.hashes[user], domainName)
		} else if hasPassword {
			password := utf16le.EncodeStringToBytes(s.accounts[user])
			v2Hash = ntowfv2(USER, password, domainName)
		} else {
			// Guest allowed but no user found? This block is protected by check above, but for safety:
			// Should act as guest or fail? If guest allowed, we might have returned earlier?
			// But if specific user was requested and not found, we return error unless mapped to guest?
			// We already returned error if not found and not guest.
			// If we are here, we might be guest?
			// Logic above: `if !hasPassword && !hasHash && !s.allowGuest { return error }`
			// If allowGuest is true but user not found, we proceed here?
			// If user not found, we can't verify password. We should probably fail or map to Guest session WITHOUT verifying password?
			// Guest usually means: ignore password.
			// The original logic: `if _, ok := s.accounts[user]; !ok && !s.allowGuest { return error }`
			// If not found and allowGuest=true, it proceeds to verify password using... key lookup failure?
			// Actually `s.accounts[user]` would return empty string.
			// NTLM for guest shouldn't verify password?
			// If user="Guest", we returned earlier.
			// If user="bob" (not found) and allowGuest=true -> we try verify with empty password?
			// Let's preserve strictness: if we have creds, verify them.
			if s.allowGuest {
				// Guest fallback logic if credentials fail?
				// Or treat unknown user as Guest immediately?
				// Original logic crashed/failed on lookup? `s.accounts[user]`
			}
			password := utf16le.EncodeStringToBytes("")
			v2Hash = ntowfv2(USER, password, domainName)
		}

		// NTLMv2 verification per MS-NLMP 3.3.2:
		// NTProofStr = HMAC_MD5(ResponseKeyNT, ServerChallenge || temp)
		// where temp = ntResp[16:] (the raw NTLMv2ClientChallenge blob as sent by client)
		// Compare NTProofStr with ntResp[0:16]
		h := hmac.New(md5.New, v2Hash)
		serverChallenge := s.cmsg[24:32]
		h.Write(serverChallenge)
		h.Write(ntlmv2ClientChallenge) // raw client blob as-is
		expectedProof := h.Sum(nil)
		if !hmac.Equal(ntResp[:16], expectedProof) {
			return errors.New("login failure")
		}
		session := new(Session)
		session.isClientSide = false
		session.user = user
		session.negotiateFlags = flags
		// SessionBaseKey = HMAC_MD5(ResponseKeyNT, NTProofStr); from it derive
		// the exported session key plus the signing/sealing keys. These back
		// SMB2/3 signing and encryption as well as the SPNEGO mechListMIC.
		deriveSessionKeys(session, flags, v2Hash, ntResp[:16], encRandSessionKey)
		s.session = session
		return nil
	}
	return errors.New("credential is empty")
}

// deriveSessionKeys computes the NTLMv2 ExportedSessionKey and the derived
// signing/sealing keys (MS-NLMP 3.4.5.x) for a server-side session and stores
// them on session. ntProofStr is the 16-byte NTProofStr from the client's
// AUTHENTICATE response, v2Hash the ResponseKeyNT, and encRandSessionKey the
// client's EncryptedRandomSessionKey (present only with key exchange).
func deriveSessionKeys(session *Session, flags uint32, v2Hash, ntProofStr, encRandSessionKey []byte) {
	hm := hmac.New(md5.New, v2Hash)
	hm.Write(ntProofStr)
	keyExchangeKey := hm.Sum(nil) // SessionBaseKey == KeyExchangeKey for NTLMv2
	if flags&NTLMSSP_NEGOTIATE_KEY_EXCH != 0 && len(encRandSessionKey) == 16 {
		out := make([]byte, 16)
		if cipher, err := rc4.NewCipher(keyExchangeKey); err == nil {
			cipher.XORKeyStream(out, encRandSessionKey)
			session.exportedSessionKey = out
		} else {
			session.exportedSessionKey = keyExchangeKey
		}
	} else {
		session.exportedSessionKey = keyExchangeKey
	}
	session.clientSigningKey = signKey(flags, session.exportedSessionKey, true)
	session.serverSigningKey = signKey(flags, session.exportedSessionKey, false)
	session.clientSealKey = sealKey(flags, session.exportedSessionKey, true)
	session.serverSealKey = sealKey(flags, session.exportedSessionKey, false)
	session.clientHandle, _ = rc4.NewCipher(session.clientSealKey)
	session.serverHandle, _ = rc4.NewCipher(session.serverSealKey)
}

func (s *Server) Session() *Session { return s.session }

// buildTargetInfo builds AV pairs per MS-NLMP with basic names and timestamp.
func buildTargetInfo(s *Server) []byte {
	// AV pairs are UTF-16LE
	var buf bytes.Buffer
	put := func(id uint16, val []byte) {
		if len(val) == 0 {
			return
		}
		tmp := make([]byte, 4)
		le.PutUint16(tmp[0:2], id)
		le.PutUint16(tmp[2:4], uint16(len(val)))
		buf.Write(tmp)
		buf.Write(val)
	}
	if s.nbDomain != "" {
		put(MsvAvNbDomainName, utf16le.EncodeStringToBytes(s.nbDomain))
	}
	if s.nbName != "" {
		put(MsvAvNbComputerName, utf16le.EncodeStringToBytes(s.nbName))
	}
	if s.dnsDomain != "" && !isNetBIOSOnlyName(s.dnsDomain) {
		put(MsvAvDnsDomainName, utf16le.EncodeStringToBytes(s.dnsDomain))
	}
	if s.dnsName != "" && net.ParseIP(s.dnsName) == nil {
		put(MsvAvDnsComputerName, utf16le.EncodeStringToBytes(s.dnsName))
	}
	// Only include AvFlags when we are explicitly requesting MIC.
	if s.enableMIC {
		fl := make([]byte, 4)
		le.PutUint32(fl, 0x02)
		put(MsvAvFlags, fl)
	}
	// Timestamp
	const ftEpoch = 116444736000000000
	ts := uint64(time.Now().UnixNano()/100) + ftEpoch
	tbuf := make([]byte, 8)
	le.PutUint64(tbuf, ts)
	put(MsvAvTimestamp, tbuf)
	// Only advertise an SPN when the target is DNS/IP-like. Bare NetBIOS names
	// are accepted by Windows without MsvAvTargetName and match Samba more closely.
	spn := ""
	if s.targetName != "" && !isNetBIOSOnlyName(s.targetName) {
		spn = "cifs/" + s.targetName
	}
	if spn != "" {
		put(MsvAvTargetName, utf16le.EncodeStringToBytes(spn))
	}
	// EOL
	eol := make([]byte, 4)
	// id=0, len=0 already zero
	buf.Write(eol)
	return buf.Bytes()
}

func isNetBIOSOnlyName(name string) bool {
	return name != "" && !strings.Contains(name, ".")
}
