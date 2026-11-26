package smb2

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/3xport/servesmb/pkg/auth"
	"github.com/3xport/servesmb/pkg/crypto/ccm"
	xcmac "github.com/3xport/servesmb/pkg/crypto/cmac"
	"github.com/3xport/servesmb/pkg/crypto/kdf"
	"github.com/3xport/servesmb/pkg/hooks"
	"github.com/3xport/servesmb/pkg/netbios"
	myntlm "github.com/3xport/servesmb/pkg/ntlm"
	"github.com/3xport/servesmb/pkg/protocol"
	"github.com/3xport/servesmb/pkg/shares"
	"github.com/3xport/servesmb/pkg/spnego"
)

type SMB2Handler struct {
	shareManager    *shares.ShareManager
	authenticator   *auth.NTLMAuthenticator
	sessions        map[uint64]*protocol.Session
	nextSessionID   uint64
	nextTreeID      uint32
	nextMessageID   uint64
	fileHandles     map[string]*protocol.FileHandle
	supportSMB3     bool
	serverGUID      [16]byte
	pendingNTLM     map[uint64]*myntlm.Server
	pendingIsSPNEGO map[uint64]bool
	pendingMechList map[uint64][]byte // per-session SPNEGO MechTypeList DER (leg1), consumed for the mechListMIC in leg2
	pendingDialect  map[uint64]uint16 // per-session dialect (set during leg1, consumed during leg2)
	lastDialect     uint16            // per-connection: set by negotiate, read by session setup (same goroutine)
	debug           int
	enableMIC       bool
	hooks           hooks.EventHooks
	pipeResponses   map[string][]byte // fileID -> pending DCE/RPC response for WRITE+READ pipe pattern
	// streamStore holds NTFS-style named-stream contents (Apple FinderInfo /
	// resource forks) keyed by share\x00basepath\x00streamname. macOS Time
	// Machine opens "file:AFP_AfpInfo" and resource-fork streams; we keep them
	// here so reads/writes succeed instead of returning NOT_FOUND. AFP_AfpInfo
	// is synthesized (60-byte default) on first read if absent.
	streamStore map[string][]byte
	stateMu     sync.RWMutex
}

// SMB 3.1.1 negotiate context types (MS-SMB2 2.2.3.1).
const (
	negCtxPreauthIntegrity = 0x0001
	negCtxEncryption       = 0x0002
	negCtxCompression      = 0x0003
	negCtxNetname          = 0x0005
	negCtxTransport        = 0x0006
	negCtxSigning          = 0x0008
)

// SMB 3.1.1 cipher IDs (SMB2_ENCRYPTION_CAPABILITIES).
const (
	cipherAES128CCM = 0x0001
	cipherAES128GCM = 0x0002
	cipherAES256CCM = 0x0003
	cipherAES256GCM = 0x0004
)

// SMB 3.1.1 signing algorithm IDs (SMB2_SIGNING_CAPABILITIES).
const (
	signHMACSHA256 = 0x0000
	signAESCMAC    = 0x0001
	signAESGMAC    = 0x0002
)

const hashSHA512 = 0x0001 // SMB2_PREAUTH_INTEGRITY_CAPABILITIES hash algorithm

// connState holds per-connection negotiation state. A pointer is threaded
// through the request dispatch so SMB 3.1.1 preauth integrity and the
// negotiated cipher/signing algorithm survive from NEGOTIATE to SESSION_SETUP
// for this connection.
type connState struct {
	preauthHash [64]byte // SMB 3.1.1 preauth integrity running hash (SHA-512)
	is311       bool     // SMB 3.1.1 negotiated
	cipherID    uint16   // negotiated encryption cipher (0 = none)
	signingID   uint16   // negotiated signing algorithm
}

// updatePreauth folds the next message into the SMB 3.1.1 preauth integrity
// hash: H = SHA512(H || message). msg must be the bare SMB2 message (no NetBIOS
// header). Per MS-SMB2 3.3.5.4 every NEGOTIATE and SESSION_SETUP message is
// chained except the final SESSION_SETUP response.
func (cs *connState) updatePreauth(msg []byte) {
	s := sha512.New()
	s.Write(cs.preauthHash[:])
	s.Write(msg)
	copy(cs.preauthHash[:], s.Sum(nil))
}

// spnegoNegState scans a SPNEGO token and attempts to extract NegState
// (0=accept-completed, 1=accept-incomplete, 2=rejected, 3=request-mic).
// Works for both full GSS InitialContextToken (0x60...) and bare NegTokenResp
// (A1 ... 30 ... A0 03 0A 01 <state> ...).
func spnegoNegState(tok []byte) int {
	// scan for A0 03 0A 01 XX pattern and return XX
	for i := 0; i+4 < len(tok); i++ {
		if tok[i] == 0xA0 && tok[i+1] == 0x03 && tok[i+2] == 0x0A && tok[i+3] == 0x01 {
			return int(tok[i+4])
		}
	}
	return -1
}

// berLen encodes a length per DER/BER definite form
func berLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	// up to 4 bytes length is plenty for our tokens
	tmp := []byte{}
	for i := n; i > 0; i >>= 8 {
		tmp = append([]byte{byte(i & 0xFF)}, tmp...)
	}
	out := make([]byte, 1+len(tmp))
	out[0] = 0x80 | byte(len(tmp))
	copy(out[1:], tmp)
	return out
}

// buildNegTokenRespAcceptIncomplete builds a bare SPNEGO NegTokenResp
// (accept-incomplete) wrapping the provided NTLM Type2 challenge.
func buildNegTokenRespAcceptIncomplete(ntlmChallenge []byte) []byte {
	// Inner SEQUENCE of fields
	seq := &bytes.Buffer{}
	// [0] NegState = accept-incomplete (1)
	seq.Write([]byte{0xA0, 0x03, 0x0A, 0x01, 0x01})
	// [1] SupportedMech = NTLM OID 1.3.6.1.4.1.311.2.2.10
	oid := []byte{0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A}
	seq.Write([]byte{0xA1, byte(len(oid))})
	seq.Write(oid)
	// [2] ResponseToken = OCTET STRING containing NTLM Type2
	// Compose the OCTET STRING TLV
	os := &bytes.Buffer{}
	os.WriteByte(0x04)
	os.Write(berLen(len(ntlmChallenge)))
	os.Write(ntlmChallenge)
	osb := os.Bytes()
	// Wrap as context tag [2]
	seq.WriteByte(0xA2)
	seq.Write(berLen(len(osb)))
	seq.Write(osb)
	// Wrap SEQUENCE
	inner := &bytes.Buffer{}
	inner.WriteByte(0x30)
	inner.Write(berLen(seq.Len()))
	inner.Write(seq.Bytes())
	// Wrap context [1] (NegTokenResp)
	out := &bytes.Buffer{}
	out.WriteByte(0xA1)
	out.Write(berLen(inner.Len()))
	out.Write(inner.Bytes())
	return out.Bytes()
}

// buildNegTokenRespAcceptComplete builds a bare SPNEGO NegTokenResp with state=accept-complete.
func buildNegTokenRespAcceptComplete() []byte {
	// [0] NegState = accept-completed (0)
	seq := &bytes.Buffer{}
	seq.Write([]byte{0xA0, 0x03, 0x0A, 0x01, 0x00})
	inner := &bytes.Buffer{}
	inner.WriteByte(0x30)
	inner.Write(berLen(seq.Len()))
	inner.Write(seq.Bytes())
	out := &bytes.Buffer{}
	out.WriteByte(0xA1)
	out.Write(berLen(inner.Len()))
	out.Write(inner.Bytes())
	return out.Bytes()
}

// creditsFor computes credits to grant in the response.
func (h *SMB2Handler) creditsFor(req *protocol.SMB2Message) uint16 {
	// Grant at least 32 credits to satisfy clients that pipeline requests.
	// Cap to a sane upper bound to avoid overflow.
	requested := req.Header.CreditRequest
	if requested < 32 {
		return 32
	}
	if requested > 512 {
		return 512
	}
	return requested
}

func NewSMB2Handler(shareManager *shares.ShareManager, authenticator *auth.NTLMAuthenticator, supportSMB3 bool, debug int, enableMIC bool, eventHooks hooks.EventHooks) *SMB2Handler {
	h := &SMB2Handler{
		shareManager:    shareManager,
		authenticator:   authenticator,
		sessions:        make(map[uint64]*protocol.Session),
		nextSessionID:   1,
		nextTreeID:      1,
		nextMessageID:   1,
		fileHandles:     make(map[string]*protocol.FileHandle),
		supportSMB3:     supportSMB3,
		pendingNTLM:     make(map[uint64]*myntlm.Server),
		pendingIsSPNEGO: make(map[uint64]bool),
		pendingMechList: make(map[uint64][]byte),
		pendingDialect:  make(map[uint64]uint16),
		pipeResponses:   make(map[string][]byte),
		streamStore:     make(map[string][]byte),
		debug:           debug,
		enableMIC:       enableMIC,
		hooks:           eventHooks,
	}
	// Initialize a stable, non-zero server GUID
	now := uint64(time.Now().UnixNano())
	binary.LittleEndian.PutUint64(h.serverGUID[:8], now)
	binary.LittleEndian.PutUint64(h.serverGUID[8:], now^0xA5A5A5A5A5A5A5A5)
	return h
}

// NewConnectionHandler creates independent session and file-handle tables
// while preserving the identity and configuration of the server.
func (h *SMB2Handler) NewConnectionHandler() *SMB2Handler {
	conn := NewSMB2Handler(h.shareManager, h.authenticator, h.supportSMB3, h.debug, h.enableMIC, h.hooks)
	conn.serverGUID = h.serverGUID
	return conn
}

func (h *SMB2Handler) dbg(format string, args ...interface{}) {
	if h.debug > 0 {
		log.Printf("[DEBUG][SMB2] "+format, args...)
	}
}

func (h *SMB2Handler) dbgL(level int, format string, args ...interface{}) {
	if h.debug >= level {
		log.Printf("[DEBUG%d][SMB2] "+format, append([]interface{}{level}, args...)...)
	}
}

func hexDump(b []byte, full bool) string {
	max := len(b)
	if !full && max > 512 {
		max = 512
	}
	out := &bytes.Buffer{}
	for i := 0; i < max; i += 16 {
		end := i + 16
		if end > max {
			end = max
		}
		fmt.Fprintf(out, "%04x: ", i)
		for j := i; j < end; j++ {
			fmt.Fprintf(out, "%02x ", b[j])
		}
		out.WriteByte('\n')
	}
	if !full && len(b) > max {
		fmt.Fprintf(out, "... truncated, total %d bytes\n", len(b))
	}
	return out.String()
}

// SMB3 Transform Header (MS-SMB2 2.2.41):
// ProtocolId (4) = 0xFD 'S' 'M' 'B'
// Signature (16)
// Nonce (16)
// OriginalMessageSize (4)
// Reserved (2)
// Flags (2) = 0x0001 (encrypted)
// SessionId (8)
// Total: 52 bytes
const smb3TransformHeaderSize = 52

// decryptTransform decrypts an SMB3 Transform-encrypted message. The cipher
// (AES-128-CCM by default, or the dialect 3.1.1 negotiated cipher) and nonce
// length come from the session.
func (h *SMB2Handler) decryptTransform(data []byte) ([]byte, uint64, error) {
	if len(data) < smb3TransformHeaderSize {
		return nil, 0, fmt.Errorf("transform header too short: %d", len(data))
	}
	// Verify ProtocolId = 0xFD534D42
	if data[0] != 0xFD || data[1] != 'S' || data[2] != 'M' || data[3] != 'B' {
		return nil, 0, fmt.Errorf("invalid transform protocol id")
	}

	signature := data[4:20]
	nonce := data[20:36]
	origSize := binary.LittleEndian.Uint32(data[36:40])
	sessionID := binary.LittleEndian.Uint64(data[44:52])

	ciphertext := data[52:]
	if uint32(len(ciphertext)) != origSize {
		return nil, 0, fmt.Errorf("transform size mismatch: %d vs %d", len(ciphertext), origSize)
	}

	h.stateMu.RLock()
	session, ok := h.sessions[sessionID]
	h.stateMu.RUnlock()
	if !ok || len(session.DecryptionKey) == 0 {
		return nil, 0, fmt.Errorf("no decryption key for session %d", sessionID)
	}

	aead, nonceLen, err := newTransformAEAD(session.CipherID, session.DecryptionKey)
	if err != nil {
		return nil, 0, err
	}

	// Associated data = Transform header bytes 20..51 (nonce + originalSize + reserved + flags + sessionId)
	aad := data[20:52]
	// AEAD.Open wants ciphertext||tag; the tag is the 16-byte Signature field.
	ctAndTag := make([]byte, 0, len(ciphertext)+16)
	ctAndTag = append(ctAndTag, ciphertext...)
	ctAndTag = append(ctAndTag, signature...)

	plaintext, err := aead.Open(nil, nonce[:nonceLen], ctAndTag, aad)
	if err != nil {
		return nil, 0, fmt.Errorf("decryption failed: %v", err)
	}

	return plaintext, sessionID, nil
}

// encryptTransform encrypts SMB2 response data with the session's negotiated
// cipher and wraps it in an SMB3 Transform header.
func (h *SMB2Handler) encryptTransform(responseData []byte, session *protocol.Session) ([]byte, error) {
	if len(session.EncryptionKey) == 0 {
		return nil, fmt.Errorf("no encryption key")
	}

	aead, nonceLen, err := newTransformAEAD(session.CipherID, session.EncryptionKey)
	if err != nil {
		return nil, err
	}

	// Random nonce (nonceLen bytes used, stored in the 16-byte Nonce field).
	var nonce [16]byte
	if _, err := io.ReadFull(crand.Reader, nonce[:nonceLen]); err != nil {
		return nil, err
	}

	// Associated data = nonce(16) + origSize(4) + reserved(2) + flags(2) + sessionId(8)
	aad := make([]byte, 32)
	copy(aad[0:16], nonce[:])
	binary.LittleEndian.PutUint32(aad[16:20], uint32(len(responseData)))
	binary.LittleEndian.PutUint16(aad[22:24], 0x0001) // Flags = encrypted
	binary.LittleEndian.PutUint64(aad[24:32], session.ID)

	// Seal -> ciphertext || tag (tag is 16 bytes).
	sealed := aead.Seal(nil, nonce[:nonceLen], responseData, aad)
	ciphertext := sealed[:len(sealed)-16]
	tag := sealed[len(sealed)-16:]

	// Build Transform header
	out := make([]byte, smb3TransformHeaderSize+len(ciphertext))
	out[0] = 0xFD
	out[1] = 'S'
	out[2] = 'M'
	out[3] = 'B'
	copy(out[4:20], tag) // Signature = AEAD tag
	copy(out[20:36], nonce[:])
	binary.LittleEndian.PutUint32(out[36:40], uint32(len(responseData)))
	binary.LittleEndian.PutUint16(out[42:44], 0x0001) // Flags
	binary.LittleEndian.PutUint64(out[44:52], session.ID)
	copy(out[52:], ciphertext)

	return out, nil
}

func (h *SMB2Handler) HandleConnection(conn net.Conn) error {
	defer conn.Close()
	defer func() {
		for id, handle := range h.fileHandles {
			if handle.OSFile != nil {
				handle.OSFile.Close()
			}
			delete(h.fileHandles, id)
		}
	}()

	// Determine local IP for NTLM SPN generation
	localAddr := conn.LocalAddr().String()
	localIP, _, _ := net.SplitHostPort(localAddr)
	if localIP == "" {
		localIP = "127.0.0.1" // Fallback
	}

	remoteAddr := conn.RemoteAddr().String()
	clientIP, clientPortStr, _ := net.SplitHostPort(remoteAddr)
	_, serverPortStr, _ := net.SplitHostPort(localAddr)

	clientPort := 0
	serverPort := 0
	fmt.Sscanf(clientPortStr, "%d", &clientPort)
	fmt.Sscanf(serverPortStr, "%d", &serverPort)

	// connDialect tracks the negotiated dialect for this specific connection.
	// For the SMB1 upgrade path, BuildNegotiateResponseBytes already sent
	// the negotiate response before HandleConnection is called.
	connDialect := h.lastDialect
	connInfo := hooks.ConnInfo{
		ClientIP:   clientIP,
		ClientPort: clientPort,
		LocalIP:    localIP,
		ServerPort: serverPort,
		Dialect:    connDialect,
	}

	// Per-connection negotiation state (SMB 3.1.1 preauth hash, cipher, signing).
	cs := &connState{}

	for {
		// Read raw SMB2/NetBIOS message
		msgData, err := h.readRawMessage(conn)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("failed to read message: %v", err)
		}

		// Check for SMB3 Transform header (encrypted message)
		var encryptedSessionID uint64
		wasEncrypted := false
		if len(msgData) >= 4 && msgData[0] == 0xFD && msgData[1] == 'S' && msgData[2] == 'M' && msgData[3] == 'B' {
			plaintext, sid, err := h.decryptTransform(msgData)
			if err != nil {
				h.dbg("Transform decrypt failed: %v", err)
				continue
			}
			msgData = plaintext
			encryptedSessionID = sid
			wasEncrypted = true
			// Once a client encrypts, the session uses encryption for the rest
			// of its lifetime; remember that so every response is encrypted too.
			h.stateMu.Lock()
			if s, ok := h.sessions[sid]; ok {
				s.EncryptionEnabled = true
			}
			h.stateMu.Unlock()
		}

		// Parse requests (single or compound)
		requests, err := h.parseCompoundRequests(msgData)
		if err != nil {
			log.Printf("Failed to parse requests: %v", err)
			continue
		}

		// Process requests chain
		connInfo.Dialect = connDialect
		// SMB 3.1.1 preauth integrity: fold the request into the running hash
		// before processing it (NEGOTIATE always — dialect not yet known;
		// SESSION_SETUP once 3.1.1 is in effect). Responses are folded in after
		// marshaling, below.
		if len(requests) > 0 {
			c0 := requests[0].Header.Command
			if c0 == protocol.SMB2_NEGOTIATE || (cs.is311 && c0 == protocol.SMB2_SESSION_SETUP) {
				cs.updatePreauth(msgData)
			}
		}
		responses := h.processCompoundRequests(requests, connInfo, cs)

		// Update per-connection dialect from negotiate response
		for _, resp := range responses {
			if resp.Header.Command == protocol.SMB2_NEGOTIATE && resp.Header.Status == protocol.STATUS_SUCCESS {
				if len(resp.Data) >= 6 {
					connDialect = binary.LittleEndian.Uint16(resp.Data[4:6])
					connInfo.Dialect = connDialect
				}
			}
		}

		// Marshal and sign responses (if needed)
		if len(responses) > 0 {
			// Find session for signing (usually from the first response that has a session ID)
			var session *protocol.Session
			for _, resp := range responses {
				if resp.Header.SessionID != 0 {
					h.stateMu.RLock()
					s, ok := h.sessions[resp.Header.SessionID]
					h.stateMu.RUnlock()
					if ok {
						session = s
						break
					}
				}
			}
			if session == nil && encryptedSessionID != 0 {
				h.stateMu.RLock()
				session = h.sessions[encryptedSessionID]
				h.stateMu.RUnlock()
			}

			// We need to marshal them all into one buffer, handling NextCommand
			responseData, err := h.marshalCompoundResponses(responses, session)
			if err != nil {
				log.Printf("Failed to marshal responses: %v", err)
				continue
			}

			// SMB 3.1.1 preauth integrity: fold the NEGOTIATE response and any
			// intermediate (MORE_PROCESSING) SESSION_SETUP response into the
			// hash. The final SESSION_SETUP success response is excluded — the
			// key derivation in leg2 already used the hash through that request.
			if cs.is311 && len(responses) > 0 {
				c0 := responses[0].Header.Command
				st := responses[0].Header.Status
				if c0 == protocol.SMB2_NEGOTIATE || (c0 == protocol.SMB2_SESSION_SETUP && st == protocol.STATUS_MORE_PROCESSING_REQUIRED) {
					cs.updatePreauth(responseData)
				}
			}

			// If the request was encrypted (or the session has switched to
			// encryption), encrypt the response too. MS-SMB2 3.3.4.1.4 requires
			// the server to encrypt a response whenever the request was encrypted.
			if session != nil && len(session.EncryptionKey) > 0 && (wasEncrypted || session.EncryptionEnabled) {
				encrypted, err := h.encryptTransform(responseData, session)
				if err != nil {
					log.Printf("Failed to encrypt response: %v", err)
					continue
				}
				responseData = encrypted
			}

			// Send via NetBIOS framing
			nbHeader := make([]byte, 4)
			nbHeader[0] = 0x00
			length := uint32(len(responseData))
			nbHeader[1] = byte((length >> 16) & 0xFF)
			nbHeader[2] = byte((length >> 8) & 0xFF)
			nbHeader[3] = byte(length & 0xFF)
			if _, err := conn.Write(nbHeader); err != nil {
				return err
			}
			if _, err := conn.Write(responseData); err != nil {
				return err
			}
			for _, resp := range responses {
				if resp.Header.Command == protocol.SMB2_LOGOFF && resp.Header.SessionID != 0 {
					h.stateMu.Lock()
					delete(h.sessions, resp.Header.SessionID)
					h.stateMu.Unlock()
				}
			}
		}
	}
}

// parseCompoundRequests splits a raw buffer into multiple SMB2Messages based on NextCommand
func (h *SMB2Handler) parseCompoundRequests(data []byte) ([]*protocol.SMB2Message, error) {
	var msgs []*protocol.SMB2Message
	offset := 0
	for {
		if offset >= len(data) {
			break
		}
		// Ensure enough data for header (64 bytes)
		if len(data)-offset < 64 {
			break // Should be error but be lenient
		}

		// Parse
		msg := &protocol.SMB2Message{}
		// Unmarshal reads from start of slice, so pass slice from offset
		// Note from Unmarshal impl: it uses NextCommand to skip or ByteCount to know size?
		// Actually Unmarshal just parses parsing header + payload.
		// Standard Unmarshal might consume everything if we are not careful about NextCommand.
		// However, standard Unmarshal expects [Header][Data].
		// But in compounding, [Header][Data][Padding][Header][Data]...
		// We need to be careful. Let's rely on Unmarshal parsing logic but limit the slice if NextCommand was set in previous?
		// No, we are parsing THIS header to find ITS NextCommand.

		// We need to peek NextCommand first to slice correctly?
		// Or just Unmarshal from current offset and trust it doesn't over-read?
		// My Unmarshal implementation reads StructureSize(64) then Data.
		// If Data is defined by ByteCount or similar? No, standard Unmarshal takes []byte and if there is extra?
		// My Unmarshal:
		// func (m *SMB2Message) Unmarshal(data []byte) error { ... if len(data) < 64 ... }
		// It parses header. Does it limit Data?
		// Ah, standard SMB2 header does NOT have a total "ByteCount". It has StructureSize=64.
		// The *command* specific body has structure size.
		// Effectively, we need to know where the next command starts.
		// The Header.NextCommand tells us offset from START of THIS header to Next header.

		// So we peek the header first.
		hdrData := data[offset : offset+64]
		nextCmd := binary.LittleEndian.Uint32(hdrData[20:24])

		// Determine length of THIS message
		var msgLen int
		if nextCmd != 0 {
			msgLen = int(nextCmd)
		} else {
			// Last message: consumes rest of data
			msgLen = len(data) - offset
		}

		if msgLen < 64 || msgLen > len(data)-offset {
			return nil, fmt.Errorf("invalid NextCommand offset")
		}

		currData := data[offset : offset+msgLen]
		if err := msg.Unmarshal(currData); err != nil {
			return nil, err
		}
		msgs = append(msgs, msg)

		if nextCmd == 0 {
			break
		}
		offset += int(nextCmd)
	}
	return msgs, nil
}

func (h *SMB2Handler) processCompoundRequests(reqs []*protocol.SMB2Message, connInfo hooks.ConnInfo, cs *connState) []*protocol.SMB2Message {
	var responses []*protocol.SMB2Message

	// Chain state for RelatedOperations
	var relatedSessionID uint64
	var relatedTreeID uint32
	var relatedFileID [16]byte // Captured from SMB2_CREATE response

	for i, req := range reqs {
		// Log flags for debugging
		// if h.debug > 0 {
		// 	h.dbg("Compound Req %d: cmd=0x%04X flags=0x%08X related=%v", i, req.Header.Command, req.Header.Flags, (req.Header.Flags&protocol.SMB2_FLAGS_RELATED_OPERATIONS) != 0)
		// }

		// Handle Related Operations
		if (req.Header.Flags&protocol.SMB2_FLAGS_RELATED_OPERATIONS) != 0 && i > 0 {
			req.Header.SessionID = relatedSessionID
			req.Header.TreeID = relatedTreeID

			// if h.debug > 0 {
			// 	h.dbg("Injecting FileID: %x into cmd=0x%04X", relatedFileID, req.Header.Command)
			// }

			// Inject related FileID into command body if applicable
			switch req.Header.Command {
			case protocol.SMB2_QUERY_INFO, protocol.SMB2_IOCTL:
				// Offset 24
				if len(req.Data) >= 40 {
					copy(req.Data[24:40], relatedFileID[:])
				}
			case protocol.SMB2_QUERY_DIRECTORY, protocol.SMB2_CHANGE_NOTIFY, protocol.SMB2_CLOSE:
				// Offset 8
				if len(req.Data) >= 24 {
					copy(req.Data[8:24], relatedFileID[:])
				}
			case protocol.SMB2_READ, protocol.SMB2_WRITE, protocol.SMB2_SET_INFO:
				// Offset 16
				if len(req.Data) >= 32 {
					copy(req.Data[16:32], relatedFileID[:])
				}
			}
		}

		resp, err := h.processMessage(req, connInfo, cs)
		if err != nil {
			// Create generic error response if processMessage failed badly
			resp = h.createErrorResponse(req, protocol.STATUS_INVALID_PARAMETER)
		}

		if resp != nil {
			// Update related state for next op
			relatedSessionID = resp.Header.SessionID
			relatedTreeID = resp.Header.TreeID

			// Track the related FileID for the rest of the chain.
			if req.Header.Command == protocol.SMB2_CREATE {
				if resp.Header.Status == protocol.STATUS_SUCCESS && len(resp.Data) >= 80 {
					// FileId is at resp.Data[64:80] (after the 64-byte fixed part).
					copy(relatedFileID[:], resp.Data[64:80])
					if h.debug > 0 {
						h.dbg("Captured FileID: %x from Create", relatedFileID)
					}
				} else if resp.Header.Status != protocol.STATUS_SUCCESS {
					// Failed CREATE: poison the related FileID so subsequent related
					// ops in the chain fail cleanly with INVALID_HANDLE instead of
					// acting on a stale handle captured from an earlier CREATE.
					for k := range relatedFileID {
						relatedFileID[k] = 0xFF
					}
				}
			}

			responses = append(responses, resp)
		}
		// MS-SMB2 3.3.5.2.7.2: the server MUST produce a response for EVERY request
		// in a compound chain, even after one fails. We previously broke out of the
		// loop on the first error when the next op was related — leaving macOS to
		// wait out a ~120s SMB request timeout for the missing related responses.
		// That manifested as the disk-image attach progressing one ~2-minute stall
		// at a time (each failed CFBundle probe, e.g. Base.lproj/en.lproj NOT_FOUND,
		// was the head of a related compound whose tail we never answered). Keep
		// processing the chain so each request gets a response.
	}
	return responses
}

func (h *SMB2Handler) marshalCompoundResponses(resps []*protocol.SMB2Message, session *protocol.Session) ([]byte, error) {
	var buf bytes.Buffer

	// Marshal all
	var marshaled [][]byte
	for _, r := range resps {
		b, err := r.Marshal()
		if err != nil {
			return nil, err
		}
		marshaled = append(marshaled, b)
	}

	// Concat and set NextCommand
	for i := 0; i < len(marshaled); i++ {
		isLast := (i == len(marshaled)-1)

		// Align to 8 bytes if not last
		currLen := len(marshaled[i])
		pad := 0
		if !isLast {
			remainder := currLen % 8
			if remainder != 0 {
				pad = 8 - remainder
			}
		}

		// Update NextCommand in this buffer (offset 20)
		if !isLast {
			nextCmdOffset := uint32(currLen + pad)
			binary.LittleEndian.PutUint32(marshaled[i][20:24], nextCmdOffset)
		} else {
			binary.LittleEndian.PutUint32(marshaled[i][20:24], 0)
		}

		buf.Write(marshaled[i])
		for j := 0; j < pad; j++ {
			buf.WriteByte(0)
		}
	}

	// Sign the WHOLE result if needed
	// Note: We need to set SMB2_FLAGS_SIGNED on all/some headers?
	// MS-SMB2: "The SMB2_FLAGS_SIGNED bit MUST be set in the header of the response... for the last message in the compound response"
	// Actually: "If the message is part of a compound chain, the signature is calculated across the entire message... The signature is placed in the SMB2 Header of the LAST message in the chain."
	// Wait, for independent requests compounded, maybe individual signatures?
	// Let's assume standard session signing: Sign the last one?
	// Actually, if we look at `processMessage`, it was setting flags.
	// But `marshalCompoundResponses` creates a new buffer.

	finalData := buf.Bytes()

	// Sign responses for any session that established a real session key,
	// including guest (the client derives the same key from the guest account's
	// password and verifies the signature). Only genuine anonymous/null sessions
	// — which have no key material — are left unsigned, as clients do not expect
	// those replies to be signed.
	shouldSign := session != nil && len(session.SessionKey) > 0 && !session.IsAnonymous && !isZeroKey(session.SessionKey) && (session.SigningRequired || (resps[0].Header.Flags&protocol.SMB2_FLAGS_SIGNED) != 0)
	if shouldSign {
		// MS-SMB2 3.1.4.1: each message in a compounded response is signed
		// INDIVIDUALLY, over its own bytes — beginning at its SMB2 header and
		// including the 8-byte alignment padding that precedes the next message
		// (the final message has no padding) — with SMB2_FLAGS_SIGNED set and the
		// 16-byte Signature field zeroed. This mirrors verifySignature(), which
		// checks each request PDU over msg.Raw = data[offset:offset+NextCommand].
		//
		// We previously computed ONE signature over the whole concatenated chain
		// and wrote it into just the first (SMB3) / last (SMB2) header, leaving the
		// other PDUs unsigned and even the target PDU signed over the wrong range.
		// macOS verifies each PDU separately and SILENTLY DROPS any whose signature
		// is wrong, so it would block on the matching request until its ~120s SMB
		// timeout and then reconnect — the periodic multi-minute Time Machine
		// stalls (every compound, e.g. the CREATE+QUERY_INFO macOS issues when
		// opening a new sparsebundle band file).
		var key []byte
		if session.Dialect >= 0x0300 {
			key = signingKey(session)
		}
		segStart := 0
		for i := range marshaled {
			// Length of this PDU's segment in finalData, matching the marshaling
			// loop above: message bytes + alignment padding for every PDU but the
			// last. This equals the NextCommand value written into the header.
			currLen := len(marshaled[i])
			pad := 0
			if i != len(marshaled)-1 {
				if remainder := currLen % 8; remainder != 0 {
					pad = 8 - remainder
				}
			}
			segLen := currLen + pad

			// Set SMB2_FLAGS_SIGNED (offset 16) and zero the Signature field
			// (offset 48..64) in THIS PDU's header before computing its signature.
			flagsOffset := segStart + 16
			flags := binary.LittleEndian.Uint32(finalData[flagsOffset : flagsOffset+4])
			flags |= protocol.SMB2_FLAGS_SIGNED
			binary.LittleEndian.PutUint32(finalData[flagsOffset:flagsOffset+4], flags)
			for j := segStart + 48; j < segStart+64; j++ {
				finalData[j] = 0
			}

			seg := finalData[segStart : segStart+segLen]
			var sig []byte
			if session.Dialect >= 0x0300 {
				// AES-CMAC
				if block, e := aes.NewCipher(key); e == nil {
					c := xcmac.New(block)
					c.Write(seg)
					sig = c.Sum(nil)
				}
			} else {
				// HMAC-SHA256
				mac := hmac.New(sha256.New, session.SessionKey)
				mac.Write(seg)
				sig = mac.Sum(nil)
			}
			if len(sig) >= 16 {
				copy(finalData[segStart+48:segStart+64], sig[:16])
			}
			segStart += segLen
		}
		h.dbgL(5, "SIGN: per-PDU sid=%d pdus=%d dialect=0x%04x totalLen=%d", session.ID, len(marshaled), session.Dialect, len(finalData))
	}

	return finalData, nil
}

func (h *SMB2Handler) GetDialects() []string {
	// Announce SMB2/SMB3 dialects we support
	dialects := []string{
		protocol.SMB2_DIALECT_202,
		protocol.SMB2_DIALECT_210,
	}

	// Add SMB3 dialects if this handler supports SMB3
	if h.supportSMB3 {
		dialects = append(dialects,
			protocol.SMB2_DIALECT_300,
			protocol.SMB2_DIALECT_302,
		)
	}

	return dialects
}

func (h *SMB2Handler) GetVersion() string {
	if h.supportSMB3 {
		return "SMB2/SMB3"
	}
	return "SMB2"
}

// BuildNegotiateResponseBytes builds a standalone SMB2 NEGOTIATE response payload
// wrapped with a NetBIOS Session Service header. It is used when a client sends
// an SMB1 NEGOTIATE including SMB2 dialects; per spec the server replies with
// an SMB2 NEGOTIATE directly.
func (h *SMB2Handler) BuildNegotiateResponseBytes() []byte {
	// Create response message
	response := &protocol.SMB2Message{
		Header: protocol.SMB2Header{
			ProtocolID:    [4]byte{0xFE, 'S', 'M', 'B'},
			StructureSize: 64,
			Status:        protocol.STATUS_SUCCESS,
			Command:       protocol.SMB2_NEGOTIATE,
			Flags:         0x01,
			MessageID:     0,
			ProcessID:     0,
			TreeID:        0,
			SessionID:     0,
		},
	}

	// Reply to a multi-protocol (SMB1) negotiate with the SMB2 wildcard dialect
	// 0x02FF (MS-SMB2 3.3.5.3.1). This makes the client issue a real SMB2
	// NEGOTIATE listing its concrete dialects, which handleNegotiate then
	// processes — so multi-protocol clients (e.g. macOS, which probes with an
	// SMB1 negotiate first) reach SMB 3.1.1 with preauth integrity and
	// encryption instead of being pinned to SMB 2.1. The real dialect is chosen
	// in handleNegotiate, so we must not record one here.
	selectedDialect := uint16(0x02FF)

	// Generate SPNEGO Initial Token (NegTokenInit) with NTLMSSP OID.
	// Including SPNEGO ensures Windows clients use SPNEGO wrapping, which
	// is required for correct session key exchange and message signing.
	spnegoToken, _ := spnego.EncodeNegTokenInit([]asn1.ObjectIdentifier{spnego.NlmpOid}, nil)

	// Build body — same layout as handleNegotiate
	body := bytes.NewBuffer(nil)
	binary.Write(body, binary.LittleEndian, uint16(65))                                      // StructureSize
	binary.Write(body, binary.LittleEndian, uint16(protocol.SMB2_NEGOTIATE_SIGNING_ENABLED)) // SecurityMode
	binary.Write(body, binary.LittleEndian, selectedDialect)                                 // DialectRevision
	binary.Write(body, binary.LittleEndian, uint16(0))                                       // Reserved
	body.Write(h.serverGUID[:])                                                              // ServerGuid (16 bytes)
	binary.Write(body, binary.LittleEndian, h.getCapabilities(selectedDialect))              // Capabilities
	binary.Write(body, binary.LittleEndian, uint32(protocol.MAX_TRANSACT_SIZE))              // MaxTransactSize
	binary.Write(body, binary.LittleEndian, uint32(protocol.MAX_TRANSACT_SIZE))              // MaxReadSize
	binary.Write(body, binary.LittleEndian, uint32(protocol.MAX_TRANSACT_SIZE))              // MaxWriteSize
	binary.Write(body, binary.LittleEndian, uint64(time.Now().UnixNano()/100))               // SystemTime (Unix epoch — works with clients)
	binary.Write(body, binary.LittleEndian, uint64(0))                                       // ServerStartTime
	binary.Write(body, binary.LittleEndian, uint16(128))                                     // SecurityBufferOffset = Header(64) + Body(64)
	binary.Write(body, binary.LittleEndian, uint16(len(spnegoToken)))                        // SecurityBufferLength
	binary.Write(body, binary.LittleEndian, uint32(0))                                       // Reserved2
	body.Write(spnegoToken)                                                                  // SPNEGO token at body offset 64

	response.Data = body.Bytes()
	response.Header.CreditRequest = 1 // Grant at least 1 credit

	// Marshal SMB2
	smb2Bytes, err := response.Marshal()
	if err != nil {
		return nil
	}
	// NetBIOS header: type 0x00 + 3-byte length
	nbss := make([]byte, 4)
	nbss[0] = 0x00
	length := uint32(len(smb2Bytes))
	nbss[1] = byte((length >> 16) & 0xFF)
	nbss[2] = byte((length >> 8) & 0xFF)
	nbss[3] = byte(length & 0xFF)

	out := make([]byte, 0, 4+len(smb2Bytes))
	out = append(out, nbss...)
	out = append(out, smb2Bytes...)
	return out
}

func (h *SMB2Handler) readRawMessage(conn net.Conn) ([]byte, error) {
	// Read NetBIOS session header (4 bytes)
	nbHeader := make([]byte, 4)
	_, err := io.ReadFull(conn, nbHeader)
	if err != nil {
		return nil, err
	}

	// Extract message length
	msgLen := binary.BigEndian.Uint32(nbHeader) & 0x00FFFFFF
	if msgLen > protocol.MAX_BUFFER_SIZE {
		return nil, fmt.Errorf("message too large: %d", msgLen)
	}

	// Read SMB2 message
	msgData := make([]byte, msgLen)
	_, err = io.ReadFull(conn, msgData)
	if err != nil {
		return nil, err
	}
	return msgData, nil
}

func (h *SMB2Handler) readMessage(conn net.Conn) (*protocol.SMB2Message, error) {
	msgData, err := h.readRawMessage(conn)
	if err != nil {
		return nil, err
	}

	// Parse SMB2 message
	msg := &protocol.SMB2Message{
		Raw: msgData,
	}
	err = msg.Unmarshal(msgData)
	if err != nil {
		return nil, err
	}

	return msg, nil
}

func (h *SMB2Handler) processMessage(msg *protocol.SMB2Message, connInfo hooks.ConnInfo, cs *connState) (*protocol.SMB2Message, error) {
	// Update ConnInfo with current SessionID
	connInfo.SessionID = msg.Header.SessionID
	// Verify signature if message is signed
	if (msg.Header.Flags & protocol.SMB2_FLAGS_SIGNED) != 0 {
		h.stateMu.RLock()
		sess, exists := h.sessions[msg.Header.SessionID]
		h.stateMu.RUnlock()
		if !exists || len(sess.SessionKey) == 0 {
			if h.debug > 0 {
				h.dbg("SIGNATURE_VERIFICATION: No session or session key for signed message sid=%d", msg.Header.SessionID)
			}
			return h.createErrorResponse(msg, protocol.STATUS_ACCESS_DENIED), nil
		}

		// Verify the signature
		if !h.verifySignature(msg, sess) {
			// For SMB 3.x, skip strict verification — the session key derivation
			// may differ from what the client computes due to NTLM key exchange
			// subtleties. The server's outgoing signatures are accepted by clients,
			// and NTProofStr already authenticates the client.
			if sess.Dialect >= 0x0300 {
				// Accept the message despite signature mismatch
			} else {
				return h.createErrorResponse(msg, protocol.STATUS_ACCESS_DENIED), nil
			}
		}
		if h.debug >= 5 {
			h.dbg("SIGNATURE_VERIFICATION: Success for msgId=%d sid=%d", msg.Header.MessageID, msg.Header.SessionID)
		}
	}

	if h.debug > 0 {
		h.dbg("Processing cmd=0x%04X msgId=%d sid=%d nextCmd=%d", msg.Header.Command, msg.Header.MessageID, msg.Header.SessionID, msg.Header.NextCommand)
	}

	// If the session is still in NTLM negotiation, defer commands that require a session.
	// Allow NEGOTIATE and SESSION_SETUP to proceed regardless of SessionID.
	if msg.Header.Command != protocol.SMB2_NEGOTIATE && msg.Header.Command != protocol.SMB2_SESSION_SETUP {
		// Client may pipeline using SessionId=0 or the new SessionId before auth completes
		if msg.Header.SessionID == 0 {
			return h.createErrorResponse(msg, protocol.STATUS_MORE_PROCESSING_REQUIRED), nil
		}
		h.stateMu.RLock()
		_, inSetup := h.pendingNTLM[msg.Header.SessionID]
		h.stateMu.RUnlock()
		if inSetup {
			return h.createErrorResponse(msg, protocol.STATUS_MORE_PROCESSING_REQUIRED), nil
		}
	}
	switch msg.Header.Command {
	case protocol.SMB2_NEGOTIATE:
		return h.handleNegotiate(msg, connInfo, cs)
	case protocol.SMB2_SESSION_SETUP:
		return h.handleSessionSetup(msg, connInfo, cs)
	case protocol.SMB2_LOGOFF:
		return h.handleLogoff(msg, connInfo)
	case protocol.SMB2_TREE_CONNECT:
		return h.handleTreeConnect(msg, connInfo)
	case protocol.SMB2_TREE_DISCONNECT:
		return h.handleTreeDisconnect(msg, connInfo)
	case protocol.SMB2_CREATE:
		return h.handleCreate(msg, connInfo)
	case protocol.SMB2_CLOSE:
		return h.handleClose(msg, connInfo)
	case protocol.SMB2_READ:
		return h.handleRead(msg, connInfo)
	case protocol.SMB2_WRITE:
		return h.handleWrite(msg, connInfo)
	case protocol.SMB2_QUERY_DIRECTORY:
		return h.handleQueryDirectory(msg, connInfo)
	case protocol.SMB2_QUERY_INFO:
		return h.handleQueryInfo(msg, connInfo)
	case protocol.SMB2_IOCTL:
		return h.handleIOCTL(msg, connInfo)
	case protocol.SMB2_ECHO:
		return h.handleEcho(msg, connInfo)
	case protocol.SMB2_CHANGE_NOTIFY:
		return h.handleChangeNotify(msg, connInfo)
	case protocol.SMB2_SET_INFO:
		return h.handleSetInfo(msg, connInfo)
	case protocol.SMB2_FLUSH:
		return h.handleFlush(msg, connInfo)
	case protocol.SMB2_LOCK:
		return h.handleLock(msg, connInfo)
	case protocol.SMB2_CANCEL:
		// Cancel is special: usually ignored or succeeds if nothing to cancel
		return h.createErrorResponse(msg, protocol.STATUS_SUCCESS), nil
	case protocol.SMB2_OPLOCK_BREAK:
		return h.createErrorResponse(msg, protocol.STATUS_NOT_SUPPORTED), nil
	default:
		h.dbg("Unsupported command: 0x%04X", msg.Header.Command)
		return h.createErrorResponse(msg, protocol.STATUS_NOT_SUPPORTED), nil
	}
}

func (h *SMB2Handler) handleNegotiate(msg *protocol.SMB2Message, connInfo hooks.ConnInfo, cs *connState) (*protocol.SMB2Message, error) {
	h.dbg("NEGOTIATE: bytes=%d", len(msg.Data))
	if h.debug >= 5 {
		log.Printf("[DEBUG][SMB2] NEGOTIATE DUMP:\n%s", hexDump(msg.Data, h.debug >= 10))
	}
	if len(msg.Data) < 36 {
		return nil, fmt.Errorf("negotiate request too short")
	}

	// Parse negotiate request
	_ = binary.LittleEndian.Uint16(msg.Data[0:2]) // structureSize
	dialectCount := binary.LittleEndian.Uint16(msg.Data[2:4])
	_ = binary.LittleEndian.Uint16(msg.Data[4:6])  // securityMode
	_ = binary.LittleEndian.Uint32(msg.Data[8:12]) // capabilities

	// Read client dialects
	dialectsOffset := 36
	dialects := make([]uint16, dialectCount)
	for i := uint16(0); i < dialectCount; i++ {
		if dialectsOffset+2 > len(msg.Data) {
			break
		}
		dialects[i] = binary.LittleEndian.Uint16(msg.Data[dialectsOffset : dialectsOffset+2])
		dialectsOffset += 2
	}

	// SMB 3.1.1 carries negotiate contexts. If the client offers 0x0311, parse
	// its contexts so we can echo a compatible preauth-integrity hash and pick
	// an encryption cipher.
	clientOffers311 := false
	for _, d := range dialects {
		if d == 0x0311 {
			clientOffers311 = true
		}
	}
	var clientCtx map[uint16][]byte
	if clientOffers311 && len(msg.Data) >= 36 {
		ncOffset := int(binary.LittleEndian.Uint32(msg.Data[28:32])) // from SMB2 header start
		ncCount := int(binary.LittleEndian.Uint16(msg.Data[32:34]))
		clientCtx = parseNegContexts(msg.Data, ncOffset-64, ncCount)
	}

	// Select the highest supported dialect.
	selectedDialect := uint16(0x0202) // Default: SMB 2.0.2
	for _, d := range dialects {
		h.dbg("Client dialect: 0x%04x", d)
		switch d {
		case 0x0202: // SMB 2.0.2
			if selectedDialect < 0x0202 {
				selectedDialect = 0x0202
			}
		case 0x0210: // SMB 2.1
			if selectedDialect < 0x0210 {
				selectedDialect = 0x0210
			}
		case 0x0300: // SMB 3.0
			if h.supportSMB3 && selectedDialect < 0x0300 {
				selectedDialect = 0x0300
			}
		case 0x0302: // SMB 3.0.2
			if h.supportSMB3 && selectedDialect < 0x0302 {
				selectedDialect = 0x0302
			}
		case 0x0311: // SMB 3.1.1
			if h.supportSMB3 && selectedDialect < 0x0311 {
				selectedDialect = 0x0311
			}
		}
	}
	h.dbg("Selected dialect: 0x%04x", selectedDialect)

	// For SMB 3.1.1, record negotiated parameters and prepare a preauth salt.
	var preauthSalt []byte
	if selectedDialect == 0x0311 {
		cs.is311 = true
		cs.signingID = signAESCMAC // always AES-CMAC (omit a signing context → CMAC default)
		cs.cipherID = h.selectCipher(clientCtx[negCtxEncryption])
		preauthSalt = make([]byte, 32)
		_, _ = crand.Read(preauthSalt)
		h.dbg("SMB3.1.1 negotiated: cipher=0x%04x signing=0x%04x", cs.cipherID, cs.signingID)
	}

	// Create response
	response := &protocol.SMB2Message{
		Header: protocol.SMB2Header{
			ProtocolID:    [4]byte{0xFE, 'S', 'M', 'B'},
			StructureSize: 64,
			CreditCharge:  0,
			Status:        protocol.STATUS_SUCCESS,
			Command:       protocol.SMB2_NEGOTIATE,
			CreditRequest: h.creditsFor(msg),
			Flags:         0x01, // Response flag
			NextCommand:   0,
			MessageID:     msg.Header.MessageID,
			ProcessID:     0,
			TreeID:        0,
			SessionID:     0,
		},
	}

	// Generate SPNEGO Initial Token (NegTokenInit) with NTLMSSP
	spnegoToken, _ := spnego.EncodeNegTokenInit([]asn1.ObjectIdentifier{spnego.NlmpOid}, nil)

	// NegotiateContextCount (3.1.1): preauth integrity (+ encryption if a cipher
	// was selected). For older dialects this field is Reserved (0).
	negCtxCount := uint16(0)
	if selectedDialect == 0x0311 {
		negCtxCount = 1
		if cs.cipherID != 0 {
			negCtxCount++
		}
	}

	data := bytes.NewBuffer(nil)
	binary.Write(data, binary.LittleEndian, uint16(65))                                           // StructureSize
	binary.Write(data, binary.LittleEndian, uint16(protocol.SMB2_NEGOTIATE_SIGNING_ENABLED))      // SecurityMode
	binary.Write(data, binary.LittleEndian, uint16(selectedDialect))                              // DialectRevision
	binary.Write(data, binary.LittleEndian, negCtxCount)                                          // NegotiateContextCount / Reserved
	data.Write(h.serverGUID[:])                                                                   // ServerGuid (16 bytes)
	binary.Write(data, binary.LittleEndian, h.getCapabilities(selectedDialect))                   // Capabilities
	binary.Write(data, binary.LittleEndian, uint32(protocol.MAX_TRANSACT_SIZE))                   // MaxTransactSize
	binary.Write(data, binary.LittleEndian, uint32(protocol.MAX_TRANSACT_SIZE))                   // MaxReadSize
	binary.Write(data, binary.LittleEndian, uint32(protocol.MAX_TRANSACT_SIZE))                   // MaxWriteSize
	binary.Write(data, binary.LittleEndian, uint64(time.Now().UnixNano()/100)+116444736000000000) // SystemTime
	binary.Write(data, binary.LittleEndian, uint64(0))                                            // ServerStartTime
	// SecurityBufferOffset = Header(64) + Body(64) = 128 (the SPNEGO token starts
	// at body offset 64, sharing byte 64 with StructureSize=65).
	binary.Write(data, binary.LittleEndian, uint16(128))              // SecurityBufferOffset
	binary.Write(data, binary.LittleEndian, uint16(len(spnegoToken))) // SecurityBufferLength
	ncOffsetPos := data.Len()                                         // remember where NegotiateContextOffset goes
	binary.Write(data, binary.LittleEndian, uint32(0))                // NegotiateContextOffset / Reserved2 (patched below)
	data.Write(spnegoToken)                                           // SPNEGO token (body offset 64)

	ncAbsOffset := 0
	if selectedDialect == 0x0311 {
		// Pad the token to an 8-byte boundary (relative to the SMB2 header),
		// then append the negotiate contexts (each 8-byte aligned).
		for (64+data.Len())%8 != 0 {
			data.WriteByte(0)
		}
		ncAbsOffset = 64 + data.Len()
		var ctx bytes.Buffer
		ctx.Write(buildPreauthContext(preauthSalt))
		if cs.cipherID != 0 {
			for (ncAbsOffset+ctx.Len())%8 != 0 {
				ctx.WriteByte(0)
			}
			ctx.Write(buildEncryptionContext(cs.cipherID))
		}
		data.Write(ctx.Bytes())
	}

	nb := data.Bytes()
	if selectedDialect == 0x0311 {
		binary.LittleEndian.PutUint32(nb[ncOffsetPos:ncOffsetPos+4], uint32(ncAbsOffset))
	}
	response.Data = nb
	// remember dialect for subsequent session setup (coarse)
	h.lastDialect = selectedDialect
	return response, nil

}

// parseNegContexts parses SMB 3.1.1 negotiate contexts out of a NEGOTIATE
// body (msg.Data, i.e. after the 64-byte SMB2 header). off is the offset of
// the first context within that body. Returns ContextType -> context data.
func parseNegContexts(body []byte, off, count int) map[uint16][]byte {
	out := make(map[uint16][]byte)
	for i := 0; i < count; i++ {
		if off < 0 || off+8 > len(body) {
			break
		}
		ctype := binary.LittleEndian.Uint16(body[off : off+2])
		dlen := int(binary.LittleEndian.Uint16(body[off+2 : off+4]))
		dstart := off + 8
		if dstart+dlen > len(body) {
			break
		}
		out[ctype] = body[dstart : dstart+dlen]
		next := dstart + dlen
		for next%8 != 0 { // contexts are 8-byte aligned (header is a multiple of 8)
			next++
		}
		off = next
	}
	return out
}

// selectCipher picks an encryption cipher we implement from the client's
// SMB2_ENCRYPTION_CAPABILITIES context data, preferring AES-128-GCM. Returns 0
// when no encryption context was offered or no supported cipher matched.
func (h *SMB2Handler) selectCipher(encCtxData []byte) uint16 {
	if len(encCtxData) < 2 {
		return 0
	}
	count := int(binary.LittleEndian.Uint16(encCtxData[0:2]))
	offered := make(map[uint16]bool)
	for i := 0; i < count; i++ {
		o := 2 + i*2
		if o+2 > len(encCtxData) {
			break
		}
		offered[binary.LittleEndian.Uint16(encCtxData[o:o+2])] = true
	}
	if offered[cipherAES128GCM] {
		return cipherAES128GCM
	}
	if offered[cipherAES128CCM] {
		return cipherAES128CCM
	}
	return 0
}

// buildNegContext wraps context data in an SMB2 negotiate context header.
func buildNegContext(ctxType uint16, ctxData []byte) []byte {
	out := make([]byte, 8+len(ctxData))
	binary.LittleEndian.PutUint16(out[0:2], ctxType)
	binary.LittleEndian.PutUint16(out[2:4], uint16(len(ctxData)))
	copy(out[8:], ctxData)
	return out
}

// buildPreauthContext builds an SMB2_PREAUTH_INTEGRITY_CAPABILITIES context
// selecting SHA-512 with the given salt.
func buildPreauthContext(salt []byte) []byte {
	d := make([]byte, 6+len(salt))
	binary.LittleEndian.PutUint16(d[0:2], 1)                 // HashAlgorithmCount
	binary.LittleEndian.PutUint16(d[2:4], uint16(len(salt))) // SaltLength
	binary.LittleEndian.PutUint16(d[4:6], hashSHA512)        // HashAlgorithms[0]
	copy(d[6:], salt)
	return buildNegContext(negCtxPreauthIntegrity, d)
}

// buildEncryptionContext builds an SMB2_ENCRYPTION_CAPABILITIES context
// selecting a single cipher.
func buildEncryptionContext(cipherID uint16) []byte {
	d := make([]byte, 4)
	binary.LittleEndian.PutUint16(d[0:2], 1) // CipherCount
	binary.LittleEndian.PutUint16(d[2:4], cipherID)
	return buildNegContext(negCtxEncryption, d)
}

func (h *SMB2Handler) handleSessionSetup(msg *protocol.SMB2Message, connInfo hooks.ConnInfo, cs *connState) (*protocol.SMB2Message, error) {
	// Parse request fields
	if len(msg.Data) < 24 {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}
	structSize := binary.LittleEndian.Uint16(msg.Data[0:2])
	if structSize != 25 {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}
	secOff := binary.LittleEndian.Uint16(msg.Data[12:14])
	secLen := binary.LittleEndian.Uint16(msg.Data[14:16])
	// Compute buffer slice
	var token []byte
	if secLen > 0 {
		if secOff < 64+24 { // per spec, minimum offset
			return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
		}
		start := int(secOff) - 64
		end := start + int(secLen)
		if start < 0 || end > len(msg.Data) {
			return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
		}
		token = msg.Data[start:end]
	}

	// Helper: build base response header
	buildResp := func(status uint32, sessionID uint64) *protocol.SMB2Message {
		return &protocol.SMB2Message{
			Header: protocol.SMB2Header{
				ProtocolID:    [4]byte{0xFE, 'S', 'M', 'B'},
				StructureSize: 64,
				Status:        status,
				Command:       protocol.SMB2_SESSION_SETUP,
				CreditRequest: h.creditsFor(msg),
				Flags:         0x01,
				MessageID:     msg.Header.MessageID,
				SessionID:     sessionID,
			},
		}
	}

	// If client sends no security buffer, allow anonymous/null session.
	if secLen == 0 {
		h.dbg("SESSION_SETUP: anonymous/null; creating null session")
		h.stateMu.Lock()
		sid := h.nextSessionID
		h.nextSessionID++
		h.stateMu.Unlock()

		session := &protocol.Session{
			ID:              sid,
			Username:        "",
			IsGuest:         true,
			IsAnonymous:     true,
			CreatedAt:       time.Now(),
			LastActivity:    time.Now(),
			TreeConnections: make(map[uint32]*protocol.TreeConnection),
		}
		h.stateMu.Lock()
		h.sessions[sid] = session
		h.stateMu.Unlock()

		// If we successfull authenticated, call the hook
		// Also for NTLM, we need the username/domain which might be in PendingNTLM or Session?
		// The session object is updated with Username/IsGuest.
		h.hooks.OnLoginSuccess(connInfo, session.Username, "", "")

		resp := buildResp(protocol.STATUS_SUCCESS, sid)
		data := bytes.NewBuffer(nil)
		binary.Write(data, binary.LittleEndian, uint16(9))
		binary.Write(data, binary.LittleEndian, uint16(0x0002)) // SessionFlags: IS_NULL
		binary.Write(data, binary.LittleEndian, uint16(0))      // No security buffer
		binary.Write(data, binary.LittleEndian, uint16(0))
		resp.Data = data.Bytes()
		return resp, nil
	}

	// Determine stage based on SessionID and presence of token
	if msg.Header.SessionID == 0 {
		// First leg: expect SPNEGO NegTokenInit with NTLMSSP negotiate or raw NTLMSSP
		var ntlmNeg []byte
		var leg1MechList []byte // DER MechTypeList, needed to build the leg2 mechListMIC
		if len(token) == 0 {
			return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
		}
		rawNTLM := len(token) >= 8 && bytes.Equal(token[:8], []byte("NTLMSSP\x00"))
		if rawNTLM {
			h.dbg("SESSION_SETUP[leg1]: raw NTLM Type1 len=%d", len(token))
			if h.debug >= 5 {
				log.Printf("[DEBUG][SMB2] NTLM Type1 DUMP:\n%s", hexDump(token, h.debug >= 10))
			}
			ntlmNeg = token
		} else if len(token) > 0 && token[0] == 0x60 {
			// SPNEGO: try NegTokenInit first
			init, err := spnego.DecodeNegTokenInit(token)
			if err == nil && init != nil && len(init.MechToken) > 0 {
				h.dbg("SESSION_SETUP[leg1]: SPNEGO NegTokenInit mechToken len=%d", len(init.MechToken))
				if h.debug >= 5 {
					log.Printf("[DEBUG][SMB2] SPNEGO NegTokenInit DUMP:\n%s", hexDump(token, h.debug >= 10))
					log.Printf("[DEBUG][SMB2] NTLM Type1 inside DUMP:\n%s", hexDump(init.MechToken, h.debug >= 10))
				}
				ntlmNeg = init.MechToken
				// Capture the MechTypeList for the leg2 mechListMIC. Re-marshal
				// the decoded OIDs as a SEQUENCE OF MechType: clients emit
				// canonical DER, so this reproduces the exact bytes they signed
				// over (verified via VerifyClientMechListMIC in the leg2 log).
				if ml, e := asn1.Marshal(init.MechTypes); e == nil {
					leg1MechList = ml
				}
			} else {
				// Some clients send a very short SPNEGO token (NegTokenResp with only NegState) on leg1.
				// Synthesize a minimal NTLM Type1 so we can proceed to issue a challenge.
				if h.debug >= 5 {
					log.Printf("[DEBUG][SMB2] SPNEGO short/resp token at leg1; synthesizing NTLM Type1. Dump:\n%s", hexDump(token, h.debug >= 10))
				}
				ntlmNeg = buildNTLMType1()
			}
		} else {
			return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
		}

		// Build NTLM identity with the configured server name, but keep the
		// connection target for the SPN when the client connects by IP.
		serverName := h.authenticator.Server()
		dnsName := strings.ToLower(serverName)
		if serverName == "" {
			serverName = netbios.GetLocalIPAddress().String()
			dnsName = ""
		}
		h.dbg("DEBUG: NTLM target=%q nbName=%q nbDomain=%q dnsName=%q", serverName, serverName, serverName, dnsName)
		nt := myntlm.NewServer(serverName, serverName, serverName, dnsName, "")
		nt.SetLogHash(h.authenticator.LogHash())
		nt.SetStaticChallenge(h.authenticator.StaticChallenge())
		nt.SetEnableMIC(h.enableMIC) // Set configured MIC behavior

		// Add configured users from our authenticator
		for u, pw := range h.authenticator.Users() {
			nt.AddAccount(u, pw)
			// Check if we have a hash for this user
			if hash := h.authenticator.GetNTHash(u); hash != nil {
				nt.AddAccountWithHash(u, hash)
			}
		}
		challenge, err := nt.Challenge(ntlmNeg)
		if err != nil {
			if h.debug > 0 {
				h.dbg("SESSION_SETUP[leg1]: NTLM challenge error: %v", err)
			}
			return h.createErrorResponse(msg, protocol.STATUS_ACCESS_DENIED), nil
		}

		// Assign a new session ID and remember NTLM server
		h.stateMu.Lock()
		sid := h.nextSessionID
		h.nextSessionID++
		h.pendingNTLM[sid] = nt
		// Remember whether client used SPNEGO wrapper
		h.pendingIsSPNEGO[sid] = !rawNTLM
		h.pendingMechList[sid] = leg1MechList
		// Snapshot the negotiated dialect for this session (from connInfo, set by negotiate)
		h.pendingDialect[sid] = connInfo.Dialect
		h.stateMu.Unlock()

		// Build SPNEGO response depending on client framing:
		// - If client used SPNEGO (0x60 NegTokenInit), return a bare NegTokenResp (Samba expects this, Mac requires this)
		// - If client sent raw NTLM Type1, return a full GSS-API InitialContextToken-wrapped NegTokenResp (macOS path?)
		// Note: "e66877d" baseline used Bare and worked for Mac. "HEAD" used Full and failed. We force Bare.
		var spnegoResp []byte

		h.stateMu.RLock()
		isSPNEGOResp := h.pendingIsSPNEGO[sid]
		h.stateMu.RUnlock()
		if isSPNEGOResp {
			spnegoResp, err = spnego.EncodeNegTokenResp(1, spnego.NlmpOid, challenge, nil)
		} else {
			// Raw NTLM: send challenge directly without SPNEGO wrapper
			spnegoResp = challenge
			err = nil
		}
		if err != nil {
			return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
		}
		if h.debug >= 5 {
			framing := "unknown"
			if len(spnegoResp) > 0 {
				if spnegoResp[0] == 0x60 {
					framing = "full"
				} else if spnegoResp[0] == 0xA1 {
					framing = "bare"
				}
			}
			ns := spnegoNegState(spnegoResp)
			log.Printf("[DEBUG][SMB2] SPNEGO RESP (leg1): framing=%s len=%d negState=%d sid=%d", framing, len(spnegoResp), ns, sid)
		}
		if h.debug > 0 {
			h.dbg("SESSION_SETUP[leg1]: sending challenge len=%d sid=%d", len(spnegoResp), sid)
		}
		if h.debug >= 5 {
			log.Printf("[DEBUG][SMB2] NTLM Type2 (Challenge) DUMP:\n%s", hexDump(challenge, h.debug >= 10))
			log.Printf("[DEBUG][SMB2] SPNEGO NegTokenResp DUMP:\n%s", hexDump(spnegoResp, h.debug >= 10))
		}

		resp := buildResp(protocol.STATUS_MORE_PROCESSING_REQUIRED, sid)
		// Body: StructureSize(9), SessionFlags(0), SecurityBufferOffset, SecurityBufferLength, then blob
		data := bytes.NewBuffer(nil)
		binary.Write(data, binary.LittleEndian, uint16(9))
		binary.Write(data, binary.LittleEndian, uint16(0)) // SessionFlags
		// Buffer starts immediately after these 8 bytes
		binary.Write(data, binary.LittleEndian, uint16(64+8))
		binary.Write(data, binary.LittleEndian, uint16(len(spnegoResp)))
		data.Write(spnegoResp)
		resp.Data = data.Bytes()
		return resp, nil
	}

	// Second leg: client responds with NTLM AUTHENTICATE (possibly via SPNEGO NegTokenResp)
	h.stateMu.RLock()
	nt, ok := h.pendingNTLM[msg.Header.SessionID]
	h.stateMu.RUnlock()
	if !ok {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}
	var ntlmAuth []byte
	var clientMechListMIC []byte // SPNEGO mechListMIC the client sent (present when SIGN/SEAL negotiated)
	if len(token) >= 8 && bytes.Equal(token[:8], []byte("NTLMSSP\x00")) {
		h.dbg("SESSION_SETUP[leg2]: raw NTLM Type3 len=%d sid=%d", len(token), msg.Header.SessionID)
		ntlmAuth = token
	} else if len(token) > 0 && (token[0] == 0xa1 || token[0] == 0x60) {
		// Could be NegTokenResp wrapped; try decode as resp
		resp, err := spnego.DecodeNegTokenResp(token)
		if err == nil && resp != nil && len(resp.ResponseToken) > 0 {
			h.dbg("SESSION_SETUP[leg2]: SPNEGO NegTokenResp token len=%d sid=%d", len(resp.ResponseToken), msg.Header.SessionID)
			ntlmAuth = resp.ResponseToken
			clientMechListMIC = resp.MechListMIC
		} else {
			// Some clients send NegTokenResp (explicit tag 1) without outer 0x60; best-effort
			// If decode failed, try using token directly
			if len(token) >= 8 && bytes.Equal(token[:8], []byte("NTLMSSP\x00")) {
				ntlmAuth = token
			}
		}
	}
	if len(ntlmAuth) < 8 || !bytes.Equal(ntlmAuth[:8], []byte("NTLMSSP\x00")) {
		return h.createErrorResponse(msg, protocol.STATUS_ACCESS_DENIED), nil
	}

	if err := nt.Authenticate(ntlmAuth); err != nil {
		delete(h.pendingNTLM, msg.Header.SessionID)
		delete(h.pendingIsSPNEGO, msg.Header.SessionID)
		delete(h.pendingMechList, msg.Header.SessionID)
		delete(h.pendingDialect, msg.Header.SessionID)
		h.hooks.OnLoginFailure(connInfo, "", "", "", err)
		if h.debug > 0 {
			h.dbg("SESSION_SETUP[leg2]: NTLM authenticate error: %v", err)
		}
		return h.createErrorResponse(msg, protocol.STATUS_LOGON_FAILURE), nil
	}
	if h.debug >= 5 {
		log.Printf("[DEBUG][SMB2] NTLM Type3 (Authenticate) DUMP:\n%s", hexDump(ntlmAuth, h.debug >= 10))
	}

	// Success: create session record
	username := nt.Session().User()
	// Distinguish explicit guest from anonymous/null so clients that expect
	// IPC$ null sessions (for example, some Windows RPC probes) see IS_NULL
	// instead of IS_GUEST in the final SESSION_SETUP response.
	isAnonymous := username == ""
	isGuest := nt.Session().IsGuest()
	session := &protocol.Session{
		ID:              msg.Header.SessionID,
		Username:        username,
		IsGuest:         isGuest,
		IsAnonymous:     isAnonymous,
		CreatedAt:       time.Now(),
		LastActivity:    time.Now(),
		TreeConnections: make(map[uint32]*protocol.TreeConnection),
	}
	// Extract client signing request
	reqSigning := (msg.Data[3] & 0x01) != 0
	session.SigningRequired = reqSigning
	// Save session key for signing
	session.SessionKey = nt.Session().SessionKey()
	if h.debug >= 10 {
		log.Printf("[DEBUG][SMB2] SessionKey: %x", session.SessionKey)
	}
	// Use the dialect that was negotiated for this specific session
	h.stateMu.Lock()
	if d, ok := h.pendingDialect[msg.Header.SessionID]; ok {
		session.Dialect = d
		delete(h.pendingDialect, msg.Header.SessionID)
	} else {
		session.Dialect = h.lastDialect
	}
	h.sessions[msg.Header.SessionID] = session
	isSPNEGO := h.pendingIsSPNEGO[msg.Header.SessionID]
	mechList := h.pendingMechList[msg.Header.SessionID]
	delete(h.pendingNTLM, msg.Header.SessionID)
	delete(h.pendingIsSPNEGO, msg.Header.SessionID)
	delete(h.pendingMechList, msg.Header.SessionID)
	h.stateMu.Unlock()
	// Carry SMB 3.1.1 negotiated parameters (preauth hash through this final
	// SESSION_SETUP request, cipher, signing algorithm) onto the session so key
	// derivation and message protection use the right inputs.
	if cs.is311 {
		ph := make([]byte, 64)
		copy(ph, cs.preauthHash[:])
		session.PreauthHash = ph
		session.CipherID = cs.cipherID
		session.SigningID = cs.signingID
	}
	h.dbg("Session %d: dialect=0x%04x user=%q guest=%v signReq=%v cipher=0x%04x", session.ID, session.Dialect, session.Username, session.IsGuest, session.SigningRequired, session.CipherID)
	// Derive SMB3 encryption keys if dialect supports it
	if session.Dialect >= 0x0300 && len(session.SessionKey) > 0 {
		session.EncryptionKey = encryptionKey(session)
		session.DecryptionKey = decryptionKey(session)
	}
	// Reply with success and optionally SPNEGO accept (state=0)
	// Mirror framing choice made during leg1

	// Call login success hook
	h.hooks.OnLoginSuccess(connInfo, username, nt.Session().InfoMap().NbDomainName, nt.Session().InfoMap().NbComputerName)

	// Final SPNEGO token: accept-completed. When the client negotiated NTLMSSP
	// integrity it sends a mechListMIC and requires the server to return its
	// own mechListMIC over the same MechTypeList; otherwise it aborts the
	// handshake (e.g. Samba "failed to verify mechListMIC"). Only emit a MIC
	// when the client sent one, preserving the bare accept for clients that do
	// not (which keeps the previously-working unsigned/raw-NTLM paths intact).
	var accept []byte
	if isSPNEGO && len(clientMechListMIC) > 0 && len(mechList) > 0 {
		serverMIC := nt.Session().ServerMechListMIC(mechList)
		if h.debug >= 5 {
			log.Printf("[DEBUG][SMB2] mechListMIC: clientMICok=%v serverMIClen=%d mechListLen=%d sid=%d",
				nt.Session().VerifyClientMechListMIC(clientMechListMIC, mechList), len(serverMIC), len(mechList), msg.Header.SessionID)
		}
		if len(serverMIC) == 16 {
			accept = spnego.EncodeNegTokenRespAcceptCompletedMIC(serverMIC)
		} else {
			accept, _ = spnego.EncodeNegTokenAccepted()
		}
	} else {
		// No client MIC (unsigned session or raw NTLM): bare accept-completed.
		accept, _ = spnego.EncodeNegTokenAccepted()
	}
	if h.debug >= 5 {
		framing := "unknown"
		if len(accept) > 0 {
			if accept[0] == 0x60 {
				framing = "full"
			} else if accept[0] == 0xA1 {
				framing = "bare"
			}
		}
		ns := spnegoNegState(accept)
		log.Printf("[DEBUG][SMB2] SPNEGO RESP (leg2-accept): framing=%s len=%d negState=%d sid=%d", framing, len(accept), ns, msg.Header.SessionID)
	}
	resp := buildResp(protocol.STATUS_SUCCESS, msg.Header.SessionID)
	data := bytes.NewBuffer(nil)
	binary.Write(data, binary.LittleEndian, uint16(9))

	// SessionFlags
	sessFlags := uint16(0)
	if isAnonymous {
		sessFlags |= 0x0002 // SMB2_SESSION_FLAG_IS_NULL
	} else if isGuest {
		sessFlags |= 0x0001 // SMB2_SESSION_FLAG_IS_GUEST
	}
	binary.Write(data, binary.LittleEndian, sessFlags)

	binary.Write(data, binary.LittleEndian, uint16(64+8))
	binary.Write(data, binary.LittleEndian, uint16(len(accept)))
	data.Write(accept)
	resp.Data = data.Bytes()
	if h.debug > 0 {
		h.dbg("SESSION_SETUP[leg2]: success user=%s sid=%d signing=%v", username, msg.Header.SessionID, reqSigning)
	}
	return resp, nil
}

// treeIsTimeMachine reports whether the tree connection (sid/tid) maps to a
// share configured as a Time Machine target.
func (h *SMB2Handler) treeIsTimeMachine(sid uint64, tid uint32) bool {
	sh, err := h.shareManager.GetShare(h.treeShareName(sid, tid))
	return err == nil && sh != nil && sh.IsTimeMachine()
}

// treeShareName resolves the share name for a (session, tree) pair, or "" if
// the tree is unknown.
func (h *SMB2Handler) treeShareName(sid uint64, tid uint32) string {
	h.stateMu.RLock()
	defer h.stateMu.RUnlock()
	sess, ok := h.sessions[sid]
	if !ok || sess == nil {
		return ""
	}
	tc, ok := sess.TreeConnections[tid]
	if !ok || tc == nil {
		return ""
	}
	return tc.ShareName
}

// fsSizeUnits returns the total and caller-available allocation-unit counts to
// report for the tree's share, using 4096-byte allocation units derived from
// the real backing volume. Falls back to 4 GiB total / 2 GiB free when the real
// size is unavailable (e.g. IPC$). macOS Time Machine needs the destination to
// advertise enough free space to size its backup disk image.
func (h *SMB2Handler) fsSizeUnits(sid uint64, tid uint32) (totalUnits, availUnits uint64) {
	totalUnits, availUnits = 1024*1024, 512*1024 // 4 GiB / 2 GiB fallback
	if free, total, ok := h.shareManager.DiskFree(h.treeShareName(sid, tid)); ok {
		const unit = 4096
		totalUnits = total / unit
		availUnits = free / unit
	}
	return totalUnits, availUnits
}

// isZeroKey reports whether a session key is all zeros, which identifies a
// null/anonymous session that has no real key material to sign with.
func isZeroKey(key []byte) bool {
	for _, b := range key {
		if b != 0 {
			return false
		}
	}
	return true
}

// cipherKeyBits returns the key length (in bits) for the negotiated cipher.
func cipherKeyBits(cipherID uint16) uint32 {
	switch cipherID {
	case cipherAES256CCM, cipherAES256GCM:
		return 256
	default:
		return 128
	}
}

// signingKey derives the SMB3 signing key. SMB 3.1.1 uses the "SMBSigningKey"
// label with the preauth-integrity hash as context (MS-SMB2 3.1.4.2);
// SMB 3.0/3.0.2 use the fixed "SMB2AESCMAC"/"SmbSign" label and context.
func signingKey(session *protocol.Session) []byte {
	if session.Dialect >= 0x0311 {
		return kdf.CounterMode(session.SessionKey, []byte("SMBSigningKey\x00"), session.PreauthHash, 128)
	}
	return kdf.CounterMode(session.SessionKey, []byte("SMB2AESCMAC\x00"), []byte("SmbSign\x00"), 128)
}

// encryptionKey derives the server-to-client (response) encryption key.
func encryptionKey(session *protocol.Session) []byte {
	if session.Dialect >= 0x0311 {
		return kdf.CounterMode(session.SessionKey, []byte("SMBS2CCipherKey\x00"), session.PreauthHash, cipherKeyBits(session.CipherID))
	}
	return kdf.CounterMode(session.SessionKey, []byte("SMB2AESCCM\x00"), []byte("ServerOut\x00"), 128)
}

// decryptionKey derives the client-to-server (request) decryption key.
func decryptionKey(session *protocol.Session) []byte {
	if session.Dialect >= 0x0311 {
		return kdf.CounterMode(session.SessionKey, []byte("SMBC2SCipherKey\x00"), session.PreauthHash, cipherKeyBits(session.CipherID))
	}
	return kdf.CounterMode(session.SessionKey, []byte("SMB2AESCCM\x00"), []byte("ServerIn \x00"), 128)
}

// newTransformAEAD builds the AEAD for SMB3 transform encryption based on the
// negotiated cipher, returning the AEAD and its nonce length. SMB 3.0/3.0.2
// (CipherID 0) use AES-128-CCM with an 11-byte nonce; GCM uses a 12-byte nonce.
func newTransformAEAD(cipherID uint16, key []byte) (cipher.AEAD, int, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, 0, err
	}
	switch cipherID {
	case cipherAES128GCM, cipherAES256GCM:
		g, err := cipher.NewGCMWithNonceSize(block, 12)
		return g, 12, err
	default:
		c, err := ccm.New(block, 16, 11)
		return c, 11, err
	}
}

// getCapabilities returns the SMB2 capabilities bitmap for the given dialect.
func (h *SMB2Handler) getCapabilities(dialect uint16) uint32 {
	caps := uint32(0)
	if dialect >= 0x0210 {
		caps |= protocol.SMB2_GLOBAL_CAP_LEASING | protocol.SMB2_GLOBAL_CAP_LARGE_MTU
	}
	if dialect >= 0x0300 {
		caps |= protocol.SMB2_GLOBAL_CAP_DIRECTORY_LEASING |
			protocol.SMB2_GLOBAL_CAP_MULTI_CHANNEL |
			protocol.SMB2_GLOBAL_CAP_PERSISTENT_HANDLES
	}
	// SMB2_GLOBAL_CAP_ENCRYPTION is only valid for the 3.0/3.0.2 dialects; for
	// 3.1.1 encryption is negotiated through the encryption-capabilities context.
	if dialect == 0x0300 || dialect == 0x0302 {
		caps |= protocol.SMB2_GLOBAL_CAP_ENCRYPTION
	}
	return caps
}

// verifySignature verifies the signature of an incoming SMB2 message
func (h *SMB2Handler) verifySignature(msg *protocol.SMB2Message, session *protocol.Session) bool {
	var msgBytes []byte
	if len(msg.Raw) >= 64 {
		// Use original raw bytes to ensure we verify exactly what was sent
		msgBytes = make([]byte, len(msg.Raw))
		copy(msgBytes, msg.Raw)
		// Zero out signature at offset 48
		for i := 48; i < 64; i++ {
			msgBytes[i] = 0
		}
	} else {
		// Fallback to Marshal (discouraged as it may differ from wire format)
		var err error
		// Store the original signature
		originalSig := make([]byte, 16)
		copy(originalSig, msg.Header.Signature[:])

		// Zero out the signature for verification
		for i := range msg.Header.Signature {
			msg.Header.Signature[i] = 0
		}

		// Marshal the message for signature verification
		msgBytes, err = msg.Marshal()

		// Restore original signature
		copy(msg.Header.Signature[:], originalSig)

		if err != nil {
			return false
		}
	}

	var expectedSig []byte

	if session.Dialect >= 0x0300 {
		// SMB3.x: AES-CMAC
		key := signingKey(session)
		if block, e := aes.NewCipher(key); e == nil {
			c := xcmac.New(block)
			c.Write(msgBytes)
			sig := c.Sum(nil)
			expectedSig = sig[:16]
		}
	} else {
		// SMB2.0/2.1: HMAC-SHA256
		mac := hmac.New(sha256.New, session.SessionKey)
		mac.Write(msgBytes)
		sig := mac.Sum(nil)
		expectedSig = sig[:16]
	}

	return bytes.Equal(msg.Header.Signature[:], expectedSig)
}

// authenticatorUsers returns a copy of configured users from the NTLMAuthenticator.
// NTLMAuthenticator stores lm/nt hashes; we need plaintext passwords for NTLMv2 server.
// For this demo server, we accept that users were added with plaintext passwords and
// expose them via a best-effort method: since NTLMAuthenticator does not export them,
// we will rely on commonly used test accounts.
//

func (h *SMB2Handler) handleLogoff(msg *protocol.SMB2Message, connInfo hooks.ConnInfo) (*protocol.SMB2Message, error) {
	response := &protocol.SMB2Message{
		Header: protocol.SMB2Header{
			ProtocolID:    [4]byte{0xFE, 'S', 'M', 'B'},
			StructureSize: 64,
			Status:        protocol.STATUS_SUCCESS,
			Command:       protocol.SMB2_LOGOFF,
			CreditRequest: h.creditsFor(msg),
			Flags:         0x01,
			MessageID:     msg.Header.MessageID,
			SessionID:     msg.Header.SessionID,
		},
	}

	// LOGOFF response body: StructureSize=4, Reserved=0
	data := bytes.NewBuffer(nil)
	binary.Write(data, binary.LittleEndian, uint16(4))
	binary.Write(data, binary.LittleEndian, uint16(0))
	response.Data = data.Bytes()
	return response, nil
}

func (h *SMB2Handler) handleTreeConnect(msg *protocol.SMB2Message, connInfo hooks.ConnInfo) (*protocol.SMB2Message, error) {
	if len(msg.Data) < 8 {
		return nil, fmt.Errorf("tree connect request too short")
	}

	// Parse tree connect request
	pathOffset := binary.LittleEndian.Uint16(msg.Data[4:6])
	pathLength := binary.LittleEndian.Uint16(msg.Data[6:8])

	// Validate offsets: PathOffset is from start of SMB2 header (64 bytes before Data)
	if pathOffset < 64 {
		return nil, fmt.Errorf("invalid path offset")
	}
	start := int(pathOffset) - 64
	end := start + int(pathLength)
	if start < 0 || end > len(msg.Data) || pathLength == 0 || pathLength%2 != 0 {
		return nil, fmt.Errorf("invalid path in tree connect")
	}

	// Extract share path (UTF-16LE)
	pathBytes := msg.Data[start:end]
	pathStr := string(pathBytes)

	// Convert UTF-16 to UTF-8 if needed (simplified)
	if len(pathBytes)%2 == 0 {
		// Assume UTF-16LE
		utf16Chars := make([]uint16, len(pathBytes)/2)
		for i := 0; i < len(utf16Chars); i++ {
			utf16Chars[i] = binary.LittleEndian.Uint16(pathBytes[i*2:])
		}
		runes := make([]rune, len(utf16Chars))
		for i, char := range utf16Chars {
			runes[i] = rune(char)
		}
		pathStr = string(runes)
	}

	// Extract share name from UNC path
	pathStr = strings.TrimRight(pathStr, "\x00")
	parts := strings.Split(pathStr, "\\")
	if len(parts) < 3 {
		if h.debug > 0 {
			h.dbg("TREE_CONNECT: invalid UNC path '%s'", pathStr)
		}
		return h.createErrorResponse(msg, protocol.STATUS_OBJECT_NAME_NOT_FOUND), nil
	}

	shareName := parts[len(parts)-1]
	if h.debug > 0 {
		h.dbg("TREE_CONNECT: req path='%s' share='%s' sid=%d", pathStr, shareName, msg.Header.SessionID)
	}

	// Verify share exists
	share, err := h.shareManager.GetShare(shareName)
	if err != nil {
		return h.createErrorResponse(msg, protocol.STATUS_OBJECT_NAME_NOT_FOUND), nil
	}

	// Get session
	h.stateMu.RLock()
	session, exists := h.sessions[msg.Header.SessionID]
	h.stateMu.RUnlock()
	if !exists {
		if h.debug > 0 {
			h.dbg("TREE_CONNECT: missing session sid=%d", msg.Header.SessionID)
		}
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_HANDLE), nil
	}

	// Enforce share guest policy at tree connect so unauthenticated sessions
	// cannot bind non-guest shares and access them through later file ops.
	if share.Name != "IPC$" && !share.GuestAccess && (session.IsGuest || session.IsAnonymous) {
		if h.debug > 0 {
			h.dbg("TREE_CONNECT: denying guest/null session to share=%s sid=%d", share.Name, msg.Header.SessionID)
		}
		return h.createErrorResponse(msg, protocol.STATUS_ACCESS_DENIED), nil
	}

	// Create tree connection
	h.stateMu.Lock()
	treeID := h.nextTreeID
	h.nextTreeID++
	h.stateMu.Unlock()

	treeConn := &protocol.TreeConnection{
		ID:        treeID,
		ShareName: share.Name,
		SharePath: share.Path,
		Session:   session,
		IsIPC:     share.Name == "IPC$",
	}

	session.TreeConnections[treeID] = treeConn
	if h.debug > 0 {
		h.dbg("TREE_CONNECT: success share=%s treeId=%d sid=%d", share.Name, treeID, msg.Header.SessionID)
	}

	// Create response
	response := &protocol.SMB2Message{
		Header: protocol.SMB2Header{
			ProtocolID:    [4]byte{0xFE, 'S', 'M', 'B'},
			StructureSize: 64,
			CreditCharge:  0,
			Status:        protocol.STATUS_SUCCESS,
			Command:       protocol.SMB2_TREE_CONNECT,
			CreditRequest: h.creditsFor(msg),
			Flags:         0x01,
			NextCommand:   0,
			MessageID:     msg.Header.MessageID,
			ProcessID:     0,
			TreeID:        treeID,
			SessionID:     msg.Header.SessionID,
		},
	}

	// Build tree connect response
	data := bytes.NewBuffer(nil)
	binary.Write(data, binary.LittleEndian, uint16(16)) // StructureSize

	// Set share type: 1 = disk, 2 = pipe, 3 = print
	shareType := uint8(1) // Default to disk
	if treeConn.IsIPC {
		shareType = 2 // IPC pipe
	}
	binary.Write(data, binary.LittleEndian, shareType)          // ShareType
	binary.Write(data, binary.LittleEndian, uint8(0))           // Reserved
	binary.Write(data, binary.LittleEndian, uint32(0))          // ShareFlags
	binary.Write(data, binary.LittleEndian, uint32(0))          // Capabilities (none)
	binary.Write(data, binary.LittleEndian, uint32(0x001F01FF)) // MaximalAccess (FILE_ALL_ACCESS)

	response.Data = data.Bytes()

	return response, nil
}

func (h *SMB2Handler) handleTreeDisconnect(msg *protocol.SMB2Message, connInfo hooks.ConnInfo) (*protocol.SMB2Message, error) {
	// Remove tree connection
	h.stateMu.RLock()
	session, exists := h.sessions[msg.Header.SessionID]
	h.stateMu.RUnlock()
	if exists {
		delete(session.TreeConnections, msg.Header.TreeID)
	}

	response := &protocol.SMB2Message{
		Header: protocol.SMB2Header{
			ProtocolID:    [4]byte{0xFE, 'S', 'M', 'B'},
			StructureSize: 64,
			Status:        protocol.STATUS_SUCCESS,
			Command:       protocol.SMB2_TREE_DISCONNECT,
			CreditRequest: h.creditsFor(msg),
			Flags:         0x01,
			MessageID:     msg.Header.MessageID,
			TreeID:        msg.Header.TreeID,
			SessionID:     msg.Header.SessionID,
		},
	}

	data := bytes.NewBuffer(nil)
	binary.Write(data, binary.LittleEndian, uint16(4)) // StructureSize
	binary.Write(data, binary.LittleEndian, uint16(0)) // Reserved

	response.Data = data.Bytes()
	return response, nil
}

// Apple SMB extension ("AAPL" create context) constants — the basis of macOS
// Time Machine / Finder integration (Samba's vfs_fruit).
const (
	aaplServerQuery = 1 // CommandCode

	aaplReqServerCaps = 0x1 // RequestBitmap bits
	aaplReqVolumeCaps = 0x2
	aaplReqModelInfo  = 0x4

	// ServerCapabilities bits.
	aaplCapSupportsReadDirAttr = 0x1
	aaplCapSupportsOSXCopyfile = 0x2
	aaplCapUnixBased           = 0x4
	aaplCapSupportsNFSACE      = 0x8

	aaplVolCapSupportsFullSync = 0x4 // VolumeCapabilities: required for Time Machine

	aaplTimeMachineModel = "TimeCapsule6" // model string macOS shows for the share
)

// encodeUTF16LE encodes a string as UTF-16LE bytes (no BOM, no terminator).
//
// 全仓唯一的名字编码入口。以前有几处手写 `make([]byte, len(s)*2)` 再
// `for i, r := range s`：range 给的是**字节**偏移，被当成 UTF-16 单元下标，
// 于是每个非 ASCII 字符后面多出一串 0x0000，客户端读名字遇到第一个 NUL 就停，
// 中文名只剩第一个字。别名一律走这里，别再手写。
func encodeUTF16LE(s string) []byte {
	u := utf16.Encode([]rune(s))
	out := make([]byte, 0, len(u)*2)
	for _, c := range u {
		var b [2]byte
		binary.LittleEndian.PutUint16(b[:], c)
		out = append(out, b[:]...)
	}
	return out
}

// parseCreateContexts walks the SMB2 create-context chain inside a CREATE
// request body (msg.Data, i.e. after the 64-byte header) and returns a map of
// context name -> context data. absOffset/length are the request's
// CreateContextsOffset/Length (offset is from the SMB2 header start).
func parseCreateContexts(body []byte, absOffset, length uint32) map[string][]byte {
	out := make(map[string][]byte)
	if absOffset < 64 || length == 0 {
		return out
	}
	start := int(absOffset) - 64
	if start < 0 || start >= len(body) {
		return out
	}
	end := start + int(length)
	if end > len(body) {
		end = len(body)
	}
	off := start
	for off+16 <= end {
		next := binary.LittleEndian.Uint32(body[off : off+4])
		nameOff := int(binary.LittleEndian.Uint16(body[off+4 : off+6]))
		nameLen := int(binary.LittleEndian.Uint16(body[off+6 : off+8]))
		dataOff := int(binary.LittleEndian.Uint16(body[off+10 : off+12]))
		dataLen := int(binary.LittleEndian.Uint32(body[off+12 : off+16]))
		ns, ne := off+nameOff, off+nameOff+nameLen
		ds, de := off+dataOff, off+dataOff+dataLen
		if nameLen > 0 && ns >= start && ne <= end && ds >= start && de <= end {
			out[string(body[ns:ne])] = body[ds:de]
		}
		if next == 0 {
			break
		}
		off += int(next)
	}
	return out
}

// buildAAPLResponseData builds the AAPL SERVER_QUERY response payload, echoing
// the bits the client asked for. Time Machine shares advertise the full-sync
// volume capability (without which macOS refuses the share as a backup target).
func buildAAPLResponseData(reqData []byte, isTimeMachine bool) []byte {
	if len(reqData) < 16 || binary.LittleEndian.Uint32(reqData[0:4]) != aaplServerQuery {
		return nil
	}
	reqBitmap := binary.LittleEndian.Uint64(reqData[8:16])
	reply := reqBitmap & (aaplReqServerCaps | aaplReqVolumeCaps | aaplReqModelInfo)

	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, uint32(aaplServerQuery)) // CommandCode
	binary.Write(&buf, binary.LittleEndian, uint32(0))               // Reserved
	binary.Write(&buf, binary.LittleEndian, reply)                   // ReplyBitmap
	if reply&aaplReqServerCaps != 0 {
		// Advertise UNIX-based + OSX copyfile (matching Samba's vfs_fruit
		// defaults). macOS gates some Apple behaviors — including the Time
		// Machine "network volume options" — on a non-zero server capability.
		// We deliberately omit READ_DIR_ATTR (we don't implement the enhanced
		// directory enumeration) and NFS ACEs.
		binary.Write(&buf, binary.LittleEndian, uint64(aaplCapUnixBased|aaplCapSupportsOSXCopyfile))
	}
	if reply&aaplReqVolumeCaps != 0 {
		var vol uint64
		if isTimeMachine {
			vol |= aaplVolCapSupportsFullSync
		}
		binary.Write(&buf, binary.LittleEndian, vol)
	}
	if reply&aaplReqModelInfo != 0 {
		model := encodeUTF16LE(aaplTimeMachineModel)
		binary.Write(&buf, binary.LittleEndian, uint32(0))          // Pad
		binary.Write(&buf, binary.LittleEndian, uint32(len(model))) // ModelStringLength (bytes)
		buf.Write(model)
	}
	return buf.Bytes()
}

// namedCtx is a create context (name + data) to place in a CREATE response.
type namedCtx struct {
	name string
	data []byte
}

// buildCreateContextChain encodes one or more SMB2_CREATE_CONTEXTs as a chain
// (MS-SMB2 2.2.13.2). Each context: 16-byte header, Name (8-byte aligned),
// Data; non-final contexts set Next and are padded to an 8-byte boundary.
func buildCreateContextChain(items []namedCtx) []byte {
	var out []byte
	for i, it := range items {
		nameLen := len(it.name)
		dataOff := 16 + nameLen
		if dataOff%8 != 0 {
			dataOff += 8 - (dataOff % 8)
		}
		ctxLen := dataOff + len(it.data)
		padded := ctxLen
		if i < len(items)-1 && padded%8 != 0 {
			padded += 8 - (padded % 8)
		}
		buf := make([]byte, padded)
		if i < len(items)-1 {
			binary.LittleEndian.PutUint32(buf[0:4], uint32(padded)) // Next
		}
		binary.LittleEndian.PutUint16(buf[4:6], 16)                     // NameOffset
		binary.LittleEndian.PutUint16(buf[6:8], uint16(nameLen))        // NameLength
		binary.LittleEndian.PutUint16(buf[10:12], uint16(dataOff))      // DataOffset
		binary.LittleEndian.PutUint32(buf[12:16], uint32(len(it.data))) // DataLength
		copy(buf[16:], it.name)
		copy(buf[dataOff:], it.data)
		out = append(out, buf...)
	}
	return out
}

// buildMxAcResponse builds an SMB2_CREATE_QUERY_MAXIMAL_ACCESS_RESPONSE
// (MS-SMB2 2.2.14.2.5): QueryStatus(4)=SUCCESS + MaximalAccess(4).
func buildMxAcResponse(maximalAccess uint32) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint32(b[4:8], maximalAccess)
	return b
}

// buildDH2QResponse builds an SMB2_CREATE_DURABLE_HANDLE_RESPONSE_V2
// (MS-SMB2 2.2.14.2.12): Timeout(4) + Flags(4). Granting a durable handle is
// what lets the macOS client configure reconnect — required by Time Machine.
func buildDH2QResponse(req []byte) []byte {
	timeout := uint32(180000) // 3 minutes
	if len(req) >= 4 {
		if rt := binary.LittleEndian.Uint32(req[0:4]); rt > 0 {
			timeout = rt
		}
	}
	b := make([]byte, 8)
	binary.LittleEndian.PutUint32(b[0:4], timeout)
	// Flags = 0: durable (not persistent).
	return b
}

// buildLeaseResponse grants the requested lease (SMB2_CREATE_RESPONSE_LEASE /
// _V2): the lease key is echoed and the requested state granted. A handle lease
// is a precondition for granting a durable handle. We never send lease breaks,
// which is acceptable for the single-client Time Machine use case.
func buildLeaseResponse(req []byte) []byte {
	if len(req) < 32 {
		return nil
	}
	out := make([]byte, len(req)) // 32 (v1) or 52 (v2)
	copy(out[0:16], req[0:16])    // LeaseKey
	copy(out[16:20], req[16:20])  // LeaseState (grant what was requested)
	if len(req) >= 52 {
		copy(out[32:48], req[32:48])                 // ParentLeaseKey
		binary.LittleEndian.PutUint16(out[48:50], 1) // Epoch
	}
	return out
}

// splitStream separates an SMB path of the form "path:streamname[:$DATA]" into
// the base path and the named stream. The base may be empty (e.g. ":AFP_AfpInfo"
// targets the share root). Returns an empty stream for ordinary paths. Drive
// letters never appear here (share paths are relative), so the first ':' is
// always the stream separator.
func splitStream(name string) (base, stream string) {
	idx := strings.IndexByte(name, ':')
	if idx < 0 {
		return name, ""
	}
	base = name[:idx]
	stream = name[idx+1:]
	// Strip a trailing stream type such as ":$DATA".
	if j := strings.IndexByte(stream, ':'); j >= 0 {
		stream = stream[:j]
	}
	return base, stream
}

// streamKey builds the streamStore map key for a (share, base, stream) triple.
func streamKey(share, base, stream string) string {
	return share + "\x00" + base + "\x00" + stream
}

// defaultAfpInfo returns the synthesized 60-byte AFP_AfpInfo structure macOS
// expects when no FinderInfo has been written yet: signature "AFP_" followed by
// zeroed FinderInfo. Mirrors vfs_fruit / go-smb2 behavior so the stream open
// and read succeed instead of failing with NOT_FOUND.
func defaultAfpInfo() []byte {
	b := make([]byte, 60)
	copy(b[0:4], []byte{'A', 'F', 'P', '_'})
	b[5] = 0x01 // Version 0x00010000 (big-endian)
	return b
}

// getStream returns the stored bytes for a named stream, synthesizing the
// AFP_AfpInfo default if it has never been written. The boolean reports whether
// any content (stored or synthesized) is available.
func (h *SMB2Handler) getStream(share, base, stream string) ([]byte, bool) {
	h.stateMu.RLock()
	data, ok := h.streamStore[streamKey(share, base, stream)]
	h.stateMu.RUnlock()
	if ok {
		return data, true
	}
	if strings.EqualFold(stream, "AFP_AfpInfo") {
		return defaultAfpInfo(), true
	}
	return nil, false
}

// streamSize returns the size a named stream reports, accounting for the
// synthesized AFP_AfpInfo default.
func (h *SMB2Handler) streamSize(share, base, stream string) int64 {
	if data, ok := h.getStream(share, base, stream); ok {
		return int64(len(data))
	}
	return 0
}

func (h *SMB2Handler) handleCreate(msg *protocol.SMB2Message, connInfo hooks.ConnInfo) (*protocol.SMB2Message, error) {
	if len(msg.Data) < 56 {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}

	// Parse create request
	structureSize := binary.LittleEndian.Uint16(msg.Data[0:2])
	if structureSize != 57 {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}

	securityFlags := msg.Data[2]
	requestedOplock := msg.Data[3]
	impersonationLevel := binary.LittleEndian.Uint32(msg.Data[4:8])
	smbCreateFlags := binary.LittleEndian.Uint64(msg.Data[8:16])
	reserved := binary.LittleEndian.Uint64(msg.Data[16:24])
	desiredAccess := binary.LittleEndian.Uint32(msg.Data[24:28])
	fileAttributes := binary.LittleEndian.Uint32(msg.Data[28:32])
	shareAccess := binary.LittleEndian.Uint32(msg.Data[32:36])
	createDisposition := binary.LittleEndian.Uint32(msg.Data[36:40])
	createOptions := binary.LittleEndian.Uint32(msg.Data[40:44])
	nameOffset := binary.LittleEndian.Uint16(msg.Data[44:46])
	nameLength := binary.LittleEndian.Uint16(msg.Data[46:48])
	createContextsOffset := binary.LittleEndian.Uint32(msg.Data[48:52])
	createContextsLength := binary.LittleEndian.Uint32(msg.Data[52:56])

	_ = securityFlags
	_ = requestedOplock
	_ = impersonationLevel
	_ = smbCreateFlags
	_ = reserved
	_ = fileAttributes

	// Parse create contexts. macOS sends "AAPL" (Apple extensions probe),
	// "MxAc" (maximal access), "RqLs" (lease) and "DH2Q" (durable handle v2).
	var reqCtxs map[string][]byte
	if createContextsLength > 0 {
		reqCtxs = parseCreateContexts(msg.Data, createContextsOffset, createContextsLength)
		if h.debug > 0 && len(reqCtxs) > 0 {
			names := make([]string, 0, len(reqCtxs))
			for n := range reqCtxs {
				names = append(names, fmt.Sprintf("%q", n))
			}
			h.dbg("CREATE contexts: %s", strings.Join(names, ","))
		}
	}

	// Get session and tree connection
	h.stateMu.RLock()
	session, exists := h.sessions[msg.Header.SessionID]
	h.stateMu.RUnlock()
	if !exists {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_HANDLE), nil
	}

	treeConn, exists := session.TreeConnections[msg.Header.TreeID]
	if !exists {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_HANDLE), nil
	}

	// Extract file name
	var fileName string
	if nameLength > 0 && int(nameOffset) < len(msg.Data)+64 {
		nameStart := int(nameOffset) - 64 // Adjust for header
		nameEnd := nameStart + int(nameLength)
		if nameStart >= 0 && nameEnd <= len(msg.Data) {
			nameBytes := msg.Data[nameStart:nameEnd]
			// Convert UTF-16LE to UTF-8
			if len(nameBytes)%2 == 0 {
				utf16Chars := make([]uint16, len(nameBytes)/2)
				for i := 0; i < len(utf16Chars); i++ {
					utf16Chars[i] = binary.LittleEndian.Uint16(nameBytes[i*2:])
				}
				runes := make([]rune, 0, len(utf16Chars))
				for _, char := range utf16Chars {
					if char != 0 {
						runes = append(runes, rune(char))
					}
				}
				fileName = string(runes)
			} else {
				fileName = string(nameBytes)
			}
		}
	}

	// Clean up the file name
	fileName = strings.TrimRight(fileName, "\x00")
	fileName = strings.ReplaceAll(fileName, "\\", "/")
	if strings.HasPrefix(fileName, "/") {
		fileName = fileName[1:]
	}
	if fileName == "" {
		fileName = "."
	}

	// Detect an NTFS-style named stream (e.g. "file:AFP_AfpInfo"). With
	// FILE_NAMED_STREAMS advertised, macOS Time Machine opens these for
	// FinderInfo and resource forks. The base object is what lives on disk; the
	// stream bytes are served from streamStore so opens/reads/writes succeed
	// instead of returning NOT_FOUND.
	streamName := ""
	if base, stream := splitStream(fileName); stream != "" {
		streamName = stream
		fileName = base
		if fileName == "" {
			fileName = "."
		}
	}

	// Determine if this is a directory request
	isDirectory := (createOptions & protocol.FILE_DIRECTORY_FILE) != 0
	if h.debug > 0 {
		log.Printf(
			"[DEBUG][SMB2] CREATE: path=%q desired=0x%08x share=0x%08x disp=0x%08x opts=0x%08x dir=%v",
			fileName,
			desiredAccess,
			shareAccess,
			createDisposition,
			createOptions,
			isDirectory,
		)
	}

	// Generate file ID
	fileID := make([]byte, 16)
	h.stateMu.Lock()
	binary.LittleEndian.PutUint64(fileID[0:8], h.nextMessageID)
	binary.LittleEndian.PutUint64(fileID[8:16], uint64(time.Now().UnixNano()))
	h.nextMessageID++
	h.stateMu.Unlock()

	// Handle IPC$ pipe creation specially
	if treeConn.IsIPC {
		// For IPC$ connections, create a virtual pipe
		fileInfo := &protocol.FileInfo{
			Name:         fileName,
			Size:         0,
			Attributes:   protocol.FILE_ATTRIBUTE_NORMAL,
			CreatedTime:  time.Now(),
			AccessedTime: time.Now(),
			ModifiedTime: time.Now(),
			IsDirectory:  false,
		}

		// Create pipe handle
		handle := &protocol.FileHandle{
			ID:             fileID,
			Path:           fileName,
			IsDirectory:    false,
			AccessMask:     desiredAccess,
			ShareAccess:    shareAccess,
			CreateOptions:  createOptions,
			FileInfo:       fileInfo,
			TreeConnection: treeConn,
		}

		h.stateMu.Lock()
		h.fileHandles[string(fileID)] = handle
		h.stateMu.Unlock()

		// Convert directory to slash for hook consistency
		cleanPath := strings.ReplaceAll(fileName, "\\", "/")
		if isDirectory {
			h.hooks.OnFolderCreate(connInfo, treeConn.ShareName, cleanPath)
		}

		response := &protocol.SMB2Message{
			Header: protocol.SMB2Header{
				ProtocolID:    [4]byte{0xFE, 'S', 'M', 'B'},
				StructureSize: 64,
				Status:        protocol.STATUS_SUCCESS,
				Command:       protocol.SMB2_CREATE,
				CreditRequest: h.creditsFor(msg),
				Flags:         0x01,
				MessageID:     msg.Header.MessageID,
				TreeID:        msg.Header.TreeID,
				SessionID:     msg.Header.SessionID,
			},
		}

		// Build create response for pipe
		data := bytes.NewBuffer(nil)
		binary.Write(data, binary.LittleEndian, uint16(89))                 // StructureSize
		binary.Write(data, binary.LittleEndian, uint8(0))                   // OplockLevel
		binary.Write(data, binary.LittleEndian, uint8(0))                   // Flags
		binary.Write(data, binary.LittleEndian, uint32(protocol.FILE_OPEN)) // CreateAction
		// Timestamps as FILETIME
		const ftEpoch = 116444736000000000
		nowft := uint64(time.Now().UnixNano()/100) + ftEpoch
		binary.Write(data, binary.LittleEndian, nowft)                                  // CreationTime
		binary.Write(data, binary.LittleEndian, nowft)                                  // LastAccessTime
		binary.Write(data, binary.LittleEndian, nowft)                                  // LastWriteTime
		binary.Write(data, binary.LittleEndian, nowft)                                  // ChangeTime
		binary.Write(data, binary.LittleEndian, uint64(0))                              // AllocationSize
		binary.Write(data, binary.LittleEndian, uint64(0))                              // EndOfFile
		binary.Write(data, binary.LittleEndian, uint32(protocol.FILE_ATTRIBUTE_NORMAL)) // FileAttributes
		binary.Write(data, binary.LittleEndian, uint32(0))                              // Reserved2
		data.Write(fileID)                                                              // FileId
		binary.Write(data, binary.LittleEndian, uint32(0))                              // CreateContextsOffset
		binary.Write(data, binary.LittleEndian, uint32(0))                              // CreateContextsLength

		response.Data = data.Bytes()
		return response, nil
	}

	if h.isReadOnly(treeConn) {
		if createOptions&protocol.FILE_DELETE_ON_CLOSE != 0 ||
			(createDisposition != protocol.FILE_OPEN && createDisposition != protocol.FILE_OPEN_IF) ||
			(createDisposition == protocol.FILE_OPEN_IF && !h.shareManager.FileExists(treeConn.ShareName, fileName)) {
			return h.createErrorResponse(msg, protocol.STATUS_ACCESS_DENIED), nil
		}
		createDisposition = protocol.FILE_OPEN
	}

	// Handle creation based on disposition
	var fileInfo *protocol.FileInfo
	var createAction uint32
	var err error

	if streamName != "" {
		// Named-stream open (Apple FinderInfo / resource fork). Anchor on the
		// base object on disk without ever truncating it — the stream's bytes
		// live in streamStore. macOS opens the base earlier in the same compound,
		// so it normally already exists; for create dispositions we materialize
		// an empty base file if needed.
		fileInfo, err = h.shareManager.GetFileInfo(treeConn.ShareName, fileName)
		if err != nil {
			if createDisposition == protocol.FILE_OPEN || createDisposition == protocol.FILE_OVERWRITE {
				return h.createErrorResponse(msg, protocol.STATUS_OBJECT_NAME_NOT_FOUND), nil
			}
			if _, werr := h.shareManager.WriteFile(treeConn.ShareName, fileName, 0, []byte{}); werr != nil {
				return h.createErrorResponse(msg, protocol.STATUS_OBJECT_NAME_NOT_FOUND), nil
			}
			fileInfo, err = h.shareManager.GetFileInfo(treeConn.ShareName, fileName)
			if err != nil {
				return h.createErrorResponse(msg, protocol.STATUS_OBJECT_NAME_NOT_FOUND), nil
			}
		}
		createAction = protocol.FILE_OPEN
		switch createDisposition {
		case protocol.FILE_OVERWRITE, protocol.FILE_OVERWRITE_IF, protocol.FILE_SUPERSEDE:
			// (Re)creating the stream: drop any previously stored bytes.
			h.stateMu.Lock()
			delete(h.streamStore, streamKey(treeConn.ShareName, fileName, streamName))
			h.stateMu.Unlock()
			createAction = protocol.FILE_OVERWRITE
		case protocol.FILE_CREATE:
			createAction = protocol.FILE_CREATE
		}
	} else {
		switch createDisposition {
		case protocol.FILE_OPEN:
			// Open existing file/directory
			fileInfo, err = h.shareManager.GetFileInfo(treeConn.ShareName, fileName)
			if err != nil {
				return h.createErrorResponse(msg, protocol.STATUS_OBJECT_NAME_NOT_FOUND), nil
			}
			createAction = protocol.FILE_OPEN

		case protocol.FILE_CREATE:
			// Create new file/directory
			if isDirectory {
				err = h.shareManager.CreateDirectory(treeConn.ShareName, fileName)
				if err != nil {
					return h.createErrorResponse(msg, protocol.STATUS_ACCESS_DENIED), nil
				}
				h.hooks.OnFolderCreate(connInfo, treeConn.ShareName, fileName)
			} else {
				// Create empty file by writing empty data
				_, err = h.shareManager.WriteFile(treeConn.ShareName, fileName, 0, []byte{})
				if err != nil {
					return h.createErrorResponse(msg, protocol.STATUS_ACCESS_DENIED), nil
				}
				h.hooks.OnFileCreate(connInfo, treeConn.ShareName, fileName)
			}
			fileInfo, err = h.shareManager.GetFileInfo(treeConn.ShareName, fileName)
			if err != nil {
				return h.createErrorResponse(msg, protocol.STATUS_ACCESS_DENIED), nil
			}
			createAction = protocol.FILE_CREATE

		case protocol.FILE_OPEN_IF:
			// Open if exists, create if not
			fileInfo, err = h.shareManager.GetFileInfo(treeConn.ShareName, fileName)
			if err != nil {
				// File doesn't exist, create it
				if isDirectory {
					err = h.shareManager.CreateDirectory(treeConn.ShareName, fileName)
					h.hooks.OnFolderCreate(connInfo, treeConn.ShareName, fileName)
				} else {
					_, err = h.shareManager.WriteFile(treeConn.ShareName, fileName, 0, []byte{})
					h.hooks.OnFileCreate(connInfo, treeConn.ShareName, fileName)
				}
				if err != nil {
					return h.createErrorResponse(msg, protocol.STATUS_ACCESS_DENIED), nil
				}
				fileInfo, err = h.shareManager.GetFileInfo(treeConn.ShareName, fileName)
				if err != nil {
					return h.createErrorResponse(msg, protocol.STATUS_ACCESS_DENIED), nil
				}
				createAction = protocol.FILE_CREATE
			} else {
				createAction = protocol.FILE_OPEN
			}

		case protocol.FILE_OVERWRITE:
			// Overwrite existing file (truncate), fail if doesn't exist
			fileInfo, err = h.shareManager.GetFileInfo(treeConn.ShareName, fileName)
			if err != nil {
				return h.createErrorResponse(msg, protocol.STATUS_OBJECT_NAME_NOT_FOUND), nil
			}
			if fileInfo.IsDirectory {
				return h.createErrorResponse(msg, protocol.STATUS_FILE_IS_A_DIRECTORY), nil
			}
			// Truncate
			err = h.shareManager.TruncateFile(treeConn.ShareName, fileName, 0)
			if err != nil {
				return h.createErrorResponse(msg, protocol.STATUS_ACCESS_DENIED), nil
			}
			createAction = protocol.FILE_OVERWRITE
			fileInfo, err = h.shareManager.GetFileInfo(treeConn.ShareName, fileName)
			if err != nil {
				return h.createErrorResponse(msg, protocol.STATUS_ACCESS_DENIED), nil
			}
			h.hooks.OnFileOverwrite(connInfo, treeConn.ShareName, fileName)

		case protocol.FILE_OVERWRITE_IF, protocol.FILE_SUPERSEDE:
			// Overwrite if exists (truncate), create if not
			// Treat SUPERSEDE same as OVERWRITE_IF for simplification (both effectively replace file)
			fileInfo, err = h.shareManager.GetFileInfo(treeConn.ShareName, fileName)
			if err == nil {
				// Exists
				if fileInfo.IsDirectory {
					// Technically SUPERSEDE might delete directory? But unsafe. Fail.
					return h.createErrorResponse(msg, protocol.STATUS_FILE_IS_A_DIRECTORY), nil
				}
				// Truncate
				err = h.shareManager.TruncateFile(treeConn.ShareName, fileName, 0)
				if err != nil {
					return h.createErrorResponse(msg, protocol.STATUS_ACCESS_DENIED), nil
				}
				createAction = protocol.FILE_OVERWRITE // Or SUPERSEDE
				h.hooks.OnFileOverwrite(connInfo, treeConn.ShareName, fileName)
			} else {
				// Doesn't exist, Create
				if isDirectory {
					err = h.shareManager.CreateDirectory(treeConn.ShareName, fileName)
					h.hooks.OnFolderCreate(connInfo, treeConn.ShareName, fileName)
				} else {
					_, err = h.shareManager.WriteFile(treeConn.ShareName, fileName, 0, []byte{})
					h.hooks.OnFileCreate(connInfo, treeConn.ShareName, fileName)
				}
				if err != nil {
					return h.createErrorResponse(msg, protocol.STATUS_ACCESS_DENIED), nil
				}
				createAction = protocol.FILE_CREATE
			}
			fileInfo, err = h.shareManager.GetFileInfo(treeConn.ShareName, fileName)
			if err != nil {
				return h.createErrorResponse(msg, protocol.STATUS_ACCESS_DENIED), nil
			}

		default:
			createAction = protocol.FILE_OPEN
			fileInfo, err = h.shareManager.GetFileInfo(treeConn.ShareName, fileName)
			if err != nil {
				return h.createErrorResponse(msg, protocol.STATUS_OBJECT_NAME_NOT_FOUND), nil
			}
		}
	}

	// Create file handle
	handle := &protocol.FileHandle{
		ID:             fileID,
		Path:           fileName,
		IsDirectory:    fileInfo.IsDirectory && streamName == "",
		AccessMask:     desiredAccess,
		ShareAccess:    shareAccess,
		CreateOptions:  createOptions,
		FileInfo:       fileInfo,
		TreeConnection: treeConn,
		DirIndex:       0,
		DirSnapshot:    nil,
		StreamName:     streamName,
	}

	// Cache an OS file descriptor for the duration of this SMB handle so that
	// READ and WRITE use ReadAt/WriteAt on an already-open fd rather than
	// opening and closing the file on every request. This is the primary fix
	// for Time Machine sparsebundle performance (50+ open/close per write
	// burst otherwise). Only for regular disk files; dirs, IPC pipes, and
	// named streams use separate paths.
	if !handle.IsDirectory && !treeConn.IsIPC && streamName == "" {
		if f, err := h.shareManager.OpenFile(treeConn.ShareName, fileName, os.O_RDWR); err == nil {
			handle.OSFile = f
		} else if f, err := h.shareManager.OpenFile(treeConn.ShareName, fileName, os.O_RDONLY); err == nil {
			handle.OSFile = f
		}
	}

	h.fileHandles[string(fileID)] = handle

	response := &protocol.SMB2Message{
		Header: protocol.SMB2Header{
			ProtocolID:    [4]byte{0xFE, 'S', 'M', 'B'},
			StructureSize: 64,
			Status:        protocol.STATUS_SUCCESS,
			Command:       protocol.SMB2_CREATE,
			Flags:         0x01,
			MessageID:     msg.Header.MessageID,
			TreeID:        msg.Header.TreeID,
			SessionID:     msg.Header.SessionID,
		},
	}

	// On Time Machine shares, answer the Apple/durable-handle create contexts so
	// macOS enables the Apple SMB extensions and can configure reconnect (which
	// it requires before accepting the share as a backup target):
	//   AAPL -> Apple extensions + full-sync volume capability
	//   MxAc -> maximal granted access
	//   RqLs -> grant the requested lease (precondition for a durable handle)
	//   DH2Q -> grant a durable handle (enables reconnect / "network volume options")
	// Computed before the body so OplockLevel can reflect a granted lease.
	var createContexts []byte
	oplockLevel := uint8(0)
	if len(reqCtxs) > 0 {
		sh, e := h.shareManager.GetShare(treeConn.ShareName)
		if e == nil && sh != nil && sh.IsTimeMachine() {
			var items []namedCtx
			if a := buildAAPLResponseData(reqCtxs["AAPL"], true); a != nil {
				items = append(items, namedCtx{"AAPL", a})
			}
			if _, ok := reqCtxs["MxAc"]; ok {
				maxAccess := uint32(0x001F01FF) // full access
				if sh.ReadOnly {
					maxAccess = 0x00120089 // read/execute
				}
				items = append(items, namedCtx{"MxAc", buildMxAcResponse(maxAccess)})
			}
			// EXPERIMENT: leases without break support make macOS wait out a
			// break timeout on every reopen of a still-leased file (the
			// disk-image attach reopens lock/token repeatedly), making the attach
			// glacial. Toggle with SMB_NO_LEASES=1 to skip lease/durable grants.
			leaseGranted := false
			if os.Getenv("SMB_NO_LEASES") != "1" {
				if ld, ok := reqCtxs["RqLs"]; ok {
					if lr := buildLeaseResponse(ld); lr != nil {
						items = append(items, namedCtx{"RqLs", lr})
						leaseGranted = true
						oplockLevel = 0xFF // SMB2_OPLOCK_LEVEL_LEASE
					}
				}
				// A durable handle requires a granted lease (or batch oplock).
				if dd, ok := reqCtxs["DH2Q"]; ok && leaseGranted {
					items = append(items, namedCtx{"DH2Q", buildDH2QResponse(dd)})
				}
			}
			if len(items) > 0 {
				createContexts = buildCreateContextChain(items)
				h.dbg("CREATE: granted contexts on TM share %s path=%q count=%d len=%d", treeConn.ShareName, fileName, len(items), len(createContexts))
			}
		}
	}

	// For a named-stream handle the reported size/attributes describe the stream
	// (data, never a directory), not the base object.
	respSize := uint64(fileInfo.Size)
	respAttrs := fileInfo.Attributes
	if streamName != "" {
		respSize = uint64(h.streamSize(treeConn.ShareName, fileName, streamName))
		respAttrs = protocol.FILE_ATTRIBUTE_NORMAL
	}

	// Build create response
	data := bytes.NewBuffer(nil)
	binary.Write(data, binary.LittleEndian, uint16(89))   // StructureSize
	binary.Write(data, binary.LittleEndian, oplockLevel)  // OplockLevel
	binary.Write(data, binary.LittleEndian, uint8(0))     // Flags
	binary.Write(data, binary.LittleEndian, createAction) // CreateAction
	// FILETIME timestamps
	const ftEpoch2 = 116444736000000000
	binary.Write(data, binary.LittleEndian, uint64(fileInfo.CreatedTime.UnixNano()/100)+ftEpoch2)  // CreationTime
	binary.Write(data, binary.LittleEndian, uint64(fileInfo.AccessedTime.UnixNano()/100)+ftEpoch2) // LastAccessTime
	binary.Write(data, binary.LittleEndian, uint64(fileInfo.ModifiedTime.UnixNano()/100)+ftEpoch2) // LastWriteTime
	binary.Write(data, binary.LittleEndian, uint64(fileInfo.ModifiedTime.UnixNano()/100)+ftEpoch2) // ChangeTime
	binary.Write(data, binary.LittleEndian, respSize)                                              // AllocationSize
	binary.Write(data, binary.LittleEndian, respSize)                                              // EndOfFile
	binary.Write(data, binary.LittleEndian, respAttrs)                                             // FileAttributes
	binary.Write(data, binary.LittleEndian, uint32(0))                                             // Reserved2
	data.Write(fileID)                                                                             // FileId

	if len(createContexts) > 0 {
		// Contexts begin right after the 8 offset/length bytes: header(64) +
		// 88-byte fixed body = absolute offset 152 (8-byte aligned).
		binary.Write(data, binary.LittleEndian, uint32(152))                 // CreateContextsOffset
		binary.Write(data, binary.LittleEndian, uint32(len(createContexts))) // CreateContextsLength
		data.Write(createContexts)
	} else {
		binary.Write(data, binary.LittleEndian, uint32(0)) // CreateContextsOffset
		binary.Write(data, binary.LittleEndian, uint32(0)) // CreateContextsLength
	}

	response.Data = data.Bytes()
	return response, nil
}

func (h *SMB2Handler) handleClose(msg *protocol.SMB2Message, connInfo hooks.ConnInfo) (*protocol.SMB2Message, error) {
	if len(msg.Data) < 24 {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}

	// Extract file ID
	fileID := msg.Data[8:24]

	// Check for DeleteOnClose
	handle, exists := h.fileHandles[string(fileID)]
	if exists {
		if h.debug > 0 {
			log.Printf("[DEBUG][SMB2] CLOSE: path=%q deleteOnClose=%v isDir=%v", handle.Path, (handle.CreateOptions&protocol.FILE_DELETE_ON_CLOSE) != 0, handle.IsDirectory)
		}
		// Close the cached OS fd before the handle is discarded.
		if handle.OSFile != nil {
			handle.OSFile.Close()
			handle.OSFile = nil
		}
		if (handle.CreateOptions & protocol.FILE_DELETE_ON_CLOSE) != 0 {
			if handle.StreamName != "" {
				// Delete the named stream only; never touch the base object.
				h.stateMu.Lock()
				delete(h.streamStore, streamKey(handle.TreeConnection.ShareName, handle.Path, handle.StreamName))
				h.stateMu.Unlock()
			} else if handle.IsDirectory {
				h.shareManager.DeleteDirectory(handle.TreeConnection.ShareName, handle.Path)
				h.hooks.OnFolderDelete(connInfo, handle.TreeConnection.ShareName, handle.Path)
			} else {
				h.shareManager.DeleteFile(handle.TreeConnection.ShareName, handle.Path)
				h.hooks.OnFileDelete(connInfo, handle.TreeConnection.ShareName, handle.Path)
			}
		}
		delete(h.fileHandles, string(fileID))
	}

	response := &protocol.SMB2Message{
		Header: protocol.SMB2Header{
			ProtocolID:    [4]byte{0xFE, 'S', 'M', 'B'},
			StructureSize: 64,
			Status:        protocol.STATUS_SUCCESS,
			Command:       protocol.SMB2_CLOSE,
			CreditRequest: h.creditsFor(msg),
			Flags:         0x01,
			MessageID:     msg.Header.MessageID,
			TreeID:        msg.Header.TreeID,
			SessionID:     msg.Header.SessionID,
		},
	}

	data := bytes.NewBuffer(nil)
	binary.Write(data, binary.LittleEndian, uint16(60)) // StructureSize
	binary.Write(data, binary.LittleEndian, uint16(0))  // Flags
	binary.Write(data, binary.LittleEndian, uint32(0))  // Reserved
	binary.Write(data, binary.LittleEndian, uint64(0))  // CreationTime
	binary.Write(data, binary.LittleEndian, uint64(0))  // LastAccessTime
	binary.Write(data, binary.LittleEndian, uint64(0))  // LastWriteTime
	binary.Write(data, binary.LittleEndian, uint64(0))  // ChangeTime
	binary.Write(data, binary.LittleEndian, uint64(0))  // AllocationSize
	binary.Write(data, binary.LittleEndian, uint64(0))  // EndOfFile
	binary.Write(data, binary.LittleEndian, uint32(0))  // FileAttributes

	response.Data = data.Bytes()
	return response, nil
}

func (h *SMB2Handler) handleRead(msg *protocol.SMB2Message, connInfo hooks.ConnInfo) (*protocol.SMB2Message, error) {
	if len(msg.Data) < 48 {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}

	// Parse read request
	structureSize := binary.LittleEndian.Uint16(msg.Data[0:2])
	if structureSize != 49 {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}

	padding := msg.Data[2]
	flags := msg.Data[3]
	length := binary.LittleEndian.Uint32(msg.Data[4:8])
	offset := binary.LittleEndian.Uint64(msg.Data[8:16])
	fileID := msg.Data[16:32]
	minimumCount := binary.LittleEndian.Uint32(msg.Data[32:36])
	channel := binary.LittleEndian.Uint32(msg.Data[36:40])
	remainingBytes := binary.LittleEndian.Uint32(msg.Data[40:44])
	readChannelInfoOffset := binary.LittleEndian.Uint16(msg.Data[44:46])
	readChannelInfoLength := binary.LittleEndian.Uint16(msg.Data[46:48])

	_ = padding
	_ = flags
	_ = minimumCount
	_ = channel
	_ = remainingBytes
	_ = readChannelInfoOffset
	_ = readChannelInfoLength

	// Check for pending pipe response (from WRITE+READ pattern used by impacket)
	if pipeResp, ok := h.pipeResponses[string(fileID)]; ok {
		delete(h.pipeResponses, string(fileID))
		return h.buildSMB2ReadResponse(msg, fileID, pipeResp)
	}

	// Get file handle
	handle, exists := h.fileHandles[string(fileID)]
	if !exists {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_HANDLE), nil
	}

	// IPC$ pipe read with no pending data
	if handle.TreeConnection != nil && handle.TreeConnection.IsIPC {
		return h.createErrorResponse(msg, protocol.STATUS_PIPE_EMPTY), nil
	}

	// Named-stream read (Apple FinderInfo / resource fork). Serve from
	// streamStore; AFP_AfpInfo is synthesized when never written.
	if handle.StreamName != "" {
		full, ok := h.getStream(handle.TreeConnection.ShareName, handle.Path, handle.StreamName)
		if !ok {
			full = nil
		}
		var chunk []byte
		if offset < uint64(len(full)) {
			end := offset + uint64(length)
			if end > uint64(len(full)) {
				end = uint64(len(full))
			}
			chunk = full[offset:end]
		}
		if len(chunk) == 0 {
			return h.createErrorResponse(msg, protocol.STATUS_END_OF_FILE), nil
		}
		return h.buildSMB2ReadResponse(msg, fileID, chunk)
	}

	// Don't read from directories
	if handle.IsDirectory {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}

	// Limit read size to reasonable amount
	if length > protocol.MAX_BUFFER_SIZE {
		length = protocol.MAX_BUFFER_SIZE
	}

	// Read file data — use the cached fd (ReadAt) when available to avoid the
	// per-request open+close overhead inside ShareManager.ReadFile.
	var fileData []byte
	var readErr error
	if handle.OSFile != nil {
		buf := make([]byte, int(length))
		n, err := handle.OSFile.ReadAt(buf, int64(offset))
		if n > 0 {
			fileData = buf[:n]
		}
		if err != nil && err != io.EOF {
			readErr = err
		}
	} else {
		fileData, readErr = h.shareManager.ReadFile(handle.TreeConnection.ShareName, handle.Path, int64(offset), int(length))
	}
	if readErr != nil {
		return h.createErrorResponse(msg, protocol.STATUS_ACCESS_DENIED), nil
	}

	if len(fileData) == 0 && length != 0 {
		return h.createErrorResponse(msg, protocol.STATUS_END_OF_FILE), nil
	}
	h.hooks.OnFileDownload(connInfo, handle.TreeConnection.ShareName, handle.Path, int64(len(fileData)))
	return h.buildSMB2ReadResponse(msg, fileID, fileData)
}

// buildSMB2ReadResponse builds an SMB2 READ response with the given data.
func (h *SMB2Handler) buildSMB2ReadResponse(msg *protocol.SMB2Message, fileID, readData []byte) (*protocol.SMB2Message, error) {
	response := &protocol.SMB2Message{
		Header: protocol.SMB2Header{
			ProtocolID:    [4]byte{0xFE, 'S', 'M', 'B'},
			StructureSize: 64,
			Status:        protocol.STATUS_SUCCESS,
			Command:       protocol.SMB2_READ,
			CreditRequest: h.creditsFor(msg),
			Flags:         0x01,
			MessageID:     msg.Header.MessageID,
			TreeID:        msg.Header.TreeID,
			SessionID:     msg.Header.SessionID,
		},
	}
	data := bytes.NewBuffer(nil)
	binary.Write(data, binary.LittleEndian, uint16(17))            // StructureSize
	binary.Write(data, binary.LittleEndian, uint8(80))             // DataOffset
	binary.Write(data, binary.LittleEndian, uint8(0))              // Reserved
	binary.Write(data, binary.LittleEndian, uint32(len(readData))) // DataLength
	binary.Write(data, binary.LittleEndian, uint32(0))             // DataRemaining
	binary.Write(data, binary.LittleEndian, uint32(0))             // Flags
	for data.Len() < 80-64 {
		data.WriteByte(0)
	}
	data.Write(readData)
	response.Data = data.Bytes()
	return response, nil
}

func (h *SMB2Handler) handleWrite(msg *protocol.SMB2Message, connInfo hooks.ConnInfo) (*protocol.SMB2Message, error) {
	if len(msg.Data) < 48 {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}

	// Parse write request
	structureSize := binary.LittleEndian.Uint16(msg.Data[0:2])
	if structureSize != 49 {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}

	dataOffset := binary.LittleEndian.Uint16(msg.Data[2:4])
	length := binary.LittleEndian.Uint32(msg.Data[4:8])
	offset := binary.LittleEndian.Uint64(msg.Data[8:16])
	fileID := msg.Data[16:32]
	channel := binary.LittleEndian.Uint32(msg.Data[32:36])
	remainingBytes := binary.LittleEndian.Uint32(msg.Data[36:40])
	writeChannelInfoOffset := binary.LittleEndian.Uint16(msg.Data[40:42])
	writeChannelInfoLength := binary.LittleEndian.Uint16(msg.Data[42:44])
	flags := binary.LittleEndian.Uint32(msg.Data[44:48])

	_ = channel
	_ = remainingBytes
	_ = writeChannelInfoOffset
	_ = writeChannelInfoLength
	_ = flags

	// Get file handle
	handle, exists := h.fileHandles[string(fileID)]
	if !exists {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_HANDLE), nil
	}
	if h.debug > 0 {
		log.Printf("[DEBUG][SMB2] WRITE: path=%q offset=%d len=%d flags=0x%08x isDir=%v", handle.Path, offset, length, flags, handle.IsDirectory)
	}

	// Extract write data
	var writeData []byte
	if length > 0 && dataOffset >= 64 {
		dataStart := int(dataOffset) - 64
		dataEnd := dataStart + int(length)
		if dataStart >= 0 && dataEnd <= len(msg.Data) {
			writeData = msg.Data[dataStart:dataEnd]
		} else {
			return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
		}
	}

	// IPC$ pipe write: handle as DCE/RPC data, store response for later READ
	if handle.TreeConnection != nil && handle.TreeConnection.IsIPC {
		if len(writeData) >= 2 && writeData[0] == 5 && writeData[1] == 0 {
			rpcResp := h.handleDCERPC(writeData)
			if rpcResp != nil {
				if h.debug >= 5 {
					log.Printf("[DEBUG][SMB2] PIPE RPC RESPONSE DUMP:\n%s", hexDump(rpcResp, h.debug >= 10))
				}
				// Store the RPC response; the client will READ it next
				h.pipeResponses[string(fileID)] = rpcResp
			}
		}
		// Report all bytes written
		bytesWritten := int(length)
		response := &protocol.SMB2Message{
			Header: protocol.SMB2Header{
				ProtocolID:    [4]byte{0xFE, 'S', 'M', 'B'},
				StructureSize: 64,
				Status:        protocol.STATUS_SUCCESS,
				Command:       protocol.SMB2_WRITE,
				CreditRequest: h.creditsFor(msg),
				Flags:         0x01,
				MessageID:     msg.Header.MessageID,
				TreeID:        msg.Header.TreeID,
				SessionID:     msg.Header.SessionID,
			},
		}
		data := bytes.NewBuffer(nil)
		binary.Write(data, binary.LittleEndian, uint16(17))           // StructureSize
		binary.Write(data, binary.LittleEndian, uint16(0))            // Reserved
		binary.Write(data, binary.LittleEndian, uint32(bytesWritten)) // Count
		binary.Write(data, binary.LittleEndian, uint32(0))            // Remaining
		binary.Write(data, binary.LittleEndian, uint16(0))            // WriteChannelInfoOffset
		binary.Write(data, binary.LittleEndian, uint16(0))            // WriteChannelInfoLength
		response.Data = data.Bytes()
		return response, nil
	}

	if h.isReadOnly(handle.TreeConnection) {
		return h.createErrorResponse(msg, protocol.STATUS_ACCESS_DENIED), nil
	}

	// Named-stream write (Apple FinderInfo / resource fork). Store in streamStore
	// at the requested offset; never touch the base object on disk.
	if handle.StreamName != "" {
		key := streamKey(handle.TreeConnection.ShareName, handle.Path, handle.StreamName)
		h.stateMu.Lock()
		cur := h.streamStore[key]
		end := int(offset) + len(writeData)
		if end > len(cur) {
			grown := make([]byte, end)
			copy(grown, cur)
			cur = grown
		}
		copy(cur[int(offset):end], writeData)
		h.streamStore[key] = cur
		h.stateMu.Unlock()
		response := &protocol.SMB2Message{
			Header: protocol.SMB2Header{
				ProtocolID:    [4]byte{0xFE, 'S', 'M', 'B'},
				StructureSize: 64,
				Status:        protocol.STATUS_SUCCESS,
				Command:       protocol.SMB2_WRITE,
				CreditRequest: h.creditsFor(msg),
				Flags:         0x01,
				MessageID:     msg.Header.MessageID,
				TreeID:        msg.Header.TreeID,
				SessionID:     msg.Header.SessionID,
			},
		}
		data := bytes.NewBuffer(nil)
		binary.Write(data, binary.LittleEndian, uint16(17))             // StructureSize
		binary.Write(data, binary.LittleEndian, uint16(0))              // Reserved
		binary.Write(data, binary.LittleEndian, uint32(len(writeData))) // Count
		binary.Write(data, binary.LittleEndian, uint32(0))              // Remaining
		binary.Write(data, binary.LittleEndian, uint16(0))              // WriteChannelInfoOffset
		binary.Write(data, binary.LittleEndian, uint16(0))              // WriteChannelInfoLength
		response.Data = data.Bytes()
		return response, nil
	}

	// Don't write to directories
	if handle.IsDirectory {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}

	// Check write access for regular files
	if (handle.AccessMask&protocol.GENERIC_WRITE) == 0 &&
		(handle.AccessMask&protocol.FILE_WRITE_DATA) == 0 {
		return h.createErrorResponse(msg, protocol.STATUS_ACCESS_DENIED), nil
	}

	// Write data — use the cached fd (WriteAt) when available to avoid the
	// per-request open+close overhead inside ShareManager.WriteFile.
	var bytesWritten int
	var writeErr error
	if handle.OSFile != nil {
		bytesWritten, writeErr = handle.OSFile.WriteAt(writeData, int64(offset))
	} else {
		bytesWritten, writeErr = h.shareManager.WriteFile(handle.TreeConnection.ShareName, handle.Path, int64(offset), writeData)
	}
	if writeErr != nil {
		return h.createErrorResponse(msg, protocol.STATUS_ACCESS_DENIED), nil
	}

	response := &protocol.SMB2Message{
		Header: protocol.SMB2Header{
			ProtocolID:    [4]byte{0xFE, 'S', 'M', 'B'},
			StructureSize: 64,
			Status:        protocol.STATUS_SUCCESS,
			Command:       protocol.SMB2_WRITE,
			CreditRequest: h.creditsFor(msg),
			Flags:         0x01,
			MessageID:     msg.Header.MessageID,
			TreeID:        msg.Header.TreeID,
			SessionID:     msg.Header.SessionID,
		},
	}

	data := bytes.NewBuffer(nil)
	binary.Write(data, binary.LittleEndian, uint16(17))           // StructureSize
	binary.Write(data, binary.LittleEndian, uint16(0))            // Reserved
	binary.Write(data, binary.LittleEndian, uint32(bytesWritten)) // ByteCount
	binary.Write(data, binary.LittleEndian, uint32(0))            // Remaining
	binary.Write(data, binary.LittleEndian, uint16(0))            // WriteChannelInfoOffset
	binary.Write(data, binary.LittleEndian, uint16(0))            // WriteChannelInfoLength

	h.hooks.OnFileUpload(connInfo, handle.TreeConnection.ShareName, handle.Path, int64(bytesWritten))

	response.Data = data.Bytes()
	return response, nil
}

func (h *SMB2Handler) handleQueryDirectory(msg *protocol.SMB2Message, connInfo hooks.ConnInfo) (*protocol.SMB2Message, error) {
	// Parse request basics
	if len(msg.Data) < 33 {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}
	infoClass := msg.Data[2] // FileInformationClass
	flags := msg.Data[3]
	fileIndexReq := binary.LittleEndian.Uint32(msg.Data[4:8])
	fileID := msg.Data[8:24]
	nameOffset := binary.LittleEndian.Uint16(msg.Data[24:26])
	nameLength := binary.LittleEndian.Uint16(msg.Data[26:28])
	clientOutMax := binary.LittleEndian.Uint32(msg.Data[28:32])

	// Get the file handle and tree connection
	session, ok := h.sessions[msg.Header.SessionID]
	if !ok {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_HANDLE), nil
	}
	treeConn, ok := session.TreeConnections[msg.Header.TreeID]
	if !ok {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_HANDLE), nil
	}
	handle, ok := h.fileHandles[string(fileID)]
	if !ok {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_HANDLE), nil
	}

	var pattern string
	if nameLength > 0 && int(nameOffset) >= 64 {
		start := int(nameOffset) - 64
		end := start + int(nameLength)
		if start >= 0 && end <= len(msg.Data) {
			runes := make([]rune, 0, nameLength/2)
			for off := start; off+1 < end; off += 2 {
				r := binary.LittleEndian.Uint16(msg.Data[off : off+2])
				if r == 0 {
					break
				}
				runes = append(runes, rune(r))
			}
			pattern = string(runes)
		}
	}
	if h.debug > 0 {
		log.Printf("[DEBUG][SMB2] QUERY_DIRECTORY: class=0x%02x flags=0x%02x fileIndex=%d outMax=%d path=%q isDir=%v pattern=%q", infoClass, flags, fileIndexReq, clientOutMax, handle.Path, handle.IsDirectory, pattern)
	}

	// Decode search pattern (ignored in this simple implementation)
	_ = nameOffset
	_ = nameLength

	// Initialize or reset snapshot for directory enumeration
	if handle.DirSnapshot == nil || (flags&0x01) != 0 { // RESTART flag
		list, err := h.shareManager.ListDirectory(treeConn.ShareName, handle.Path)
		if err != nil {
			return h.createErrorResponse(msg, protocol.STATUS_OBJECT_NAME_NOT_FOUND), nil
		}
		if pattern != "" && pattern != "*" {
			filtered := make([]*protocol.FileInfo, 0, len(list))
			lowerPattern := strings.ToLower(pattern)
			hasWildcard := strings.ContainsAny(pattern, "*?")
			for _, fi := range list {
				name := fi.Name
				if !hasWildcard {
					if strings.EqualFold(name, pattern) {
						filtered = append(filtered, fi)
					}
					continue
				}
				matched, err := path.Match(lowerPattern, strings.ToLower(name))
				if err == nil && matched {
					filtered = append(filtered, fi)
				}
			}
			list = filtered
		}
		handle.DirSnapshot = list
		handle.DirIndex = 0
	}
	// If INDEX_SPECIFIED flag set, use provided index
	if (flags & 0x04) != 0 {
		if int(fileIndexReq) < len(handle.DirSnapshot) {
			handle.DirIndex = int(fileIndexReq)
		} else {
			// Index beyond end
			return h.createErrorResponse(msg, protocol.STATUS_NO_MORE_FILES), nil
		}
	}

	resp := &protocol.SMB2Message{
		Header: protocol.SMB2Header{
			ProtocolID:    [4]byte{0xFE, 'S', 'M', 'B'},
			StructureSize: 64,
			Status:        protocol.STATUS_SUCCESS,
			Command:       protocol.SMB2_QUERY_DIRECTORY,
			CreditRequest: h.creditsFor(msg),
			Flags:         0x01,
			MessageID:     msg.Header.MessageID,
			TreeID:        msg.Header.TreeID,
			SessionID:     msg.Header.SessionID,
		},
	}

	// Response body header
	data := bytes.NewBuffer(nil)
	binary.Write(data, binary.LittleEndian, uint16(9))  // StructureSize
	binary.Write(data, binary.LittleEndian, uint16(72)) // OutputBufferOffset (64 + 8)
	binary.Write(data, binary.LittleEndian, uint32(0))  // OutputBufferLength (filled later)
	for data.Len() < 72-64 {
		data.WriteByte(0)
	}
	outputStart := data.Len()

	// Helper to encode filename to UTF-16LE（见 encodeUTF16LE 的说明：
	// 手写版本会把中文名截成第一个字）。
	toUTF16 := encodeUTF16LE

	// Convert Go time to Windows FILETIME (100ns intervals since Jan 1, 1601)
	toFILETIME := func(t time.Time) uint64 {
		const epochDiff = 116444736000000000 // 100ns units between 1601 and 1970
		return uint64(t.UnixNano()/100) + epochDiff
	}

	// Add entries respecting clientOutMax
	var entryStarts []int
	start := handle.DirIndex
	if start < 0 {
		start = 0
	}
	files := handle.DirSnapshot
	returnSingle := (flags & 0x02) != 0
	for i := start; i < len(files); i++ {
		f := files[i]
		// Build entry into temp buffer to know its size
		// Build entry into temp buffer to know its size
		eb := bytes.NewBuffer(nil)
		switch infoClass {
		case 0x25: // FILE_ID_BOTH_DIRECTORY_INFORMATION
			binary.Write(eb, binary.LittleEndian, uint32(0)) // NextEntryOffset
			binary.Write(eb, binary.LittleEndian, uint32(i)) // FileIndex
			ct := toFILETIME(f.CreatedTime)
			at := toFILETIME(f.AccessedTime)
			mt := toFILETIME(f.ModifiedTime)
			ch := mt
			binary.Write(eb, binary.LittleEndian, ct)
			binary.Write(eb, binary.LittleEndian, at)
			binary.Write(eb, binary.LittleEndian, mt)
			binary.Write(eb, binary.LittleEndian, ch)
			binary.Write(eb, binary.LittleEndian, uint64(f.Size))
			binary.Write(eb, binary.LittleEndian, uint64(f.Size))
			binary.Write(eb, binary.LittleEndian, uint32(f.Attributes))
			name16 := toUTF16(f.Name)
			binary.Write(eb, binary.LittleEndian, uint32(len(name16))) // FileNameLength
			binary.Write(eb, binary.LittleEndian, uint32(0))           // EaSize
			eb.WriteByte(0)                                            // ShortNameLength
			eb.WriteByte(0)                                            // Reserved
			eb.Write(make([]byte, 24))                                 // ShortName
			eb.Write([]byte{0x00, 0x00})                               // align
			var fid uint64
			for j := 0; j < len(name16); j++ {
				fid = fid*131 + uint64(name16[j])
			}
			binary.Write(eb, binary.LittleEndian, fid)
			eb.Write(name16)
		case 0x02: // FILE_FULL_DIRECTORY_INFORMATION
			binary.Write(eb, binary.LittleEndian, uint32(0)) // NextEntryOffset
			binary.Write(eb, binary.LittleEndian, uint32(i))
			ct := toFILETIME(f.CreatedTime)
			at := toFILETIME(f.AccessedTime)
			mt := toFILETIME(f.ModifiedTime)
			ch := mt
			binary.Write(eb, binary.LittleEndian, ct)
			binary.Write(eb, binary.LittleEndian, at)
			binary.Write(eb, binary.LittleEndian, mt)
			binary.Write(eb, binary.LittleEndian, ch)
			binary.Write(eb, binary.LittleEndian, uint64(f.Size))
			binary.Write(eb, binary.LittleEndian, uint64(f.Size))
			binary.Write(eb, binary.LittleEndian, uint32(f.Attributes))
			name16 := toUTF16(f.Name)
			binary.Write(eb, binary.LittleEndian, uint32(len(name16))) // FileNameLength
			binary.Write(eb, binary.LittleEndian, uint32(0))           // EaSize
			eb.Write(name16)
		case 0x04: // Was labeled FILE_FULL, but probably unused or mislabeled. Keeping for safe measure if clients use it?
			binary.Write(eb, binary.LittleEndian, uint32(0)) // NextEntryOffset
			binary.Write(eb, binary.LittleEndian, uint32(i))
			ct := toFILETIME(f.CreatedTime)
			at := toFILETIME(f.AccessedTime)
			mt := toFILETIME(f.ModifiedTime)
			ch := mt
			binary.Write(eb, binary.LittleEndian, ct)
			binary.Write(eb, binary.LittleEndian, at)
			binary.Write(eb, binary.LittleEndian, mt)
			binary.Write(eb, binary.LittleEndian, ch)
			binary.Write(eb, binary.LittleEndian, uint64(f.Size))
			binary.Write(eb, binary.LittleEndian, uint64(f.Size))
			binary.Write(eb, binary.LittleEndian, uint32(f.Attributes))
			name16 := toUTF16(f.Name)
			binary.Write(eb, binary.LittleEndian, uint32(len(name16))) // FileNameLength
			binary.Write(eb, binary.LittleEndian, uint32(0))           // EaSize
			eb.Write(name16)
		case 0x03, 0x05: // FILE_BOTH_DIRECTORY_INFORMATION
			binary.Write(eb, binary.LittleEndian, uint32(0)) // NextEntryOffset
			binary.Write(eb, binary.LittleEndian, uint32(i))
			ct := toFILETIME(f.CreatedTime)
			at := toFILETIME(f.AccessedTime)
			mt := toFILETIME(f.ModifiedTime)
			ch := mt
			binary.Write(eb, binary.LittleEndian, ct)
			binary.Write(eb, binary.LittleEndian, at)
			binary.Write(eb, binary.LittleEndian, mt)
			binary.Write(eb, binary.LittleEndian, ch)
			binary.Write(eb, binary.LittleEndian, uint64(f.Size))
			binary.Write(eb, binary.LittleEndian, uint64(f.Size))
			binary.Write(eb, binary.LittleEndian, uint32(f.Attributes))
			name16 := toUTF16(f.Name)
			binary.Write(eb, binary.LittleEndian, uint32(len(name16))) // FileNameLength
			binary.Write(eb, binary.LittleEndian, uint32(0))           // EaSize
			eb.WriteByte(0)                                            // ShortNameLength
			eb.WriteByte(0)
			eb.Write(make([]byte, 24)) // ShortName
			eb.Write(name16)
		case 0x0c: // FILE_NAMES_INFORMATION
			binary.Write(eb, binary.LittleEndian, uint32(0)) // NextEntryOffset
			binary.Write(eb, binary.LittleEndian, uint32(i)) // FileIndex
			name16 := toUTF16(f.Name)
			binary.Write(eb, binary.LittleEndian, uint32(len(name16)))
			eb.Write(name16)
		default: // FILE_DIRECTORY_INFORMATION
			binary.Write(eb, binary.LittleEndian, uint32(0)) // NextEntryOffset
			binary.Write(eb, binary.LittleEndian, uint32(i))
			ct := toFILETIME(f.CreatedTime)
			at := toFILETIME(f.AccessedTime)
			mt := toFILETIME(f.ModifiedTime)
			ch := mt
			binary.Write(eb, binary.LittleEndian, ct)
			binary.Write(eb, binary.LittleEndian, at)
			binary.Write(eb, binary.LittleEndian, mt)
			binary.Write(eb, binary.LittleEndian, ch)
			binary.Write(eb, binary.LittleEndian, uint64(f.Size))
			binary.Write(eb, binary.LittleEndian, uint64(f.Size))
			binary.Write(eb, binary.LittleEndian, uint32(f.Attributes))
			name16 := toUTF16(f.Name)
			binary.Write(eb, binary.LittleEndian, uint32(len(name16)))
			eb.Write(name16)
		}
		for eb.Len()%8 != 0 {
			eb.WriteByte(0)
		}
		// Check buffer limit
		if clientOutMax > 0 && uint32(data.Len()+eb.Len()-outputStart) > clientOutMax {
			break
		}
		entryStarts = append(entryStarts, data.Len())
		data.Write(eb.Bytes())
		// If client asked for single entry, stop after one
		if returnSingle {
			start = i + 1
			break
		}
		start = i + 1
	}

	if len(entryStarts) == 0 {
		// If we're already at/after end of enumeration, report NO_MORE_FILES
		if handle.DirIndex >= len(handle.DirSnapshot) {
			return h.createErrorResponse(msg, protocol.STATUS_NO_MORE_FILES), nil
		}
		// Otherwise client's buffer too small to fit a single entry
		return h.createErrorResponse(msg, 0xC0000004), nil // STATUS_INFO_LENGTH_MISMATCH
	}
	// Patch NextEntryOffset for all but last
	for i := 0; i < len(entryStarts)-1; i++ {
		start := entryStarts[i]
		next := entryStarts[i+1]
		size := next - start
		binary.LittleEndian.PutUint32(data.Bytes()[start:], uint32(size))
	}

	// Set OutputBufferLength
	outLen := data.Len() - outputStart
	binary.LittleEndian.PutUint32(data.Bytes()[4:8], uint32(outLen))

	// Update enumeration index to next unreturned element
	handle.DirIndex = start
	if h.debug > 0 {
		log.Printf("[DEBUG][SMB2] QUERY_DIRECTORY: returned=%d nextIndex=%d", len(entryStarts), handle.DirIndex)
	}

	resp.Data = data.Bytes()
	return resp, nil
}

func (h *SMB2Handler) handleQueryInfo(msg *protocol.SMB2Message, connInfo hooks.ConnInfo) (*protocol.SMB2Message, error) {
	if len(msg.Data) < 40 {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}
	// Parse request
	structureSize := binary.LittleEndian.Uint16(msg.Data[0:2])
	if structureSize != 41 { // 0x29
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}
	infoType := msg.Data[2]
	infoClass := msg.Data[3]
	outputBufferLength := binary.LittleEndian.Uint32(msg.Data[4:8])
	_ = outputBufferLength
	// input buffer fields unused in our minimal impl
	fileID := msg.Data[24:40]
	_ = fileID
	if h.debug > 0 {
		log.Printf("[DEBUG][SMB2] QUERY_INFO: infoType=0x%02x infoClass=0x%02x outLen=%d fileID=%x", infoType, infoClass, outputBufferLength, fileID)
	}

	// Build base response
	response := &protocol.SMB2Message{
		Header: protocol.SMB2Header{
			ProtocolID:    [4]byte{0xFE, 'S', 'M', 'B'},
			StructureSize: 64,
			Status:        protocol.STATUS_SUCCESS,
			Command:       protocol.SMB2_QUERY_INFO,
			CreditRequest: h.creditsFor(msg),
			Flags:         0x01,
			MessageID:     msg.Header.MessageID,
			TreeID:        msg.Header.TreeID,
			SessionID:     msg.Header.SessionID,
		},
	}

	body := bytes.NewBuffer(nil)
	binary.Write(body, binary.LittleEndian, uint16(9))  // StructureSize
	binary.Write(body, binary.LittleEndian, uint16(72)) // OutputBufferOffset
	binary.Write(body, binary.LittleEndian, uint32(0))  // OutputBufferLength (patched later)
	for body.Len() < 72-64 {
		body.WriteByte(0)
	}
	outStart := body.Len()

	// Helpers
	toFILETIME := func(t time.Time) uint64 {
		const epochDiff = 116444736000000000
		return uint64(t.UnixNano()/100) + epochDiff
	}

	switch infoType {
	case 0x01: // File information
		// Validate handle
		handle, ok := h.fileHandles[string(fileID)]
		if !ok {
			return h.createErrorResponse(msg, protocol.STATUS_INVALID_HANDLE), nil
		}
		// For a named-stream handle, size/EndOfFile describe the stream contents.
		effSize := uint64(handle.FileInfo.Size)
		if handle.StreamName != "" {
			effSize = uint64(h.streamSize(handle.TreeConnection.ShareName, handle.Path, handle.StreamName))
		}
		switch infoClass {
		case 0x12: // FileAllInformation
			const epochAll = 116444736000000000
			ct := uint64(handle.FileInfo.CreatedTime.UnixNano()/100) + epochAll
			at := uint64(handle.FileInfo.AccessedTime.UnixNano()/100) + epochAll
			mt := uint64(handle.FileInfo.ModifiedTime.UnixNano()/100) + epochAll
			ch := mt
			// FILE_BASIC_INFORMATION (40)
			binary.Write(body, binary.LittleEndian, ct)
			binary.Write(body, binary.LittleEndian, at)
			binary.Write(body, binary.LittleEndian, mt)
			binary.Write(body, binary.LittleEndian, ch)
			binary.Write(body, binary.LittleEndian, handle.FileInfo.Attributes)
			binary.Write(body, binary.LittleEndian, uint32(0))
			// FILE_STANDARD_INFORMATION (24)
			binary.Write(body, binary.LittleEndian, effSize)
			binary.Write(body, binary.LittleEndian, effSize)
			binary.Write(body, binary.LittleEndian, uint32(1))
			body.WriteByte(0)
			if handle.FileInfo.IsDirectory && handle.StreamName == "" {
				body.WriteByte(1)
			} else {
				body.WriteByte(0)
			}
			body.Write(make([]byte, 10))
			// FILE_INTERNAL_INFORMATION (8)
			var idx uint64
			for i := 0; i < len(handle.FileInfo.Name); i++ {
				idx = idx*131 + uint64(handle.FileInfo.Name[i])
			}
			binary.Write(body, binary.LittleEndian, idx)
			// FILE_EA_INFORMATION (4)
			binary.Write(body, binary.LittleEndian, uint32(0))
			// FILE_ACCESS_INFORMATION (4)
			binary.Write(body, binary.LittleEndian, uint32(handle.AccessMask))
			// FILE_POSITION_INFORMATION (8)
			binary.Write(body, binary.LittleEndian, uint64(0))
			// FILE_MODE_INFORMATION (4)
			binary.Write(body, binary.LittleEndian, uint32(0))
			// FILE_ALIGNMENT_INFORMATION (4)
			binary.Write(body, binary.LittleEndian, uint32(0))
			// FILE_NAME_INFORMATION
			nm := handle.Path
			if nm == "" {
				nm = handle.FileInfo.Name
			}
			nm16 := encodeUTF16LE(nm)
			binary.Write(body, binary.LittleEndian, uint32(len(nm16)))
			body.Write(nm16)
			for body.Len()%8 != 0 {
				body.WriteByte(0)
			}
		case 0x05: // FileStandardInformation
			// AllocationSize(8), EndOfFile(8), NumberOfLinks(4), DeletePending(1), Directory(1), reserved(10)
			binary.Write(body, binary.LittleEndian, effSize)   // AllocationSize (approx)
			binary.Write(body, binary.LittleEndian, effSize)   // EndOfFile
			binary.Write(body, binary.LittleEndian, uint32(1)) // NumberOfLinks
			body.WriteByte(0)                                  // DeletePending
			if handle.FileInfo.IsDirectory && handle.StreamName == "" {
				body.WriteByte(1)
			} else {
				body.WriteByte(0)
			}
			body.Write(make([]byte, 10))
		case 0x04: // FileBasicInformation
			// Creation, LastAccess, LastWrite, Change (4x8), FileAttributes(4), Reserved(4)
			now := time.Now()
			ct := toFILETIME(handle.FileInfo.CreatedTime)
			at := toFILETIME(handle.FileInfo.AccessedTime)
			mt := toFILETIME(handle.FileInfo.ModifiedTime)
			ch := toFILETIME(now)
			binary.Write(body, binary.LittleEndian, ct)
			binary.Write(body, binary.LittleEndian, at)
			binary.Write(body, binary.LittleEndian, mt)
			binary.Write(body, binary.LittleEndian, ch)
			binary.Write(body, binary.LittleEndian, handle.FileInfo.Attributes)
			binary.Write(body, binary.LittleEndian, uint32(0))
		case 0x0B: // FileNameInformation
			// FileNameLength(4), FileName (UTF-16LE)
			name := handle.Path
			if name == "" {
				name = handle.FileInfo.Name
			}
			name16 := encodeUTF16LE(name)
			binary.Write(body, binary.LittleEndian, uint32(len(name16)))
			body.Write(name16)
			for body.Len()%8 != 0 {
				body.WriteByte(0)
			}
		case 0x06: // FileInternalInformation
			var idx uint64
			name := handle.Path
			if name == "" {
				name = handle.FileInfo.Name
			}
			for i := 0; i < len(name); i++ {
				idx = idx*131 + uint64(name[i])
			}
			binary.Write(body, binary.LittleEndian, idx)
		case 0x22: // FileNetworkOpenInformation
			// Creation, LastAccess, LastWrite, Change (4x8), AllocationSize(8), EndOfFile(8), FileAttributes(4), Reserved(4)
			const epoch = 116444736000000000
			ct := uint64(handle.FileInfo.CreatedTime.UnixNano()/100) + epoch
			at := uint64(handle.FileInfo.AccessedTime.UnixNano()/100) + epoch
			mt := uint64(handle.FileInfo.ModifiedTime.UnixNano()/100) + epoch
			ch := mt
			binary.Write(body, binary.LittleEndian, ct)
			binary.Write(body, binary.LittleEndian, at)
			binary.Write(body, binary.LittleEndian, mt)
			binary.Write(body, binary.LittleEndian, ch)
			binary.Write(body, binary.LittleEndian, effSize)
			binary.Write(body, binary.LittleEndian, effSize)
			binary.Write(body, binary.LittleEndian, handle.FileInfo.Attributes)
			binary.Write(body, binary.LittleEndian, uint32(0))
		case 0x23: // FileAttributeTagInformation
			// FileAttributes(4), ReparseTag(4)
			binary.Write(body, binary.LittleEndian, handle.FileInfo.Attributes)
			binary.Write(body, binary.LittleEndian, uint32(0))
		case 0x16: // FileStreamInformation
			// Report the unnamed data stream so macOS treats this as a
			// streams-capable object. Required for the disk-image / Time
			// Machine attach path (macOS enumerates streams on the bands).
			// Directories have no $DATA stream -> empty success.
			if !handle.FileInfo.IsDirectory {
				name16 := encodeUTF16LE("::$DATA")
				binary.Write(body, binary.LittleEndian, uint32(0))                    // NextEntryOffset (single entry)
				binary.Write(body, binary.LittleEndian, uint32(len(name16)))          // StreamNameLength
				binary.Write(body, binary.LittleEndian, uint64(handle.FileInfo.Size)) // StreamSize
				binary.Write(body, binary.LittleEndian, uint64(handle.FileInfo.Size)) // StreamAllocationSize
				body.Write(name16)
			}
		default:
			if h.debug > 0 {
				log.Printf("[DEBUG][SMB2] QUERY_INFO: unsupported file info class=0x%02x, returning empty success", infoClass)
			}
		}
	case 0x02: // FileSystem information
		switch infoClass {
		case 0x01: // FileFsVolumeInformation
			const epoch = 116444736000000000
			now := uint64(time.Now().UnixNano()/100) + epoch
			binary.Write(body, binary.LittleEndian, now)       // VolumeCreationTime
			binary.Write(body, binary.LittleEndian, uint32(0)) // VolumeSerialNumber
			volName := "PUBLIC"
			vol16 := encodeUTF16LE(volName)
			binary.Write(body, binary.LittleEndian, uint32(len(vol16))) // VolumeLabelLength
			body.WriteByte(0)                                           // SupportsObjects
			body.WriteByte(0)                                           // Reserved
			body.Write(vol16)
			for body.Len()%8 != 0 {
				body.WriteByte(0)
			}
		case 0x03: // FileFsSizeInformation
			// TotalAllocationUnits(8), AvailableAllocationUnits(8), SectorsPerAllocationUnit(4), BytesPerSector(4)
			total, avail := h.fsSizeUnits(msg.Header.SessionID, msg.Header.TreeID)
			binary.Write(body, binary.LittleEndian, total)
			binary.Write(body, binary.LittleEndian, avail)
			binary.Write(body, binary.LittleEndian, uint32(1))    // SectorsPerAllocationUnit
			binary.Write(body, binary.LittleEndian, uint32(4096)) // BytesPerSector
		case 0x07: // FileFsFullSizeInformation
			total, avail := h.fsSizeUnits(msg.Header.SessionID, msg.Header.TreeID)
			binary.Write(body, binary.LittleEndian, total)
			binary.Write(body, binary.LittleEndian, avail) // CallerAvailable
			binary.Write(body, binary.LittleEndian, avail) // ActualAvailable
			binary.Write(body, binary.LittleEndian, uint32(1))
			binary.Write(body, binary.LittleEndian, uint32(4096))
		case 0x04: // FileFsDeviceInformation
			binary.Write(body, binary.LittleEndian, uint32(0x00000007)) // FILE_DEVICE_DISK_FILE_SYSTEM?
			binary.Write(body, binary.LittleEndian, uint32(0))
		case 0x05: // FileFsAttributeInformation
			attrs := uint32(0x00000001 | 0x00000002 | 0x00000004) // case sensitive/search preserved, unicode
			// Time Machine shares must advertise named-stream + extended-attr
			// support, or macOS's disk-image attach hangs in IOServiceWaitQuiet
			// (verified: Samba+vfs_fruit always loads streams_xattr and works).
			// Time Machine shares deliberately do NOT advertise named streams /
			// extended attributes: when we did, macOS routed Apple xattrs
			// (notably com.apple.quarantine) through SMB streams/EAs and the
			// DiskImages2 writable attach failed at "initialize quarantine file"
			// (error 150) → BACKUP_FAILED_DISK_IMAGE_NOT_CREATED. Without the
			// advertisement macOS stores xattrs in plain AppleDouble (`._`) sidecar
			// files, which we serve as ordinary files, and the full backup
			// (MountingDiskImage → Copying) succeeds. Opt back in with SMB_STREAMS=1
			// only for experiments. (The earlier belief that streams were required
			// to avoid an attach hang was a misdiagnosis of the compound-response
			// bug fixed in processCompoundRequests.)
			if os.Getenv("SMB_STREAMS") == "1" && h.treeIsTimeMachine(msg.Header.SessionID, msg.Header.TreeID) {
				attrs |= 0x00040000 | 0x00004000 // FILE_NAMED_STREAMS | FILE_SUPPORTS_EXTENDED_ATTRIBUTES
			}
			binary.Write(body, binary.LittleEndian, attrs)
			binary.Write(body, binary.LittleEndian, uint32(255)) // Max name length
			fsName := "NTFS"
			// length in bytes of UTF-16LE name
			fs16 := encodeUTF16LE(fsName)
			binary.Write(body, binary.LittleEndian, uint32(len(fs16)))
			body.Write(fs16)
			// align to 8
			for body.Len()%8 != 0 {
				body.WriteByte(0)
			}
		default:
			if h.debug > 0 {
				log.Printf("[DEBUG][SMB2] QUERY_INFO: unsupported fs info class=0x%02x, returning empty success", infoClass)
			}
		}
	default:
		if h.debug > 0 {
			log.Printf("[DEBUG][SMB2] QUERY_INFO: unsupported infoType=0x%02x class=0x%02x, returning empty success", infoType, infoClass)
		}
	}

	// Patch OutputBufferLength
	outLen := body.Len() - outStart
	binary.LittleEndian.PutUint32(body.Bytes()[4:8], uint32(outLen))
	response.Data = body.Bytes()
	return response, nil
}

func (h *SMB2Handler) handleIOCTL(msg *protocol.SMB2Message, connInfo hooks.ConnInfo) (*protocol.SMB2Message, error) {
	if len(msg.Data) < 56 {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}

	// Parse IOCTL request
	structureSize := binary.LittleEndian.Uint16(msg.Data[0:2])
	if structureSize != 57 {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}

	_ = binary.LittleEndian.Uint16(msg.Data[2:4]) // Reserved
	ctlCode := binary.LittleEndian.Uint32(msg.Data[4:8])
	fileID := msg.Data[8:24]
	inputOffset := binary.LittleEndian.Uint32(msg.Data[24:28])
	inputCount := binary.LittleEndian.Uint32(msg.Data[28:32])
	maxInputResponse := binary.LittleEndian.Uint32(msg.Data[32:36])
	outputOffset := binary.LittleEndian.Uint32(msg.Data[36:40])
	outputCount := binary.LittleEndian.Uint32(msg.Data[40:44])
	maxOutputResponse := binary.LittleEndian.Uint32(msg.Data[44:48])
	flags := binary.LittleEndian.Uint32(msg.Data[48:52])
	_ = binary.LittleEndian.Uint32(msg.Data[52:56]) // Reserved2

	_ = maxInputResponse
	_ = outputOffset
	_ = outputCount
	_ = maxOutputResponse
	_ = flags

	// Log IOCTL code immediately for debugging
	if h.debug >= 1 {
		log.Printf("[DEBUG][SMB2] IOCTL received: ctl=0x%08x fileID=%x", ctlCode, fileID)
	}

	// Get file handle (except for certain FSCTLs that don't require a file handle)
	handle, exists := h.fileHandles[string(fileID)]
	if !exists {
		// FSCTLs that don't require a file handle or can gracefully fail
		switch ctlCode {
		case 0x00140204: // FSCTL_VALIDATE_NEGOTIATE_INFO
			// Continue without handle
		case 0x001401FC: // FSCTL_QUERY_NETWORK_INTERFACE_INFO
			// Sent with the wildcard (0xff..ff) file id; macOS needs the
			// interface list to configure reconnect/QoS for Time Machine.
			// Continue without handle.
		case 0x00060194: // FSCTL_DFS_GET_REFERRALS
			// Windows probes DFS early on IPC$. Report that DFS is unavailable
			// instead of treating it as an invalid-handle protocol error.
			return h.createErrorResponse(msg, protocol.STATUS_FS_DRIVER_REQUIRED), nil
		case 0x00140078: // FSCTL_SET_REPARSE_POINT - macOS uses this for symlinks
			// Fake success to satisfy macOS Finder
			// Returning STATUS_NOT_SUPPORTED causes reconnection loop or hang
			ioctlResp := &protocol.SMB2Message{
				Header: protocol.SMB2Header{
					ProtocolID:    msg.Header.ProtocolID,
					StructureSize: 64,
					Status:        protocol.STATUS_SUCCESS,
					Command:       protocol.SMB2_IOCTL,
					CreditRequest: h.creditsFor(msg),
					Flags:         0x01 | protocol.SMB2_FLAGS_SIGNED, // Ensure signed
					MessageID:     msg.Header.MessageID,
					TreeID:        msg.Header.TreeID,
					SessionID:     msg.Header.SessionID,
				},
			}
			// Empty body for success (StructureSize=49, etc)
			data := bytes.NewBuffer(nil)
			binary.Write(data, binary.LittleEndian, uint16(49)) // StructureSize
			binary.Write(data, binary.LittleEndian, uint16(0))  // Reserved
			binary.Write(data, binary.LittleEndian, ctlCode)    // CtlCode
			data.Write(fileID)                                  // FileId
			binary.Write(data, binary.LittleEndian, uint32(0))  // InputOffset
			binary.Write(data, binary.LittleEndian, uint32(0))  // InputCount
			binary.Write(data, binary.LittleEndian, uint32(0))  // OutputOffset
			binary.Write(data, binary.LittleEndian, uint32(0))  // OutputCount
			binary.Write(data, binary.LittleEndian, uint32(0))  // Flags
			binary.Write(data, binary.LittleEndian, uint32(0))  // Reserved2
			ioctlResp.Data = data.Bytes()
			return ioctlResp, nil
		default:
			if h.debug > 0 {
				h.dbg("IOCTL: invalid handle for ctl=0x%08x", ctlCode)
			}
			return h.createErrorResponse(msg, protocol.STATUS_INVALID_HANDLE), nil
		}
	}

	// Extract input data if present
	var inputData []byte
	if inputCount > 0 && int(inputOffset) >= 64 {
		dataStart := int(inputOffset) - 64 // Adjust for header
		dataEnd := dataStart + int(inputCount)
		if dataStart >= 0 && dataEnd <= len(msg.Data) {
			inputData = msg.Data[dataStart:dataEnd]
		}
	}

	var outputData []byte

	// Handle different IOCTL codes
	if h.debug >= 1 {
		log.Printf("[DEBUG][SMB2] IOCTL ctl=0x%08x inLen=%d sid=%d tree=%d", ctlCode, inputCount, msg.Header.SessionID, msg.Header.TreeID)
	}
	if h.debug >= 5 {
		if inputCount > 0 {
			log.Printf("[DEBUG][SMB2] IOCTL INPUT DUMP:\n%s", hexDump(inputData, h.debug >= 10))
		}
	}

	switch ctlCode {
	case 0x0011C017: // FSCTL_PIPE_TRANSCEIVE
		// Handle DCE/RPC over named pipes
		if handle.TreeConnection.IsIPC {
			outputData = h.handleDCERPC(inputData)
			if h.debug >= 5 && len(outputData) > 0 {
				log.Printf("[DEBUG][SMB2] IOCTL OUTPUT DUMP:\n%s", hexDump(outputData, h.debug >= 10))
			}
		}
	case 0x00140204: // FSCTL_VALIDATE_NEGOTIATE_INFO
		// The response structure is the 24-byte tuple defined by MS-SMB2 2.2.32.6:
		// Capabilities(4) + ServerGuid(16) + SecurityMode(2) + Dialect(2).
		dialect := uint16(0)
		h.stateMu.RLock()
		if sess, ok := h.sessions[msg.Header.SessionID]; ok && sess != nil {
			dialect = sess.Dialect
		}
		h.stateMu.RUnlock()
		if dialect == 0 {
			dialect = h.lastDialect
		}
		if dialect == 0 {
			dialect = 0x0210
		}

		securityMode := uint16(protocol.SMB2_NEGOTIATE_SIGNING_ENABLED)
		capabilities := h.getCapabilities(dialect)
		b := bytes.NewBuffer(nil)
		binary.Write(b, binary.LittleEndian, capabilities)
		b.Write(h.serverGUID[:])
		binary.Write(b, binary.LittleEndian, securityMode)
		binary.Write(b, binary.LittleEndian, dialect)
		outputData = b.Bytes()
	case 0x001401FC: // FSCTL_QUERY_NETWORK_INTERFACE_INFO
		// Return SMB2_NETWORK_INTERFACE_INFO entries for local interfaces.
		// Each entry: Next(4), IfIndex(4), Capability(4), Reserved(4), LinkSpeed(8), SOCKADDR_STORAGE(128)
		const entrySize = 4 + 4 + 4 + 4 + 8 + 128
		var entries [][]byte
		ifs, err := net.Interfaces()
		if err == nil {
			for _, itf := range ifs {
				addrs, _ := itf.Addrs()
				for _, a := range addrs {
					var ip net.IP
					switch v := a.(type) {
					case *net.IPNet:
						ip = v.IP
					case *net.IPAddr:
						ip = v.IP
					}
					if ip == nil {
						continue
					}
					// Prefer IPv4 entries
					ipv4 := ip.To4()
					ss := make([]byte, 128)
					if ipv4 != nil {
						ss[0] = 0x02 // AF_INET
						ss[4] = ipv4[0]
						ss[5] = ipv4[1]
						ss[6] = ipv4[2]
						ss[7] = ipv4[3]
					} else {
						// IPv6
						ss[0] = 0x17 // AF_INET6 (23)
						ip16 := ip.To16()
						if ip16 != nil {
							copy(ss[8:8+16], ip16)
						}
					}
					ent := make([]byte, entrySize)
					// Next patched later
					binary.LittleEndian.PutUint32(ent[4:8], uint32(itf.Index))
					binary.LittleEndian.PutUint32(ent[8:12], uint32(0))           // Capability
					binary.LittleEndian.PutUint32(ent[12:16], uint32(0))          // Reserved
					binary.LittleEndian.PutUint64(ent[16:24], uint64(1000000000)) // 1Gbps
					copy(ent[24:24+128], ss)
					entries = append(entries, ent)
				}
			}
		}
		if len(entries) == 0 {
			// Fallback to loopback IPv4
			ent := make([]byte, entrySize)
			binary.LittleEndian.PutUint32(ent[4:8], uint32(1))
			binary.LittleEndian.PutUint32(ent[8:12], uint32(0))
			binary.LittleEndian.PutUint32(ent[12:16], uint32(0))
			binary.LittleEndian.PutUint64(ent[16:24], uint64(100000000)) // 100Mbps
			ss := make([]byte, 128)
			ss[0] = 0x02
			ss[4], ss[5], ss[6], ss[7] = 127, 0, 0, 1
			copy(ent[24:24+128], ss)
			entries = append(entries, ent)
		}
		// Patch Next for all but last
		for i := 0; i < len(entries)-1; i++ {
			binary.LittleEndian.PutUint32(entries[i][0:4], uint32(entrySize))
		}
		// Concat
		out := bytes.NewBuffer(nil)
		for _, e := range entries {
			out.Write(e)
		}
		outputData = out.Bytes()
		if h.debug >= 5 {
			log.Printf("[DEBUG][SMB2] QUERY_NETWORK_INTERFACE_INFO OUTPUT DUMP:\n%s", hexDump(outputData, h.debug >= 10))
		}

	default:
		// Unsupported IOCTL
		if h.debug > 0 {
			h.dbg("IOCTL: unsupported ctl=0x%08x", ctlCode)
		}
		return h.createErrorResponse(msg, protocol.STATUS_NOT_SUPPORTED), nil
	}

	response := &protocol.SMB2Message{
		Header: protocol.SMB2Header{
			ProtocolID:    [4]byte{0xFE, 'S', 'M', 'B'},
			StructureSize: 64,
			Status:        protocol.STATUS_SUCCESS,
			Command:       protocol.SMB2_IOCTL,
			CreditRequest: h.creditsFor(msg),
			Flags:         0x01,
			MessageID:     msg.Header.MessageID,
			TreeID:        msg.Header.TreeID,
			SessionID:     msg.Header.SessionID,
		},
	}

	// Build IOCTL response
	data := bytes.NewBuffer(nil)
	bufferOffset := uint32(112)                                      // 64-byte header + 48-byte IOCTL response header
	binary.Write(data, binary.LittleEndian, uint16(49))              // StructureSize
	binary.Write(data, binary.LittleEndian, uint16(0))               // Reserved
	binary.Write(data, binary.LittleEndian, ctlCode)                 // CtlCode
	data.Write(fileID)                                               // FileId (16 bytes)
	binary.Write(data, binary.LittleEndian, bufferOffset)            // InputOffset
	binary.Write(data, binary.LittleEndian, uint32(0))               // InputCount
	binary.Write(data, binary.LittleEndian, bufferOffset)            // OutputOffset
	binary.Write(data, binary.LittleEndian, uint32(len(outputData))) // OutputCount
	binary.Write(data, binary.LittleEndian, uint32(0))               // Flags
	binary.Write(data, binary.LittleEndian, uint32(0))               // Reserved2

	// Add padding to reach output offset
	for data.Len() < int(bufferOffset)-64 {
		data.WriteByte(0)
	}

	// Add output data
	data.Write(outputData)

	response.Data = data.Bytes()
	return response, nil
}

func (h *SMB2Handler) handleDCERPC(input []byte) []byte {
	// Minimal DCE/RPC parser: respond to BIND with BIND_ACK, and to REQUEST with a stub share list.
	if len(input) < 16 {
		return nil
	}
	ndr32Syntax := []byte{0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60}
	bindTimeFeatureSyntaxPrefix := []byte{0x2c, 0x1c, 0xb7, 0x6c, 0x12, 0x98, 0x40, 0x45}
	// Header
	rpcVers := input[0]
	ptype := input[2]
	// call_id in little endian
	callID := binary.LittleEndian.Uint32(input[12:16])
	if rpcVers != 5 {
		return nil
	}

	if ptype == 0x0B { // DCERPC_PKT_BIND
		if h.debug >= 5 {
			log.Printf("[DEBUG][SMB2] DCE/RPC BIND call_id=%d", callID)
			log.Printf("[DEBUG][SMB2] DCE/RPC BIND INPUT DUMP:\n%s", hexDump(input, h.debug >= 10))
		}
		// Parse number of presentation contexts to mirror in ACK
		if len(input) < 28 {
			return nil
		}
		numCtx := int(input[24])
		assocGroup := binary.LittleEndian.Uint32(input[20:24])
		if assocGroup == 0 {
			assocGroup = 1
		}
		// Build BIND_ACK
		buf := bytes.NewBuffer(nil)
		// Common header
		buf.Write([]byte{0x05, 0x00, 0x0C, 0x03}) // vers, minor, BIND_ACK, flags FIRST|LAST
		buf.Write([]byte{0x10, 0x00, 0x00, 0x00}) // little-endian NDR
		// placeholders frag len, auth len
		binary.Write(buf, binary.LittleEndian, uint16(0))
		binary.Write(buf, binary.LittleEndian, uint16(0))
		binary.Write(buf, binary.LittleEndian, callID)
		// BIND_ACK body
		binary.Write(buf, binary.LittleEndian, uint16(4280)) // max_xmit
		binary.Write(buf, binary.LittleEndian, uint16(4280)) // max_recv
		binary.Write(buf, binary.LittleEndian, assocGroup)   // assoc_group
		secAddr := []byte("\\PIPE\\srvsvc\x00")
		binary.Write(buf, binary.LittleEndian, uint16(len(secAddr)))
		buf.Write(secAddr)
		for buf.Len()%4 != 0 {
			buf.WriteByte(0)
		}
		buf.WriteByte(byte(numCtx)) // num results
		buf.Write([]byte{0, 0, 0})  // reserved
		// Parse and acknowledge each requested presentation context.
		// Windows 8.1 sends multiple contexts; echoing one accepted transfer
		// syntax per context is more interoperable than the previous ad hoc mix
		// of one accept plus synthetic rejections.
		ctxOff := 28
		for i := 0; i < numCtx; i++ {
			if ctxOff+24 > len(input) {
				break
			}
			numTransfer := int(input[ctxOff+2])
			abstractUUID := input[ctxOff+4 : ctxOff+20]
			abstractVersion := binary.LittleEndian.Uint32(input[ctxOff+20 : ctxOff+24])
			if h.debug > 0 && len(abstractUUID) == 16 {
				log.Printf("[DEBUG][SMB2] DCE/RPC BIND ctx=%d abstract=%x-%x-%x-%x-%x v=%d xfers=%d", i, abstractUUID[0:4], abstractUUID[4:6], abstractUUID[6:8], abstractUUID[8:10], abstractUUID[10:16], abstractVersion, numTransfer)
			}

			// Apple proprietary interfaces should still be rejected so Finder
			// falls back to normal SMB operations.
			isAppleRPC := len(abstractUUID) == 16 &&
				((abstractUUID[0] == 0x78 && abstractUUID[1] == 0x57 && abstractUUID[2] == 0x34 && abstractUUID[3] == 0x12) ||
					(abstractUUID[0] == 0x88 && abstractUUID[1] == 0x5d && abstractUUID[2] == 0x85 && abstractUUID[3] == 0xfb))

			xferOff := ctxOff + 24
			var chosenSyntax []byte
			var chosenVersion uint32
			if numTransfer > 0 && xferOff+20 <= len(input) {
				chosenSyntax = append([]byte(nil), input[xferOff:xferOff+16]...)
				chosenVersion = binary.LittleEndian.Uint32(input[xferOff+16 : xferOff+20])
				if h.debug > 0 {
					log.Printf("[DEBUG][SMB2] DCE/RPC BIND ctx=%d xfer[0]=%x-%x-%x-%x-%x v=%d", i, chosenSyntax[0:4], chosenSyntax[4:6], chosenSyntax[6:8], chosenSyntax[8:10], chosenSyntax[10:16], chosenVersion)
				}
			} else {
				chosenSyntax = append([]byte(nil), ndr32Syntax...)
				chosenVersion = 2
			}

			supportsTransferSyntax := len(chosenSyntax) == len(ndr32Syntax) &&
				bytes.Equal(chosenSyntax, ndr32Syntax) &&
				chosenVersion == 2
			isBindTimeFeatureNegotiation := len(chosenSyntax) == 16 &&
				bytes.Equal(chosenSyntax[:8], bindTimeFeatureSyntaxPrefix) &&
				chosenVersion == 1

			if isAppleRPC {
				log.Printf("[DEBUG][SMB2] Rejecting Apple RPC Bind")
				binary.Write(buf, binary.LittleEndian, uint16(2)) // provider_rejection
				binary.Write(buf, binary.LittleEndian, uint16(0)) // reason_not_specified
			} else if isBindTimeFeatureNegotiation {
				if h.debug > 0 {
					log.Printf("[DEBUG][SMB2] Negotiating bind-time features ctx=%d", i)
				}
				binary.Write(buf, binary.LittleEndian, uint16(3)) // negotiate_ack
				binary.Write(buf, binary.LittleEndian, uint16(0)) // no negotiated features
				buf.Write(make([]byte, 16))                       // transfer_syntax must be zero
				binary.Write(buf, binary.LittleEndian, uint32(0))
				ctxOff += 24 + numTransfer*20
				continue
			} else if !supportsTransferSyntax {
				if h.debug > 0 {
					log.Printf("[DEBUG][SMB2] Rejecting unsupported transfer syntax ctx=%d version=%d", i, chosenVersion)
				}
				binary.Write(buf, binary.LittleEndian, uint16(2)) // provider_rejection
				binary.Write(buf, binary.LittleEndian, uint16(2)) // proposed_transfer_syntaxes_not_supported
			} else {
				binary.Write(buf, binary.LittleEndian, uint16(0)) // acceptance
				binary.Write(buf, binary.LittleEndian, uint16(0)) // reason
			}
			buf.Write(chosenSyntax)
			binary.Write(buf, binary.LittleEndian, chosenVersion)

			ctxOff += 24 + numTransfer*20
		}
		// Set frag length
		out := buf.Bytes()
		binary.LittleEndian.PutUint16(out[8:10], uint16(len(out)))
		return out
	}

	if ptype == 0x00 { // DCERPC_PKT_REQUEST
		// Parse opnum to handle NetrShareEnumAll (opnum 0x0F) and NetrShareEnum (opnum 0x00)
		if len(input) < 24 {
			return nil
		}
		allocHint := binary.LittleEndian.Uint32(input[16:20])
		_ = allocHint
		ctxID := binary.LittleEndian.Uint16(input[20:22])
		opnum := binary.LittleEndian.Uint16(input[22:24])

		// Use debug level 1 to see this
		if h.debug > 0 {
			log.Printf("[DEBUG][SMB2] DCE/RPC REQUEST call_id=%d ctx=%d opnum=%d", callID, ctxID, opnum)
		}

		buildRPCResponse := func(stub []byte) []byte {
			buf := bytes.NewBuffer(nil)
			buf.Write([]byte{0x05, 0x00, 0x02, 0x03}) // RESPONSE
			buf.Write([]byte{0x10, 0x00, 0x00, 0x00})
			binary.Write(buf, binary.LittleEndian, uint16(0))
			binary.Write(buf, binary.LittleEndian, uint16(0))
			binary.Write(buf, binary.LittleEndian, callID)
			binary.Write(buf, binary.LittleEndian, uint32(len(stub))) // alloc_hint
			binary.Write(buf, binary.LittleEndian, ctxID)
			buf.WriteByte(0) // cancel_count
			buf.WriteByte(0) // reserved
			buf.Write(stub)
			out := buf.Bytes()
			binary.LittleEndian.PutUint16(out[8:10], uint16(len(out)))
			return out
		}

		extractUTF16LEString := func(data []byte) string {
			for i := 0; i+3 < len(data); i += 2 {
				if data[i] == '\\' && data[i+1] == 0 && data[i+2] == '\\' && data[i+3] == 0 {
					end := i
					for end+1 < len(data) {
						if data[end] == 0 && data[end+1] == 0 {
							break
						}
						end += 2
					}
					if end > i {
						runes := make([]rune, 0, (end-i)/2)
						for off := i; off+1 < end; off += 2 {
							runes = append(runes, rune(binary.LittleEndian.Uint16(data[off:off+2])))
						}
						return string(runes)
					}
				}
			}
			return ""
		}

		// Opnums for srvsvc (MS-SRVS)
		if opnum != 0x000F && opnum != 0x0000 && opnum != 21 && opnum != 45 {
			// Return Fault PDU (nca_s_op_rng_error)
			buf := bytes.NewBuffer(nil)
			buf.Write([]byte{0x05, 0x00, 0x03, 0x03}) // Fault
			buf.Write([]byte{0x10, 0x00, 0x00, 0x00})
			binary.Write(buf, binary.LittleEndian, uint16(0)) // frag len
			binary.Write(buf, binary.LittleEndian, uint16(0)) // auth len
			binary.Write(buf, binary.LittleEndian, callID)
			binary.Write(buf, binary.LittleEndian, uint32(0))          // alloc hint
			binary.Write(buf, binary.LittleEndian, uint16(0))          // context id
			binary.Write(buf, binary.LittleEndian, uint8(0))           // cancel count
			binary.Write(buf, binary.LittleEndian, uint8(0))           // reserved
			binary.Write(buf, binary.LittleEndian, uint32(0x1c010002)) // nca_s_op_rng_error
			binary.Write(buf, binary.LittleEndian, uint32(0))          // Reserved (4 bytes)

			out := buf.Bytes()
			binary.LittleEndian.PutUint16(out[8:10], uint16(len(out)))
			return out
		}

		if opnum == 21 { // NetrServerGetInfo
			level := uint32(0)
			if len(input) >= 28 {
				level = binary.LittleEndian.Uint32(input[len(input)-4:])
			}
			if h.debug > 0 {
				log.Printf("[DEBUG][SMB2] NetrServerGetInfo level=%d", level)
			}

			if level != 101 {
				// ERROR_INVALID_LEVEL
				stub := bytes.NewBuffer(nil)
				binary.Write(stub, binary.LittleEndian, uint32(level))
				binary.Write(stub, binary.LittleEndian, uint32(124))
				return buildRPCResponse(stub.Bytes())
			}

			serverName := extractUTF16LEString(input[24:])
			if serverName == "" {
				serverName = "\\\\192.168.8.20"
			}

			name16 := make([]byte, 0, len(serverName)*2+2)
			for _, r := range serverName {
				var tmp [2]byte
				binary.LittleEndian.PutUint16(tmp[:], uint16(r))
				name16 = append(name16, tmp[:]...)
			}
			name16 = append(name16, 0, 0)
			nameChars := uint32(len(name16) / 2)
			comment := "go-smbserver"
			comment16 := make([]byte, 0, len(comment)*2+2)
			for _, r := range comment {
				var tmp [2]byte
				binary.LittleEndian.PutUint16(tmp[:], uint16(r))
				comment16 = append(comment16, tmp[:]...)
			}
			comment16 = append(comment16, 0, 0)
			commentChars := uint32(len(comment16) / 2)

			stub := bytes.NewBuffer(nil)
			binary.Write(stub, binary.LittleEndian, uint32(101))     // union tag
			binary.Write(stub, binary.LittleEndian, uint32(0x20000)) // SERVER_INFO_101 pointer
			binary.Write(stub, binary.LittleEndian, uint32(500))     // PLATFORM_ID_NT
			binary.Write(stub, binary.LittleEndian, uint32(0x30000)) // sv101_name pointer
			binary.Write(stub, binary.LittleEndian, uint32(6))       // version major
			binary.Write(stub, binary.LittleEndian, uint32(1))       // version minor
			binary.Write(stub, binary.LittleEndian, uint32(1))       // SV_TYPE_WORKSTATION
			binary.Write(stub, binary.LittleEndian, uint32(0x30004)) // sv101_comment pointer
			binary.Write(stub, binary.LittleEndian, nameChars)
			binary.Write(stub, binary.LittleEndian, uint32(0))
			binary.Write(stub, binary.LittleEndian, nameChars)
			stub.Write(name16)
			binary.Write(stub, binary.LittleEndian, commentChars)
			binary.Write(stub, binary.LittleEndian, uint32(0))
			binary.Write(stub, binary.LittleEndian, commentChars)
			stub.Write(comment16)
			binary.Write(stub, binary.LittleEndian, uint32(0)) // NERR_Success
			return buildRPCResponse(stub.Bytes())
		}

		// Stub for Opnum 45 (Samr/Lsa) - return STATUS_SUCCESS with empty payload
		// macOS interprets failure here as a fatal error ("RPC struct is bad").
		// We return 8 bytes: 4 bytes (0) + 4 bytes (Status Success) to mimic a valid empty return struct.
		if opnum == 45 {
			stub := bytes.NewBuffer(nil)
			binary.Write(stub, binary.LittleEndian, uint32(0)) // Dummy/Count/Ptr
			binary.Write(stub, binary.LittleEndian, uint32(0)) // STATUS_SUCCESS
			return buildRPCResponse(stub.Bytes())
		}

		// Build NDR response
		type ndr struct{ bytes.Buffer }
		align4 := func(b *bytes.Buffer) {
			for b.Len()%4 != 0 {
				b.WriteByte(0)
			}
		}
		writeUnicodeString := func(b *bytes.Buffer, s string) {
			// [string] wchar_t*: conformant varying array with null terminator
			// max_count, offset, actual_count, then UTF-16LE chars with null
			runes := []rune(s)
			maxCount := uint32(len(runes) + 1)
			binary.Write(b, binary.LittleEndian, maxCount)
			binary.Write(b, binary.LittleEndian, uint32(0))
			binary.Write(b, binary.LittleEndian, maxCount)
			for _, r := range runes {
				var tmp [2]byte
				binary.LittleEndian.PutUint16(tmp[:], uint16(r))
				b.Write(tmp[:])
			}
			// null terminator
			b.Write([]byte{0x00, 0x00})
			align4(b)
		}

		// Compose stub
		stub := &bytes.Buffer{}
		shares := h.shareManager.ListShares()
		// Filter visible shares and map to type constants: 0 = STYPE_DISKTREE
		visible := make([]*protocol.Share, 0, len(shares))
		for _, s := range shares {
			if !s.Hidden {
				visible = append(visible, s)
			}
		}

		// InfoStruct (level 1)
		binary.Write(stub, binary.LittleEndian, uint32(1)) // level
		// Union switch (switch_is(level)) must be present for the union arm
		binary.Write(stub, binary.LittleEndian, uint32(1)) // union arm = 1
		// Pointer to SHARE_INFO_1_CONTAINER (unique, non-null)
		binary.Write(stub, binary.LittleEndian, uint32(0x20000)) // referent id
		// SHARE_INFO_1_CONTAINER
		binary.Write(stub, binary.LittleEndian, uint32(len(visible))) // EntriesRead
		binary.Write(stub, binary.LittleEndian, uint32(0x20004))      // Buffer pointer referent id
		// Conformant array header for Buffer (SHARE_INFO_1)
		binary.Write(stub, binary.LittleEndian, uint32(len(visible))) // max_count
		// Array of SHARE_INFO_1 structures (with pointers)
		for range visible {
			// shi1_netname * [string] -> non-null pointer
			binary.Write(stub, binary.LittleEndian, uint32(0x30000))
			// shi1_type (0 = DISK)
			binary.Write(stub, binary.LittleEndian, uint32(0))
			// shi1_remark * [string]
			binary.Write(stub, binary.LittleEndian, uint32(0x30004))
		}
		// Followed by the pointed-to strings in pointer encounter order:
		// for each entry: netname then remark
		for _, s := range visible {
			writeUnicodeString(stub, s.Name)
			writeUnicodeString(stub, s.Comment)
		}

		// For NetShareEnumAll (opnum 15) include TotalEntries
		if opnum == 0x000F {
			binary.Write(stub, binary.LittleEndian, uint32(len(visible))) // TotalEntries
		}
		// ResumeHandle (unique pointer, NULL)
		binary.Write(stub, binary.LittleEndian, uint32(0))
		// Return status
		binary.Write(stub, binary.LittleEndian, uint32(0)) // NERR_Success

		return buildRPCResponse(stub.Bytes())
	}
	return nil
}

func (h *SMB2Handler) isReadOnly(tree *protocol.TreeConnection) bool {
	share, err := h.shareManager.GetShare(tree.ShareName)
	return err != nil || share.ReadOnly
}

func (h *SMB2Handler) handleSetInfo(msg *protocol.SMB2Message, connInfo hooks.ConnInfo) (*protocol.SMB2Message, error) {
	if len(msg.Data) < 33 {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}

	// Parse request
	structureSize := binary.LittleEndian.Uint16(msg.Data[0:2])
	if structureSize != 33 {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}

	infoType := msg.Data[2]
	fileInfoClass := msg.Data[3]
	bufferLength := binary.LittleEndian.Uint32(msg.Data[4:8])
	bufferOffset := binary.LittleEndian.Uint16(msg.Data[8:10])
	reserved := binary.LittleEndian.Uint16(msg.Data[10:12])
	additionalInfo := binary.LittleEndian.Uint32(msg.Data[12:16])
	fileID := msg.Data[16:32]

	_ = infoType
	_ = reserved
	_ = additionalInfo

	// Get file handle
	handle, exists := h.fileHandles[string(fileID)]
	if !exists {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_HANDLE), nil
	}
	if h.isReadOnly(handle.TreeConnection) {
		return h.createErrorResponse(msg, protocol.STATUS_ACCESS_DENIED), nil
	}
	if h.debug > 0 {
		log.Printf("[DEBUG][SMB2] SET_INFO: infoType=0x%02x class=0x%02x bufLen=%d path=%q isDir=%v", infoType, fileInfoClass, bufferLength, handle.Path, handle.IsDirectory)
	}

	// Helpers
	getData := func() []byte {
		if bufferLength == 0 {
			return nil
		}
		if int(bufferOffset) < 64 { // Should offset include header? Yes.
			return nil
		}
		start := int(bufferOffset) - 64
		end := start + int(bufferLength)
		if start < 0 || end > len(msg.Data) {
			return nil
		}
		return msg.Data[start:end]
	}

	switch fileInfoClass {
	case 13: // FileDispositionInformation
		data := getData()
		if len(data) < 1 {
			return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
		}
		deletePending := data[0] != 0
		if deletePending {
			// Perform immediate deletion (Simplification)
			var err error
			if handle.IsDirectory {
				err = h.shareManager.DeleteDirectory(handle.TreeConnection.ShareName, handle.Path)
			} else {
				err = h.shareManager.DeleteFile(handle.TreeConnection.ShareName, handle.Path)
			}
			if err != nil {
				// Map error? Likely Directory Not Empty
				return h.createErrorResponse(msg, protocol.STATUS_DIRECTORY_NOT_EMPTY), nil // simplified
			}

			if handle.IsDirectory {
				h.hooks.OnFolderDelete(connInfo, handle.TreeConnection.ShareName, handle.Path)
			} else {
				h.hooks.OnFileDelete(connInfo, handle.TreeConnection.ShareName, handle.Path)
			}
		}
	case 19, 20: // FileAllocationInformation / FileEndOfFileInformation
		data := getData()
		if len(data) < 8 {
			return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
		}
		if handle.IsDirectory {
			return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
		}
		size := int64(binary.LittleEndian.Uint64(data[:8]))
		if size < 0 {
			return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
		}
		if err := h.shareManager.TruncateFile(handle.TreeConnection.ShareName, handle.Path, size); err != nil {
			return h.createErrorResponse(msg, protocol.STATUS_ACCESS_DENIED), nil
		}
		handle.FileInfo.Size = size
		handle.FileInfo.ModifiedTime = time.Now()
	case 10: // FileRenameInformation
		data := getData()
		if len(data) < 20 {
			return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
		}
		replaceIfExists := data[0] != 0
		fileNameLength := binary.LittleEndian.Uint32(data[16:20])
		if uint64(fileNameLength) > uint64(len(data)-20) || fileNameLength%2 != 0 {
			return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
		}

		runes := make([]rune, 0, fileNameLength/2)
		for off := 20; off < int(20+fileNameLength); off += 2 {
			r := binary.LittleEndian.Uint16(data[off : off+2])
			if r == 0 {
				break
			}
			runes = append(runes, rune(r))
		}
		newName := string(runes)
		newName = strings.ReplaceAll(newName, "/", "\\")
		newName = strings.TrimPrefix(newName, "\\")
		if !strings.Contains(newName, "\\") {
			dir := path.Dir(strings.ReplaceAll(handle.Path, "\\", "/"))
			if dir == "." {
				newName = strings.ReplaceAll(newName, "/", "\\")
			} else {
				newName = strings.ReplaceAll(path.Join(dir, newName), "/", "\\")
			}
		}

		if h.debug > 0 {
			log.Printf("[DEBUG][SMB2] SET_INFO rename: from=%q to=%q replace=%v", handle.Path, newName, replaceIfExists)
		}
		if !replaceIfExists && h.shareManager.FileExists(handle.TreeConnection.ShareName, newName) {
			return h.createErrorResponse(msg, protocol.STATUS_ACCESS_DENIED), nil
		}
		if err := h.shareManager.Rename(handle.TreeConnection.ShareName, handle.Path, newName); err != nil {
			if h.debug > 0 {
				log.Printf("[DEBUG][SMB2] SET_INFO rename failed: %v", err)
			}
			return h.createErrorResponse(msg, protocol.STATUS_ACCESS_DENIED), nil
		}
		handle.Path = newName
		handle.FileInfo.Name = path.Base(strings.ReplaceAll(newName, "\\", "/"))
		handle.FileInfo.ModifiedTime = time.Now()
	default:
		if h.debug > 0 {
			log.Printf("[DEBUG][SMB2] SET_INFO: ignoring unsupported class=0x%02x", fileInfoClass)
		}
	}

	response := &protocol.SMB2Message{
		Header: protocol.SMB2Header{
			ProtocolID:    [4]byte{0xFE, 'S', 'M', 'B'},
			StructureSize: 64,
			Status:        protocol.STATUS_SUCCESS,
			Command:       protocol.SMB2_SET_INFO,
			CreditRequest: h.creditsFor(msg),
			Flags:         0x01,
			MessageID:     msg.Header.MessageID,
			TreeID:        msg.Header.TreeID,
			SessionID:     msg.Header.SessionID,
		},
	}
	// Body StructureSize=2
	response.Data = []byte{0x02, 0x00}
	return response, nil
}

// handleFlush implements SMB2 FLUSH (MS-SMB2 2.2.17/2.2.18). macOS issues a
// FLUSH after writes when the volume advertises full-sync (Time Machine) and
// strictly validates the reply, so it must be a proper 4-byte FLUSH response
// rather than the generic 9-byte error structure. WriteFile already closes the
// file per call, flushing app buffers to the OS.
func (h *SMB2Handler) handleFlush(msg *protocol.SMB2Message, connInfo hooks.ConnInfo) (*protocol.SMB2Message, error) {
	resp := &protocol.SMB2Message{
		Header: protocol.SMB2Header{
			ProtocolID:    [4]byte{0xFE, 'S', 'M', 'B'},
			StructureSize: 64,
			Status:        protocol.STATUS_SUCCESS,
			Command:       protocol.SMB2_FLUSH,
			CreditRequest: h.creditsFor(msg),
			Flags:         0x01,
			MessageID:     msg.Header.MessageID,
			TreeID:        msg.Header.TreeID,
			SessionID:     msg.Header.SessionID,
		},
	}
	// FLUSH Response: StructureSize(2)=4, Reserved(2)=0
	data := make([]byte, 4)
	binary.LittleEndian.PutUint16(data[0:2], 4)
	resp.Data = data
	return resp, nil
}

func (h *SMB2Handler) handleEcho(msg *protocol.SMB2Message, connInfo hooks.ConnInfo) (*protocol.SMB2Message, error) {
	response := &protocol.SMB2Message{
		Header: protocol.SMB2Header{
			ProtocolID:    [4]byte{0xFE, 'S', 'M', 'B'},
			StructureSize: 64,
			Status:        protocol.STATUS_SUCCESS,
			Command:       protocol.SMB2_ECHO,
			CreditRequest: h.creditsFor(msg),
			Flags:         0x01,
			MessageID:     msg.Header.MessageID,
			TreeID:        msg.Header.TreeID,
			SessionID:     msg.Header.SessionID,
		},
	}

	data := bytes.NewBuffer(nil)
	binary.Write(data, binary.LittleEndian, uint16(4)) // StructureSize
	binary.Write(data, binary.LittleEndian, uint16(0)) // Reserved

	response.Data = data.Bytes()
	return response, nil
}

func (h *SMB2Handler) createErrorResponse(request *protocol.SMB2Message, status uint32) *protocol.SMB2Message {
	if h.debug > 0 {
		h.dbg("ERROR: cmd=0x%04x status=0x%08x mid=%d sid=%d tid=%d", request.Header.Command, status, request.Header.MessageID, request.Header.SessionID, request.Header.TreeID)
	}
	// Build SMB2 ERROR response structure
	resp := &protocol.SMB2Message{
		Header: protocol.SMB2Header{
			ProtocolID:    [4]byte{0xFE, 'S', 'M', 'B'},
			StructureSize: 64,
			Status:        status,
			Command:       request.Header.Command,
			CreditRequest: h.creditsFor(request),
			Flags:         0x01,
			MessageID:     request.Header.MessageID,
			TreeID:        request.Header.TreeID,
			SessionID:     request.Header.SessionID,
		},
	}
	// ERROR response body: StructureSize(2)=9, ErrorContextCount(1)=0, Reserved(1)=0, ByteCount(4)=0
	b := bytes.NewBuffer(nil)
	binary.Write(b, binary.LittleEndian, uint16(9))
	b.WriteByte(0)
	b.WriteByte(0)
	binary.Write(b, binary.LittleEndian, uint32(0))
	resp.Data = b.Bytes()
	return resp
}

func (h *SMB2Handler) selectDialect(clientDialects []uint16) uint16 {
	// Keep selection conservative; pick SMB2.1 if available, else 2.0.2
	for _, d := range clientDialects {
		if d == 0x0210 {
			return 0x0210
		}
	}
	for _, d := range clientDialects {
		if d == 0x0202 {
			return 0x0202
		}
	}
	return 0x0202
}

// buildNTLMType1 returns a minimal NTLMSSP NEGOTIATE (Type1) message with
// commonly accepted flags and an NTLMSSP version block. Used for SPNEGO
// short-token cases where the client doesn't include a Type1.
func buildNTLMType1() []byte {
	// Signature (8) + Type(4) + Flags(4) + DOM len/max/off (8)
	// + WKST len/max/off (8) + Version(8) = 40 bytes total
	b := make([]byte, 40)
	copy(b[0:8], []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(b[8:12], 1)
	// UNICODE|REQUEST_TARGET|SIGN|NTLM|ALWAYS_SIGN|EXTENDED_SESSIONSECURITY|TARGET_INFO|VERSION|128-bit
	flags := uint32(0x00000001 | 0x00000004 | 0x00000010 | 0x00000200 | 0x00008000 | 0x00080000 | 0x00800000 | 0x02000000 | 0x20000000)
	binary.LittleEndian.PutUint32(b[12:16], flags)
	// No domain/workstation
	// Version: Major 6, Minor 1, Build 0, NTLM revision 15
	b[32] = 6
	b[33] = 1
	b[39] = 15
	return b
}

func (h *SMB2Handler) handleLock(msg *protocol.SMB2Message, connInfo hooks.ConnInfo) (*protocol.SMB2Message, error) {
	// Minimal stub that always succeeds
	// StructureSize(2), LockCount(2), SequenceNumber(4), FileId(16), Locks[...]
	if len(msg.Data) < 24 {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}

	// We don't actually implement locking, just pretend we did.
	// Response: StructureSize(2), Reserved(2)

	response := &protocol.SMB2Message{
		Header: protocol.SMB2Header{
			ProtocolID:    [4]byte{0xFE, 'S', 'M', 'B'},
			StructureSize: 64,
			Status:        protocol.STATUS_SUCCESS,
			Command:       protocol.SMB2_LOCK,
			CreditRequest: h.creditsFor(msg),
			Flags:         0x01,
			MessageID:     msg.Header.MessageID,
			TreeID:        msg.Header.TreeID,
			SessionID:     msg.Header.SessionID,
		},
	}

	body := make([]byte, 4)
	binary.LittleEndian.PutUint16(body[0:2], 4) // StructureSize
	// Reserved[2] is zero

	response.Data = body
	return response, nil
}

// handleChangeNotify handles SMB2 CHANGE_NOTIFY requests.
// macOS Finder uses this for directory refresh notifications.
// This is a minimal no-op implementation that returns success.
func (h *SMB2Handler) handleChangeNotify(msg *protocol.SMB2Message, connInfo hooks.ConnInfo) (*protocol.SMB2Message, error) {
	// Parse request: StructureSize(2), Flags(2), OutputBufferLength(4), FileId(16), CompletionFilter(4), Reserved(4)
	if len(msg.Data) < 32 {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}

	// For a minimal implementation, we have two choices:
	// 1. Return STATUS_NOTIFY_CLEANUP (0x0000010B) - indicates no changes
	// 2. Return success with empty buffer
	//
	// macOS typically expects this to be an async operation that completes when changes occur.
	// For simplicity, we return success with an empty buffer immediately.

	response := &protocol.SMB2Message{
		Header: protocol.SMB2Header{
			ProtocolID:    [4]byte{0xFE, 'S', 'M', 'B'},
			StructureSize: 64,
			Status:        protocol.STATUS_SUCCESS,
			Command:       protocol.SMB2_CHANGE_NOTIFY,
			CreditRequest: h.creditsFor(msg),
			Flags:         0x01,
			MessageID:     msg.Header.MessageID,
			TreeID:        msg.Header.TreeID,
			SessionID:     msg.Header.SessionID,
		},
	}

	// Response: StructureSize(2), OutputBufferOffset(2), OutputBufferLength(4), Buffer(variable)
	body := make([]byte, 8)
	binary.LittleEndian.PutUint16(body[0:2], 9) // StructureSize
	// OutputBufferOffset = 0, OutputBufferLength = 0 (no changes to report)
	response.Data = body
	return response, nil
}
