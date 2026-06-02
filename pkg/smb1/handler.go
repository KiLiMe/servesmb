package smb1

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"github.com/3xport/servesmb/pkg/auth"
	"github.com/3xport/servesmb/pkg/ntlm"
	"github.com/3xport/servesmb/pkg/protocol"
	"github.com/3xport/servesmb/pkg/shares"
	"github.com/3xport/servesmb/pkg/spnego"
	"github.com/3xport/servesmb/pkg/utf16le"
)

// smb1FileHandle tracks an open file for SMB1 operations
type smb1FileHandle struct {
	fid       uint16
	shareName string
	path      string
	isDir     bool
	isPipe    bool
	treeID    uint16
}

type SMB1Handler struct {
	shareManager    *shares.ShareManager
	authenticator   *auth.NTLMAuthenticator
	sessions        map[uint16]*protocol.Session
	nextSessionID   uint16
	nextTreeID      uint16
	nextFID         uint16
	serverGUID      [16]byte
	pendingNTLM     map[uint16]*ntlm.Server
	pendingIsSPNEGO map[uint16]bool
	nativeOS        string
	nativeLanMan    string
	pipeData        map[uint16][]byte         // FID -> pending DCE/RPC response
	fileHandles     map[uint16]*smb1FileHandle // FID -> open file
}

func NewSMB1Handler(shareManager *shares.ShareManager, authenticator *auth.NTLMAuthenticator, nativeOS, nativeLanMan string) *SMB1Handler {
	h := &SMB1Handler{
		shareManager:    shareManager,
		authenticator:   authenticator,
		sessions:        make(map[uint16]*protocol.Session),
		nextSessionID:   1,
		nextTreeID:      1,
		nextFID:         1,
		pendingNTLM:     make(map[uint16]*ntlm.Server),
		pendingIsSPNEGO: make(map[uint16]bool),
		nativeOS:        nativeOS,
		nativeLanMan:    nativeLanMan,
		pipeData:        make(map[uint16][]byte),
		fileHandles:     make(map[uint16]*smb1FileHandle),
	}
	// Generate a simplified GUID (timestamp based)
	now := uint64(time.Now().UnixNano())
	binary.LittleEndian.PutUint64(h.serverGUID[:8], now)
	binary.LittleEndian.PutUint64(h.serverGUID[8:], now^0x55AA55AA55AA55AA)
	return h
}

func (h *SMB1Handler) HandleConnection(conn net.Conn) error {
	defer conn.Close()

	for {
		// Read SMB message
		msg, err := h.readMessage(conn)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("failed to read message: %v", err)
		}

		// Process message
		response, err := h.processMessage(msg)
		if err != nil {
			// Send error response
			response = h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER)
		}

		// Send response with NetBIOS Session Service header
		if response != nil {
			responseData, err := response.Marshal()
			if err == nil {
				nbHeader := make([]byte, 4)
				// NetBIOS Session Service: first byte is message type 0x00, next 3 are length
				nbHeader[0] = 0x00
				length := uint32(len(responseData))
				nbHeader[1] = byte((length >> 16) & 0xFF)
				nbHeader[2] = byte((length >> 8) & 0xFF)
				nbHeader[3] = byte(length & 0xFF)
				conn.Write(nbHeader)
				conn.Write(responseData)
			}
		}
	}
}

func (h *SMB1Handler) GetDialects() []string {
	return []string{
		protocol.SMB1_DIALECT_CORE,
		protocol.SMB1_DIALECT_LANMAN1,
		protocol.SMB1_DIALECT_LANMAN2,
		protocol.SMB1_DIALECT_NT,
	}
}

func (h *SMB1Handler) GetVersion() string {
	return "SMB1/CIFS"
}

func (h *SMB1Handler) readMessage(conn net.Conn) (*protocol.SMB1Message, error) {
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

	// Read SMB message
	msgData := make([]byte, msgLen)
	_, err = io.ReadFull(conn, msgData)
	if err != nil {
		return nil, err
	}

	// Parse SMB message
	msg := &protocol.SMB1Message{}
	err = msg.Unmarshal(msgData)
	if err != nil {
		return nil, err
	}

	return msg, nil
}

func (h *SMB1Handler) processMessage(msg *protocol.SMB1Message) (*protocol.SMB1Message, error) {
	switch msg.Header.Command {
	case protocol.SMB1_COM_NEGOTIATE:
		return h.handleNegotiate(msg)
	case protocol.SMB1_COM_SESSION_SETUP_ANDX:
		return h.handleSessionSetup(msg)
	case protocol.SMB1_COM_TREE_CONNECT_ANDX:
		return h.handleTreeConnect(msg)
	case protocol.SMB1_COM_FIND_FIRST2: // Actually SMB1_COM_TRANSACTION2 (0x32)
		return h.handleTransaction2(msg)
	case protocol.SMB1_COM_OPEN_ANDX:
		return h.handleOpenAndX(msg)
	case protocol.SMB1_COM_READ_ANDX:
		return h.handleReadAndX(msg)
	case protocol.SMB1_COM_CLOSE:
		return h.handleClose(msg)
	case protocol.SMB1_COM_NT_CREATE_ANDX:
		return h.handleNTCreateAndX(msg)
	case protocol.SMB1_COM_TRANSACTION:
		return h.handleTransaction(msg)
	case protocol.SMB1_COM_WRITE_ANDX:
		return h.handleWriteAndX(msg)
	case protocol.SMB1_COM_WRITE:
		return h.handleWrite(msg)
	case protocol.SMB1_COM_TREE_DISCONNECT:
		return h.handleTreeDisconnect(msg)
	case protocol.SMB1_COM_LOGOFF_ANDX:
		return h.handleLogoff(msg)
	case protocol.SMB1_COM_CREATE_DIRECTORY:
		return h.handleCreateDirectory(msg)
	case protocol.SMB1_COM_DELETE_DIRECTORY:
		return h.handleDeleteDirectory(msg)
	case protocol.SMB1_COM_CHECK_DIRECTORY:
		return h.handleCheckDirectory(msg)
	case protocol.SMB1_COM_DELETE:
		return h.handleDelete(msg)
	case protocol.SMB1_COM_RENAME:
		return h.handleRename(msg)
	case protocol.SMB1_COM_QUERY_INFORMATION2:
		return h.handleQueryInformation2(msg)
	default:
		log.Printf("[SMB1] Unsupported command: 0x%02X", msg.Header.Command)
		return h.createErrorResponse(msg, protocol.STATUS_NOT_SUPPORTED), nil
	}
}

func (h *SMB1Handler) handleNegotiate(msg *protocol.SMB1Message) (*protocol.SMB1Message, error) {
	// Parse dialect strings from data
	dialects := h.parseDialects(msg.Data)

	// Choose the best supported dialect
	selectedDialect := -1
	for i, dialect := range dialects {
		if dialect == protocol.SMB1_DIALECT_NT {
			selectedDialect = i
			break
		}
	}

	if selectedDialect == -1 && len(dialects) > 0 {
		selectedDialect = len(dialects) - 1 // Choose the last one
	}

	// Check if client supports/requests Extended Security
	// useExtSec = (msg.Header.Flags2 & 0x0800) != 0
	useExtSec := (msg.Header.Flags2 & 0x0800) != 0

	// Create response
	flags2 := uint16(0x8000 | 0x4000 | 0x0001) // Unicode | NTStatus | LongNames
	if useExtSec {
		flags2 |= 0x0800 // ExtendedSecurity
	}

	response := &protocol.SMB1Message{
		Header: protocol.SMB1Header{
			Protocol: [4]byte{0xFF, 'S', 'M', 'B'},
			Command:  protocol.SMB1_COM_NEGOTIATE,
			Status:   protocol.STATUS_SUCCESS,
			Flags:    0x80,   // Response flag
			Flags2:   flags2, // Unicode | NTStatus | [ExtendedSecurity] | LongNames
			MID:      msg.Header.MID,
		},
	}

	// Build negotiate response parameters matching NT LM 0.12 (exact 17 words)
	params := bytes.NewBuffer(nil)
	binary.Write(params, binary.LittleEndian, uint8(17))               // WordCount
	binary.Write(params, binary.LittleEndian, uint16(selectedDialect)) // DialectIndex
	// SecurityMode (1 byte) + padding (1 byte)
	binary.Write(params, binary.LittleEndian, uint8(protocol.SMB1_SECURITY_USER_LEVEL|0x02))
	binary.Write(params, binary.LittleEndian, uint16(50))    // MaxMpxCount
	binary.Write(params, binary.LittleEndian, uint16(1))     // MaxNumberVcs
	binary.Write(params, binary.LittleEndian, uint32(65535)) // MaxBufferSize (4 bytes)
	binary.Write(params, binary.LittleEndian, uint32(65536)) // MaxRawSize (4 bytes)
	binary.Write(params, binary.LittleEndian, uint32(0))     // SessionKey (4 bytes)

	// Capabilities
	caps := uint32(protocol.SMB1_CAP_LARGE_FILES | protocol.SMB1_CAP_NT_SMBS | protocol.SMB1_CAP_UNICODE |
		protocol.SMB1_CAP_STATUS32 | protocol.SMB1_CAP_RPC_REMOTE_APIS |
		protocol.SMB1_CAP_NT_FIND | protocol.SMB1_CAP_LEVEL_II_OPLOCKS)
	if useExtSec {
		caps |= protocol.SMB1_CAP_EXTENDED_SECURITY
	}
	binary.Write(params, binary.LittleEndian, caps) // Capabilities (4 bytes)

	// Server System Time (8 bytes)
	const ftEpoch = 116444736000000000
	nowft := uint64(time.Now().UnixNano()/100) + ftEpoch
	binary.Write(params, binary.LittleEndian, uint32(nowft&0xFFFFFFFF)) // SystemTimeLow
	binary.Write(params, binary.LittleEndian, uint32(nowft>>32))        // SystemTimeHigh
	binary.Write(params, binary.LittleEndian, uint16(0))                // ServerTimeZone

	if useExtSec {
		binary.Write(params, binary.LittleEndian, uint8(0)) // ChallengeLength
	} else {
		binary.Write(params, binary.LittleEndian, uint8(8)) // ChallengeLength
	}

	response.Parameters = params.Bytes()

	// Data section
	data := bytes.NewBuffer(nil)

	if useExtSec {
		// ServerGUID (16 bytes) + SecurityBlob
		data.Write(h.serverGUID[:])
		// GSS-API NegTokenInit with NTLM OID
		spnegoToken, _ := spnego.EncodeNegTokenInit([]asn1.ObjectIdentifier{spnego.NlmpOid}, nil)
		data.Write(spnegoToken)
	} else {
		// Legacy: EncryptionKey (8 bytes) + Strings
		// MS-SMB: Data contains EncryptionKey + DomainName [ + ServerName? ]

		// Use authenticator challenge to ensure Session Setup verification works
		challenge := h.authenticator.GetChallenge()
		if len(challenge) < 8 {
			// fallback if something is wrong (should be 8)
			data.Write(h.serverGUID[:8])
		} else {
			data.Write(challenge[:8])
		}

		// Strings (Unicode as per Flags2 0x8000)
		// Domain
		data.Write(utf16le.EncodeStringToBytes(h.authenticator.Domain()))
		data.Write([]byte{0x00, 0x00})
		// Server (Nmap expects this)
		data.Write(utf16le.EncodeStringToBytes(h.authenticator.Server()))
		data.Write([]byte{0x00, 0x00})
	}

	// Final Data block: ByteCount + Data
	finalData := bytes.NewBuffer(nil)
	binary.Write(finalData, binary.LittleEndian, uint16(data.Len()))
	finalData.Write(data.Bytes())

	response.Data = finalData.Bytes()

	return response, nil
}

func (h *SMB1Handler) handleSessionSetup(msg *protocol.SMB1Message) (*protocol.SMB1Message, error) {
	params := msg.Parameters
	if len(params) == 0 {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}
	wordCount := params[0]

	// Handle Extended Security (WordCount 12)
	if wordCount == 12 {
		return h.handleSessionSetupExtended(msg)
	}

	// Legacy NT LM 0.12 (WordCount 13)
	if wordCount == 13 {
		return h.handleSessionSetupNTLM012(msg)
	}

	return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
}

func (h *SMB1Handler) handleSessionSetupExtended(msg *protocol.SMB1Message) (*protocol.SMB1Message, error) {
	params := msg.Parameters
	// Layout: WordCount(1), AndX(4), MaxBuf(2), MaxMpx(2), VcNum(2), SessKey(4), SecBlobLen(2), Reserved(4), Caps(4)
	if len(params) < 1+4+2+2+2+4+2+4+4 {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}

	secBlobLen := binary.LittleEndian.Uint16(params[1+4+2+2+2+4 : 1+4+2+2+2+4+2])

	if len(msg.Data) < 2 {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}
	byteCount := binary.LittleEndian.Uint16(msg.Data[0:2])
	if int(byteCount) < int(secBlobLen) || len(msg.Data) < 2+int(secBlobLen) {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}

	securityBlob := msg.Data[2 : 2+int(secBlobLen)]

	// Determine if this is a new session or continuation
	uid := msg.Header.UID
	isNewSession := (uid == 0)

	var responseBlob []byte
	var status uint32

	if isNewSession {
		// Leg 1: NegTokenInit
		// Allocate new UID
		uid = h.nextSessionID
		h.nextSessionID++

		// Decode SPNEGO Init
		var mechToken []byte
		if len(securityBlob) > 0 && securityBlob[0] == 0x60 {
			init, err := spnego.DecodeNegTokenInit(securityBlob)
			if err == nil && init != nil {
				mechToken = init.MechToken
			}
		} else if len(securityBlob) >= 8 && bytes.Equal(securityBlob[:8], []byte("NTLMSSP\x00")) {
			mechToken = securityBlob
		} else {
			// Fallback or empty
		}

		// Initialize NTLM Server with the configured server name (mirrors the
		// SMB2 path). Previously this used the connection IP for every field, so
		// dnsName was an IP and buildTargetInfo omitted MsvAvDnsComputerName from
		// the challenge. Newer impacket (0.13.1) dereferences that AV pair
		// unconditionally on its SMB1 NTLMv2 path and crashes when it is absent,
		// so advertise a real (non-IP) computer name here.
		serverName := h.authenticator.Server()
		if serverName == "" {
			serverName = "127.0.0.1"
		}
		dnsName := ""
		if net.ParseIP(serverName) == nil {
			dnsName = strings.ToLower(serverName)
		}
		nt := ntlm.NewServer(serverName, serverName, h.authenticator.Domain(), dnsName, "")
		nt.AllowGuest()
		for u, pw := range h.authenticator.Users() {
			nt.AddAccount(u, pw)
		}

		challenge, err := nt.Challenge(mechToken)
		if err != nil {
			return h.createErrorResponse(msg, protocol.STATUS_LOGON_FAILURE), nil
		}

		// Store state
		h.pendingNTLM[uid] = nt
		h.pendingIsSPNEGO[uid] = (len(securityBlob) > 0 && securityBlob[0] == 0x60)

		// Create NegTokenResp
		if h.pendingIsSPNEGO[uid] {
			var err error
			// Use explicit OID to be safe/verbose
			responseBlob, err = spnego.EncodeNegTokenResp(1, spnego.NlmpOid, challenge, nil)
			if err != nil {
				// error handling
			}
		} else {
			// Raw NTLM response if client didn't use SPNEGO (unlikely for Extended Security but valid)
			responseBlob = challenge
		}

		status = protocol.STATUS_MORE_PROCESSING_REQUIRED
	} else {
		// Leg 2: NegTokenResp (Authenticate)
		nt, ok := h.pendingNTLM[uid]
		if !ok {
			return h.createErrorResponse(msg, protocol.STATUS_INVALID_HANDLE), nil
		}

		var authMsg []byte
		// Check for SPNEGO wrapper
		if len(securityBlob) > 0 && (securityBlob[0] == 0xA1 || securityBlob[0] == 0x60) {
			resp, err := spnego.DecodeNegTokenResp(securityBlob)
			if err == nil && resp != nil {
				authMsg = resp.ResponseToken
			}
		} else {
			authMsg = securityBlob
		}

		err := nt.Authenticate(authMsg)
		if err != nil {
			delete(h.pendingNTLM, uid)
			delete(h.pendingIsSPNEGO, uid)
			return h.createErrorResponse(msg, protocol.STATUS_LOGON_FAILURE), nil
		}

			// Authentication successful
			username := nt.Session().User()
			isGuest := strings.EqualFold(username, "guest") || username == ""
			session := &protocol.Session{
				ID:              uint64(uid),
				UserID:          uid,
				Username:        username,
				IsGuest:         isGuest,
				CreatedAt:       time.Now(),
				LastActivity:    time.Now(),
				TreeConnections: make(map[uint32]*protocol.TreeConnection),
			}
			h.sessions[uid] = session

		// Clean up pending
		isSPNEGO := h.pendingIsSPNEGO[uid]
		delete(h.pendingNTLM, uid)
		delete(h.pendingIsSPNEGO, uid)

		// Final response blob
		if isSPNEGO {
			responseBlob, _ = spnego.EncodeNegTokenAccepted()
		} else {
			responseBlob = nil
		}
		status = protocol.STATUS_SUCCESS
	}

	// Construct Response
	response := &protocol.SMB1Message{
		Header: protocol.SMB1Header{
			Protocol: [4]byte{0xFF, 'S', 'M', 'B'},
			Command:  protocol.SMB1_COM_SESSION_SETUP_ANDX,
			Status:   status,
			Flags:    0x80,
			Flags2:   0x8000 | 0x4000 | 0x0800 | 0x0001, // Unicode | NTStatus | ExtendedSecurity | LongNames
			UID:      uid,
			MID:      msg.Header.MID,
		},
	}

	// WordCount 4
	p := bytes.NewBuffer(nil)
	binary.Write(p, binary.LittleEndian, uint8(4))
	binary.Write(p, binary.LittleEndian, uint8(0xFF))               // AndX Command (None)
	binary.Write(p, binary.LittleEndian, uint8(0))                  // AndX Reserved
	binary.Write(p, binary.LittleEndian, uint16(0))                 // AndX Offset
		action := uint16(0)
		if sess := h.sessions[uid]; sess != nil && sess.IsGuest {
			action = 1
		}
		binary.Write(p, binary.LittleEndian, action)                    // Action (0=okay, 1=guest)
		binary.Write(p, binary.LittleEndian, uint16(len(responseBlob))) // SecurityBlobLen

	response.Parameters = p.Bytes()

	// Data
	d := bytes.NewBuffer(nil)

	// Write ByteCount + Blob + Strings

	dataContent := bytes.NewBuffer(nil)
	dataContent.Write(responseBlob)

	// Strings (Unicode = UTF-16LE)
	// NativeOS, NativeLanMan, Domain
	dataContent.Write(utf16le.EncodeStringToBytes(h.nativeOS))
	dataContent.Write([]byte{0x00, 0x00})
	dataContent.Write(utf16le.EncodeStringToBytes(h.nativeLanMan))
	dataContent.Write([]byte{0x00, 0x00})
	dataContent.Write([]byte{0x00, 0x00}) // Domain ""

	binary.Write(d, binary.LittleEndian, uint16(dataContent.Len()))
	d.Write(dataContent.Bytes())

	response.Data = d.Bytes()

	return response, nil
}

func (h *SMB1Handler) handleSessionSetupNTLM012(msg *protocol.SMB1Message) (*protocol.SMB1Message, error) {
	// Parse NT LM 0.12 Session Setup AndX (WordCount = 13)
	params := msg.Parameters

	// Extract AndX fields and lengths
	// layout after WordCount:
	// [AndX(1),Reserved(1),Offset(2), MaxBuf(2), MaxMpx(2), VC(2), SessKey(4), OemPwdLen(2), UniPwdLen(2), Reserved(4), Capabilities(4)]

	oemPwdLen := binary.LittleEndian.Uint16(params[1+2+2+2+2+2+4 : 1+2+2+2+2+2+4+2])
	uniPwdLen := binary.LittleEndian.Uint16(params[1+2+2+2+2+2+4+2 : 1+2+2+2+2+2+4+2+2])
	// Data starts with ByteCount
	if len(msg.Data) < 2 {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}
	byteCount := binary.LittleEndian.Uint16(msg.Data[0:2])
	if int(2+byteCount) > len(msg.Data) {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}
	d := msg.Data[2 : 2+byteCount]
	if len(d) < int(oemPwdLen)+int(uniPwdLen) {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}
	lmResp := d[:oemPwdLen]
	ntResp := d[oemPwdLen : oemPwdLen+uniPwdLen]
	// Remaining are strings: account, domain, nativeOS, nativeLanMan.
	rest := d[oemPwdLen+uniPwdLen:]
	// Detect Unicode
	isUnicode := (msg.Header.Flags2 & 0x8000) != 0
	readStr := func(b []byte) (string, []byte) {
		if isUnicode {
			// Align to 2-byte boundary
			if len(b) > 0 && (len(rest)-len(b))%2 != 0 {
				b = b[1:]
			}
			// UTF-16LE null-terminated
			for i := 0; i+1 < len(b); i += 2 {
				if b[i] == 0 && b[i+1] == 0 {
					// decode
					runes := make([]rune, i/2)
					for j := 0; j < i; j += 2 {
						runes[j/2] = rune(binary.LittleEndian.Uint16(b[j : j+2]))
					}
					return string(runes), b[i+2:]
				}
			}
			return "", nil
		}
		// OEM null-terminated
		for i := 0; i < len(b); i++ {
			if b[i] == 0x00 {
				return string(b[:i]), b[i+1:]
			}
		}
		return "", nil
	}
	username, rest2 := readStr(rest)
	if rest2 == nil {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}
	_, _ = readStr(rest2) // domain (optional)

	// Verify credentials
	log.Printf("[SMB1] NTLM012 Auth: User=%s OemLen=%d UniLen=%d", username, oemPwdLen, uniPwdLen)
	ok := h.authenticator.VerifySMB1Responses(username, lmResp, ntResp)
	if !ok {
		log.Printf("[SMB1] NTLM012 Auth Failed: VerifySMB1Responses returned false")
		return h.createErrorResponse(msg, protocol.STATUS_LOGON_FAILURE), nil
	}

		// Auth OK: create session for the user
		sessionID := h.nextSessionID
		h.nextSessionID++
		isGuest := strings.EqualFold(username, "guest") || username == ""
		session := &protocol.Session{
			ID:              uint64(sessionID),
			UserID:          sessionID,
			Username:        username,
			IsGuest:         isGuest,
			CreatedAt:       time.Now(),
			LastActivity:    time.Now(),
			TreeConnections: make(map[uint32]*protocol.TreeConnection),
		}
	h.sessions[sessionID] = session

	// Create response
	response := &protocol.SMB1Message{
		Header: protocol.SMB1Header{
			Protocol: [4]byte{0xFF, 'S', 'M', 'B'},
			Command:  protocol.SMB1_COM_SESSION_SETUP_ANDX,
			Status:   protocol.STATUS_SUCCESS,
			Flags:    0x80,            // Response flag
			Flags2:   0x4000 | 0x0001, // NTStatus | LongNames (No Unicode, forcing ASCII for Nmap compatibility)
			UID:      sessionID,
			MID:      msg.Header.MID,
		},
	}

	// Build parameters
	paramBuf := bytes.NewBuffer(nil)
	binary.Write(paramBuf, binary.LittleEndian, uint8(3))    // Word count
	binary.Write(paramBuf, binary.LittleEndian, uint8(0xFF)) // AndX command (none)
	binary.Write(paramBuf, binary.LittleEndian, uint8(0))    // AndX reserved
	binary.Write(paramBuf, binary.LittleEndian, uint16(0))   // AndX offset
		action := uint16(0)
		if isGuest {
			action = 1
		}
		binary.Write(paramBuf, binary.LittleEndian, action)      // Action flags

	response.Parameters = paramBuf.Bytes()

	// Data section
	data := bytes.NewBuffer(nil)

	// Strings are ASCII (Flags2 0x8000 is NOT set)
	// Native OS
	osBytes := []byte(h.nativeOS)
	// Native LanMan
	lmBytes := []byte(h.nativeLanMan)
	// Primary Domain
	domBytes := []byte(h.authenticator.Domain())

	// Total length including null terminators (1 byte each)
	totalLen := len(osBytes) + 1 + len(lmBytes) + 1 + len(domBytes) + 1

	binary.Write(data, binary.LittleEndian, uint16(totalLen))

	data.Write(osBytes)
	data.WriteByte(0x00)
	data.Write(lmBytes)
	data.WriteByte(0x00)
	data.Write(domBytes)
	data.WriteByte(0x00)

	response.Data = data.Bytes()

	return response, nil
}

func (h *SMB1Handler) handleTreeConnect(msg *protocol.SMB1Message) (*protocol.SMB1Message, error) {
	// Parse TreeConnectAndX (WordCount=4)
	params := msg.Parameters
	if len(params) < 8 { // WordCount(1) + AndX(4) + Flags(2) + PwdLen(2) = 9 bytes (min)
		log.Printf("[SMB1] TreeConn Invalid Params Len: %d", len(params))
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}

	pwdLen := binary.LittleEndian.Uint16(params[7:9])

	if len(msg.Data) < 2 {
		log.Printf("[SMB1] TreeConn Invalid Data Len: %d", len(msg.Data))
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}
	byteCount := binary.LittleEndian.Uint16(msg.Data[0:2])
	if int(byteCount) > len(msg.Data)-2 {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}

	d := msg.Data[2 : 2+byteCount]

	// Skip password
	if len(d) < int(pwdLen) {
		log.Printf("[SMB1] TreeConn Data too short for Pwd: %d < %d", len(d), pwdLen)
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}
	rest := d[pwdLen:]

	// Determine Unicode
	isUnicode := (msg.Header.Flags2 & 0x8000) != 0
	log.Printf("[SMB1] TreeConn: PwdLen=%d ByteCount=%d Unicode=%v Hex=%X", pwdLen, byteCount, isUnicode, rest)

	// Read Path
	var pathStr string
	if isUnicode {
		// Align relative to SMB Header start
		// Header(32) + Params(len) + ByteCount(2) + PwdLen
		// Params includes WordCount byte? Yes, msg.Parameters usually does.
		// Let's rely on standard offset logic:
		// We skipped 2 bytes for ByteCount, and pwdLen bytes.
		// Base of 'd' is Data section start.

		// If we assume standard TreeConnectAndX structure:
		// Header: 32
		// WordCount: 1
		// Words: 8 (4 words)
		// ByteCount: 2
		// Total before Data: 43.
		// Data[0] is at 43.
		// We are at Data[pwdLen]. Offset = 43 + pwdLen.
		// We need to align to 2 bytes.

		// Let's approximate offset based on known fixed header size (32) + params (9) + byteCount(2) = 43.
		currentOffset := 43 + int(pwdLen)
		if currentOffset%2 != 0 && len(rest) > 0 {
			rest = rest[1:]
		}

		// Decode UTF-16LE
		for i := 0; i+1 < len(rest); i += 2 {
			if rest[i] == 0 && rest[i+1] == 0 {
				runes := make([]rune, i/2)
				for j := 0; j < i; j += 2 {
					runes[j/2] = rune(binary.LittleEndian.Uint16(rest[j : j+2]))
				}
				pathStr = string(runes)
				break
			}
		}
	} else {
		for i := 0; i < len(rest); i++ {
			if rest[i] == 0 {
				pathStr = string(rest[:i])
				break
			}
		}
	}
	log.Printf("[SMB1] TreeConn Parsed Path: %q", pathStr)

	// Path should be \\server\share
	pathStr = strings.TrimSpace(pathStr)
	parts := strings.Split(pathStr, "\\")
	if len(parts) < 3 {
		// Try forward slashes if client sent them (unlikely for UNC but possible)
		if strings.Contains(pathStr, "/") {
			parts = strings.Split(pathStr, "/")
		}
	}
	if len(parts) < 1 { // Relaxed check
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}
	shareName := parts[len(parts)-1]

	// Helper to resolve share (case insensitive)
	// Simple map lookup for now
	// shareManager usually expects exact name?
	// Add crude case insensitivity:

	// Try exact first
	share, err := h.shareManager.GetShare(shareName)
	if err != nil {
		// Try uppercase
		share, err = h.shareManager.GetShare(strings.ToUpper(shareName))
	}
	if err != nil {
		return h.createErrorResponse(msg, protocol.STATUS_OBJECT_NAME_NOT_FOUND), nil
	}

	// Get session
	session, exists := h.sessions[msg.Header.UID]
	if !exists {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_HANDLE), nil
	}

	// Enforce share guest policy at tree connect so guest/null SMB1 sessions
	// cannot attach to non-guest shares.
	if share.Name != "IPC$" && !share.GuestAccess && (session.IsGuest || session.IsAnonymous) {
		return h.createErrorResponse(msg, protocol.STATUS_ACCESS_DENIED), nil
	}

	// Create tree connection
	treeID := uint32(h.nextTreeID)
	h.nextTreeID++

	treeConn := &protocol.TreeConnection{
		ID:        treeID,
		ShareName: share.Name,
		SharePath: share.Path,
		Session:   session,
	}

	session.TreeConnections[treeID] = treeConn

	// Create response
	response := &protocol.SMB1Message{
		Header: protocol.SMB1Header{
			Protocol: [4]byte{0xFF, 'S', 'M', 'B'},
			Command:  protocol.SMB1_COM_TREE_CONNECT_ANDX,
			Status:   protocol.STATUS_SUCCESS,
			Flags:    0x80,
			Flags2:   0x8000 | 0x4000 | 0x0001, // Unicode | NTStatus | LongNames
			UID:      msg.Header.UID,
			TID:      uint16(treeID),
			MID:      msg.Header.MID,
		},
	}

	// Build parameters
	paramsOut := bytes.NewBuffer(nil)
	binary.Write(paramsOut, binary.LittleEndian, uint8(3))    // Word count
	binary.Write(paramsOut, binary.LittleEndian, uint8(0xFF)) // AndX command (none)
	binary.Write(paramsOut, binary.LittleEndian, uint8(0))    // AndX reserved
	binary.Write(paramsOut, binary.LittleEndian, uint16(0))   // AndX offset
	binary.Write(paramsOut, binary.LittleEndian, uint16(1))   // Optional support (bits)

	// Support bits: 0x0001 (Search bits)

	response.Parameters = paramsOut.Bytes()

	// Data: Service (ASCII, usually "A:", "?????", "IPC")
	// "A:" for disk share, "IPC" for pipes
	service := "A:\x00"
	if share.Name == "IPC$" {
		service = "IPC\x00"
	}

	dataOut := bytes.NewBuffer(nil)
	binary.Write(dataOut, binary.LittleEndian, uint16(len(service)))
	dataOut.WriteString(service)

	response.Data = dataOut.Bytes()

	return response, nil
}

func (h *SMB1Handler) handleTransaction2(msg *protocol.SMB1Message) (*protocol.SMB1Message, error) {
	// Parse Transaction2 Request
	params := msg.Parameters
	if len(params) < 31 { // Need at least up to Setup[0]
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}

	// Subcommand is the first Setup word.
	// Offset calculation:
	// WordCount (1) + TotalParamCount(2) + TotalDataCount(2) + MaxParamCount(2) + MaxDataCount(2) +
	// MaxSetupCount(1) + Reserved(1) + Flags(2) + Timeout(4) + Reserved(2) +
	// ParamCount(2) + ParamOffset(2) + DataCount(2) + DataOffset(2) + SetupCount(1) + Reserved(1)
	// = 1 + 28 = 29.
	subcommand := binary.LittleEndian.Uint16(params[29:31])
	log.Printf("[DEBUG] Trans2 Subcommand: %d, Params: %X", subcommand, params)

	switch subcommand {
	case 1: // TRANS2_FIND_FIRST2
		return h.handleFindFirst2(msg)
	case 2: // TRANS2_FIND_NEXT2
		return h.createErrorResponse(msg, protocol.STATUS_NO_MORE_FILES), nil
	case 3: // TRANS2_QUERY_FS_INFORMATION
		return h.handleQueryFSInformation(msg)
	case 5: // TRANS2_QUERY_PATH_INFORMATION
		return h.handleQueryPathInformation(msg)
	case 6: // TRANS2_SET_PATH_INFORMATION
		return h.handleSetPathInformation(msg)
	case 7: // TRANS2_QUERY_FILE_INFORMATION
		return h.handleQueryFileInformation(msg)
	case 8: // TRANS2_SET_FILE_INFORMATION
		return h.handleSetFileInformation(msg)
	default:
		log.Printf("Unsupported Trans2 Subcommand: %d", subcommand)
		return h.createErrorResponse(msg, protocol.STATUS_NOT_SUPPORTED), nil
	}
}

func (h *SMB1Handler) handleQueryFSInformation(msg *protocol.SMB1Message) (*protocol.SMB1Message, error) {
	// Parse Trans2 Parameters to get InfoLevel
	params := msg.Parameters
	if len(params) < 23 {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}

	wordCount := params[0]
	// ParamOffset is at index 21 (1+2+2+2+2+1+1+2+4+2 = 19 bytes before ParamCount, +2 = 21)
	// Wait, previous calc: ParamCount(19), ParamOffset(21). Yes.
	paramOffset := binary.LittleEndian.Uint16(params[21:23])

	// Base offset of Data block relative to header start
	// msg.Data includes ByteCount (2 bytes) + Bytes
	// So base is Header(32) + WordCount(1) + Words(WC*2)
	baseOffset := 32 + 1 + int(wordCount)*2

	relativeOffset := int(paramOffset) - baseOffset

	var infoLevel uint16
	if relativeOffset >= 0 && relativeOffset+2 <= len(msg.Data) {
		infoLevel = binary.LittleEndian.Uint16(msg.Data[relativeOffset : relativeOffset+2])
	} else {
		// Fallback or error?
		log.Printf("[DEBUG] Invalid ParamOffset for QueryFSInfo: %d (Base: %d, DataLen: %d)", paramOffset, baseOffset, len(msg.Data))
		// Some clients might put params in Parameters block if small enough?
		// But Trans2 usually puts them in Data or separates them.
		// Let's assume default or error.
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}

	switch infoLevel {
	case 0x0001, 0x0102: // SMB_INFO_VOLUME / SMB_QUERY_FS_VOLUME_INFO
		return h.handleQueryFSVolumeInfo(msg)
	case 0x0002, 0x0103: // SMB_INFO_VOLUME_SIZE / SMB_QUERY_FS_SIZE_INFO
		return h.handleQueryFSSizeInfo(msg)
	case 0x0105: // SMB_QUERY_FS_ATTRIBUTE_INFO
		return h.handleQueryFSAttributeInfo(msg)
	case 0x03EF: // SMB_QUERY_FS_FULL_SIZE_INFO
		return h.handleQueryFSFullSizeInfo(msg)
	default:
		log.Printf("[DEBUG] Unsupported QueryFSInfo Level: 0x%04x", infoLevel)
		return h.createErrorResponse(msg, protocol.STATUS_NOT_SUPPORTED), nil
	}
}

func (h *SMB1Handler) handleQueryFSFullSizeInfo(msg *protocol.SMB1Message) (*protocol.SMB1Message, error) {
	dataOut := bytes.NewBuffer(nil)
	// TotalAllocationUnits (8)
	binary.Write(dataOut, binary.LittleEndian, uint64(10000))
	// CallerAvailableAllocationUnits (8)
	binary.Write(dataOut, binary.LittleEndian, uint64(5000))
	// ActualAvailableAllocationUnits (8)
	binary.Write(dataOut, binary.LittleEndian, uint64(5000))
	// SectorsPerUnit (4)
	binary.Write(dataOut, binary.LittleEndian, uint32(1))
	// BytesPerSector (4)
	binary.Write(dataOut, binary.LittleEndian, uint32(512))

	return h.buildTrans2Response(msg, dataOut.Bytes())
}

func (h *SMB1Handler) handleQueryFSSizeInfo(msg *protocol.SMB1Message) (*protocol.SMB1Message, error) {
	dataOut := bytes.NewBuffer(nil)
	// TotalAllocationUnits (8)
	binary.Write(dataOut, binary.LittleEndian, uint64(10000))
	// FreeAllocationUnits (8)
	binary.Write(dataOut, binary.LittleEndian, uint64(5000))
	// SectorsPerUnit (4)
	binary.Write(dataOut, binary.LittleEndian, uint32(1))
	// BytesPerSector (4)
	binary.Write(dataOut, binary.LittleEndian, uint32(512))

	return h.buildTrans2Response(msg, dataOut.Bytes())
}

// Helper to build generic Trans2 Response
func (h *SMB1Handler) buildTrans2Response(msg *protocol.SMB1Message, dataBytes []byte) (*protocol.SMB1Message, error) {
	response := &protocol.SMB1Message{
		Header: msg.Header,
	}
	response.Header.Flags = 0x88
	response.Header.Status = protocol.STATUS_SUCCESS

	// Calculate offsets
	// We want DataOffset at 56 (typical alignment)
	// Header(32) + WC(1) + Words(20) = 53 bytes
	// ByteCount(2) = 55 bytes
	// Pad(1) -> 56 bytes
	const dataOffset = 56
	padLen := 1

	paramsOut := bytes.NewBuffer(nil)
	binary.Write(paramsOut, binary.LittleEndian, uint8(10))              // Word count
	binary.Write(paramsOut, binary.LittleEndian, uint16(0))              // TotalParamCount
	binary.Write(paramsOut, binary.LittleEndian, uint16(len(dataBytes))) // TotalDataCount
	binary.Write(paramsOut, binary.LittleEndian, uint16(0))              // Reserved
	binary.Write(paramsOut, binary.LittleEndian, uint16(0))              // ParamCount
	binary.Write(paramsOut, binary.LittleEndian, uint16(dataOffset))     // ParamOffset
	binary.Write(paramsOut, binary.LittleEndian, uint16(0))              // ParamDisplacement
	binary.Write(paramsOut, binary.LittleEndian, uint16(len(dataBytes))) // DataCount
	binary.Write(paramsOut, binary.LittleEndian, uint16(dataOffset))     // DataOffset
	binary.Write(paramsOut, binary.LittleEndian, uint16(0))              // DataDisplacement
	binary.Write(paramsOut, binary.LittleEndian, uint8(0))               // SetupCount
	binary.Write(paramsOut, binary.LittleEndian, uint8(0))               // Reserved

	response.Parameters = paramsOut.Bytes()

	byteCount := uint16(padLen + len(dataBytes))
	dataWrapper := bytes.NewBuffer(nil)
	binary.Write(dataWrapper, binary.LittleEndian, byteCount)
	dataWrapper.WriteByte(0) // Pad
	dataWrapper.Write(dataBytes)

	response.Data = dataWrapper.Bytes()
	return response, nil
}

func (h *SMB1Handler) handleFindFirst2(msg *protocol.SMB1Message) (*protocol.SMB1Message, error) {
	treeConnArg := msg.Header.TID
	session, ok := h.sessions[msg.Header.UID]
	if !ok {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_HANDLE), nil
	}
	treeConn, ok := session.TreeConnections[uint32(treeConnArg)]
	if !ok {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_HANDLE), nil
	}

	// Parse the search pattern from Trans2 parameters.
	// Trans2 params: WC(1) + fixed(28) + SetupCount(1) + Reserved(1) + Setup(2) = 33 bytes header
	// FIND_FIRST2 parameters start at the ParamOffset in the Data section:
	//   SearchAttributes(2) + SearchCount(2) + Flags(2) + InfoLevel(2) + SearchStorageType(4) + SearchPattern(variable)
	searchPattern := "*"
	params := msg.Parameters
	if len(params) >= 23 {
		wordCount := int(params[0])
		paramOffset := int(binary.LittleEndian.Uint16(params[21:23]))
		baseOffset := 32 + 1 + wordCount*2
		relOff := paramOffset - baseOffset
		if relOff >= 0 && relOff+12 < len(msg.Data) {
			t2params := msg.Data[relOff:]
			// Skip SearchAttributes(2) + SearchCount(2) + Flags(2) + InfoLevel(2) + SearchStorageType(4) = 12
			nameBytes := t2params[12:]
			isUnicode := (msg.Header.Flags2 & 0x8000) != 0
			if isUnicode {
				var runes []rune
				for i := 0; i+1 < len(nameBytes); i += 2 {
					ch := rune(binary.LittleEndian.Uint16(nameBytes[i : i+2]))
					if ch == 0 {
						break
					}
					runes = append(runes, ch)
				}
				searchPattern = string(runes)
			} else {
				for i := 0; i < len(nameBytes); i++ {
					if nameBytes[i] == 0 {
						searchPattern = string(nameBytes[:i])
						break
					}
				}
			}
		}
	}
	searchPattern = strings.TrimLeft(searchPattern, "\\")

	// Determine directory path and filename filter from search pattern
	dirPath := ""
	fileFilter := searchPattern
	if idx := strings.LastIndex(searchPattern, "\\"); idx >= 0 {
		dirPath = searchPattern[:idx]
		fileFilter = searchPattern[idx+1:]
	}

	files, err := h.shareManager.ListDirectory(treeConn.ShareName, dirPath)
	if err != nil {
		return h.createErrorResponse(msg, protocol.STATUS_OBJECT_NAME_NOT_FOUND), nil
	}

	// Filter files if the pattern is not a wildcard
	if fileFilter != "*" && fileFilter != "*.*" && !strings.Contains(fileFilter, "?") && !strings.Contains(fileFilter, "*") {
		// Exact filename match
		var filtered []*protocol.FileInfo
		for _, f := range files {
			if strings.EqualFold(f.Name, fileFilter) {
				filtered = append(filtered, f)
			}
		}
		if len(filtered) == 0 {
			return h.createErrorResponse(msg, protocol.STATUS_NO_MORE_FILES), nil
		}
		files = filtered
	}

	// Prepare Data Block (FileList)
	// We assume InfoLevel 0x104 (SMB_FIND_FILE_BOTH_DIRECTORY_INFO)

	dataBuf := bytes.NewBuffer(nil)
	const InfoLevel = 0x104

	const ftEpoch = 116444736000000000
	toFT := func(t time.Time) uint64 {
		if t.IsZero() {
			return 0
		}
		return uint64(t.UnixNano()/100) + ftEpoch
	}

	maxFiles := len(files)

	for i := 0; i < maxFiles; i++ {
		file := files[i]
		fName := file.Name

		nameBytes := utf16le.EncodeStringToBytes(fName)
		fileNameLen := uint32(len(nameBytes))

		entrySize := uint32(94) + fileNameLen
		pad := (4 - (entrySize % 4)) % 4
		nextOffset := entrySize + pad
		if i == maxFiles-1 {
			nextOffset = 0
		}

		binary.Write(dataBuf, binary.LittleEndian, uint32(nextOffset))
		binary.Write(dataBuf, binary.LittleEndian, uint32(0)) // FileIndex
		binary.Write(dataBuf, binary.LittleEndian, toFT(file.CreatedTime))
		binary.Write(dataBuf, binary.LittleEndian, toFT(file.AccessedTime))
		binary.Write(dataBuf, binary.LittleEndian, toFT(file.ModifiedTime))
		binary.Write(dataBuf, binary.LittleEndian, toFT(file.ModifiedTime)) // Change

		fileSize := uint64(file.Size)
		allocSize := (fileSize + 4095) & ^uint64(4095) // round up to 4K
		binary.Write(dataBuf, binary.LittleEndian, fileSize)  // EndOfFile
		binary.Write(dataBuf, binary.LittleEndian, allocSize) // AllocationSize

		attrs := file.Attributes
		if attrs == 0 {
			if file.IsDirectory {
				attrs = protocol.FILE_ATTRIBUTE_DIRECTORY
			} else {
				attrs = protocol.FILE_ATTRIBUTE_NORMAL
			}
		}
		binary.Write(dataBuf, binary.LittleEndian, attrs)       // FileAttributes
		binary.Write(dataBuf, binary.LittleEndian, fileNameLen) // FileNameLength
		binary.Write(dataBuf, binary.LittleEndian, uint32(0))   // EaSize
		binary.Write(dataBuf, binary.LittleEndian, uint8(0))    // ShortNameLen
		binary.Write(dataBuf, binary.LittleEndian, uint8(0))    // Reserved
		dataBuf.Write(make([]byte, 24))                         // ShortName
		dataBuf.Write(nameBytes)
		if nextOffset != 0 {
			dataBuf.Write(make([]byte, pad))
		}
	}

	// Create Response
	response := &protocol.SMB1Message{
		Header: protocol.SMB1Header{
			Protocol: [4]byte{0xFF, 'S', 'M', 'B'},
			Command:  protocol.SMB1_COM_FIND_FIRST2,
			Status:   protocol.STATUS_SUCCESS,
			Flags:    0x80,
			Flags2:   0x8000 | 0x4000 | 0x0001,
			UID:      msg.Header.UID,
			TID:      msg.Header.TID,
			MID:      msg.Header.MID,
		},
	}

	// Params
	t2Params := bytes.NewBuffer(nil)
	binary.Write(t2Params, binary.LittleEndian, uint16(1))        // SID
	binary.Write(t2Params, binary.LittleEndian, uint16(maxFiles)) // Count
	binary.Write(t2Params, binary.LittleEndian, uint16(1))        // EndOfSearch
	binary.Write(t2Params, binary.LittleEndian, uint16(0))        // EA Error
	binary.Write(t2Params, binary.LittleEndian, uint16(0))        // Last Name Offset

	t2Data := dataBuf.Bytes()

	totalParam := uint16(t2Params.Len())
	totalData := uint16(len(t2Data))

	paramOffset := uint16(56)
	dataOffset := paramOffset + totalParam

	mainParams := bytes.NewBuffer(nil)
	binary.Write(mainParams, binary.LittleEndian, uint8(10))   // WordCount
	binary.Write(mainParams, binary.LittleEndian, totalParam)  // TotalParamCount
	binary.Write(mainParams, binary.LittleEndian, totalData)   // TotalDataCount
	binary.Write(mainParams, binary.LittleEndian, uint16(0))   // Reserved
	binary.Write(mainParams, binary.LittleEndian, totalParam)  // ParamCount
	binary.Write(mainParams, binary.LittleEndian, paramOffset) // ParamOffset
	binary.Write(mainParams, binary.LittleEndian, uint16(0))   // ParamDisp
	binary.Write(mainParams, binary.LittleEndian, totalData)   // DataCount
	binary.Write(mainParams, binary.LittleEndian, dataOffset)  // DataOffset
	binary.Write(mainParams, binary.LittleEndian, uint16(0))   // DataDisp
	binary.Write(mainParams, binary.LittleEndian, uint8(0))    // SetupCount
	binary.Write(mainParams, binary.LittleEndian, uint8(0))    // Reserved

	response.Parameters = mainParams.Bytes()

	mainData := bytes.NewBuffer(nil)
	mainData.WriteByte(0) // Pad to 56
	mainData.Write(t2Params.Bytes())
	mainData.Write(t2Data)

	finalC := bytes.NewBuffer(nil)
	binary.Write(finalC, binary.LittleEndian, uint16(mainData.Len()))
	finalC.Write(mainData.Bytes())

	response.Data = finalC.Bytes()

	return response, nil
}

// resolveTreeConn looks up the tree connection for a message.
func (h *SMB1Handler) resolveTreeConn(msg *protocol.SMB1Message) (*protocol.TreeConnection, error) {
	session, ok := h.sessions[msg.Header.UID]
	if !ok {
		return nil, fmt.Errorf("no session for uid %d", msg.Header.UID)
	}
	tc, ok := session.TreeConnections[uint32(msg.Header.TID)]
	if !ok {
		return nil, fmt.Errorf("no tree for tid %d", msg.Header.TID)
	}
	return tc, nil
}

func (h *SMB1Handler) handleOpenAndX(msg *protocol.SMB1Message) (*protocol.SMB1Message, error) {
	// Parse file name from Data section
	tc, err := h.resolveTreeConn(msg)
	if err != nil {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_HANDLE), nil
	}

	// Extract filename from Data (after ByteCount, possibly with Unicode alignment)
	fileName := h.extractFileName(msg)
	if fileName == "" {
		return h.createErrorResponse(msg, protocol.STATUS_OBJECT_NAME_NOT_FOUND), nil
	}

	fileInfo, err := h.shareManager.GetFileInfo(tc.ShareName, fileName)
	if err != nil {
		return h.createErrorResponse(msg, protocol.STATUS_OBJECT_NAME_NOT_FOUND), nil
	}

	fid := h.nextFID
	h.nextFID++
	h.fileHandles[fid] = &smb1FileHandle{
		fid: fid, shareName: tc.ShareName, path: fileName,
		isDir: fileInfo.IsDirectory, treeID: msg.Header.TID,
	}

	// Build response
	response := &protocol.SMB1Message{
		Header: protocol.SMB1Header{
			Protocol: [4]byte{0xFF, 'S', 'M', 'B'},
			Command:  protocol.SMB1_COM_OPEN_ANDX,
			Status:   protocol.STATUS_SUCCESS,
			Flags:    0x80,
			Flags2:   msg.Header.Flags2 | 0x4000,
			UID:      msg.Header.UID,
			TID:      msg.Header.TID,
			MID:      msg.Header.MID,
		},
	}

	attrs := uint32(protocol.FILE_ATTRIBUTE_NORMAL)
	if fileInfo.IsDirectory {
		attrs = protocol.FILE_ATTRIBUTE_DIRECTORY
	}

	p := bytes.NewBuffer(nil)
	binary.Write(p, binary.LittleEndian, uint8(15))     // WordCount
	binary.Write(p, binary.LittleEndian, uint8(0xFF))    // AndX (none)
	binary.Write(p, binary.LittleEndian, uint8(0))       // Reserved
	binary.Write(p, binary.LittleEndian, uint16(0))      // AndXOffset
	binary.Write(p, binary.LittleEndian, uint16(fid))    // FID
	binary.Write(p, binary.LittleEndian, uint32(attrs))  // Attributes
	binary.Write(p, binary.LittleEndian, uint32(0))      // LastWriteTime (DOS format)
	binary.Write(p, binary.LittleEndian, uint32(fileInfo.Size)) // File size
	binary.Write(p, binary.LittleEndian, uint16(0x0042)) // Granted access (read/write)
	binary.Write(p, binary.LittleEndian, uint16(0))      // FileType
	binary.Write(p, binary.LittleEndian, uint16(0))      // DeviceState
	binary.Write(p, binary.LittleEndian, uint16(1))      // Action (opened)
	binary.Write(p, binary.LittleEndian, uint32(0))      // ServerFID
	binary.Write(p, binary.LittleEndian, uint16(0))      // Reserved
	response.Parameters = p.Bytes()
	response.Data = []byte{0, 0} // ByteCount = 0
	return response, nil
}

// extractOldStyleName reads a name from old-style SMB commands that have
// ByteCount(2) + BufferFormat(1) + Name format.
func (h *SMB1Handler) extractOldStyleName(msg *protocol.SMB1Message) string {
	if len(msg.Data) < 4 {
		return ""
	}
	d := msg.Data[3:] // skip ByteCount(2) + BufferFormat(1)
	isUnicode := (msg.Header.Flags2 & 0x8000) != 0
	if isUnicode {
		// Word-align: the name starts after BufferFormat. Position = Header(32) + Params + ByteCount(2) + BufFmt(1).
		// If this total is odd, skip one pad byte.
		paramLen := 0
		if len(msg.Parameters) > 0 {
			paramLen = 1 + int(msg.Parameters[0])*2
		}
		pos := 32 + paramLen + 2 + 1
		if pos%2 != 0 && len(d) > 0 {
			d = d[1:]
		}
		var runes []rune
		for i := 0; i+1 < len(d); i += 2 {
			ch := rune(binary.LittleEndian.Uint16(d[i : i+2]))
			if ch == 0 {
				break
			}
			runes = append(runes, ch)
		}
		return strings.TrimLeft(string(runes), "\\")
	}
	for i := 0; i < len(d); i++ {
		if d[i] == 0 {
			return strings.TrimLeft(string(d[:i]), "\\")
		}
	}
	return ""
}

// extractFileName reads a null-terminated file name from msg.Data after ByteCount.
func (h *SMB1Handler) extractFileName(msg *protocol.SMB1Message) string {
	if len(msg.Data) < 3 {
		return ""
	}
	d := msg.Data[2:] // skip ByteCount
	isUnicode := (msg.Header.Flags2 & 0x8000) != 0
	if isUnicode {
		// Alignment pad
		if len(d) > 0 && d[0] == 0 {
			d = d[1:]
		}
		var runes []rune
		for i := 0; i+1 < len(d); i += 2 {
			ch := rune(binary.LittleEndian.Uint16(d[i : i+2]))
			if ch == 0 {
				break
			}
			runes = append(runes, ch)
		}
		return strings.TrimLeft(string(runes), "\\")
	}
	for i := 0; i < len(d); i++ {
		if d[i] == 0 {
			return strings.TrimLeft(string(d[:i]), "\\")
		}
	}
	return ""
}

func (h *SMB1Handler) handleReadAndX(msg *protocol.SMB1Message) (*protocol.SMB1Message, error) {
	// READ_ANDX: params[0]=WC, [1]=AndX, [2]=Res, [3:5]=AndXOff, [5:7]=FID, [7:11]=Offset, [11:13]=MaxCount
	reqParams := msg.Parameters
	if len(reqParams) < 13 {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}
	fid := binary.LittleEndian.Uint16(reqParams[5:7])
	offset := uint64(binary.LittleEndian.Uint32(reqParams[7:11]))
	maxCount := int(binary.LittleEndian.Uint16(reqParams[11:13]))

	// Check for pipe data first
	if pipeResp, ok := h.pipeData[fid]; ok {
		delete(h.pipeData, fid)
		return h.buildReadResponse(msg, pipeResp)
	}

	// Look up real file handle
	handle, ok := h.fileHandles[fid]
	if !ok {
		if fid == 0x4000 { // pipe with no data
			return h.buildReadResponse(msg, nil)
		}
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_HANDLE), nil
	}

	if handle.isPipe {
		return h.buildReadResponse(msg, nil)
	}

	// Real file read
	if maxCount <= 0 {
		maxCount = 4096
	}
	data, err := h.shareManager.ReadFile(handle.shareName, handle.path, int64(offset), maxCount)
	if err != nil {
		return h.createErrorResponse(msg, protocol.STATUS_OBJECT_NAME_NOT_FOUND), nil
	}
	return h.buildReadResponse(msg, data)
}

func (h *SMB1Handler) buildReadResponse(msg *protocol.SMB1Message, readData []byte) (*protocol.SMB1Message, error) {
	response := &protocol.SMB1Message{
		Header: protocol.SMB1Header{
			Protocol: [4]byte{0xFF, 'S', 'M', 'B'},
			Command:  protocol.SMB1_COM_READ_ANDX,
			Status:   protocol.STATUS_SUCCESS,
			Flags:    0x80,
			Flags2:   msg.Header.Flags2 | 0x4000,
			UID:      msg.Header.UID,
			TID:      msg.Header.TID,
			MID:      msg.Header.MID,
		},
	}

	// Data offset = Header(32) + WordCount(1) + Words(24) + ByteCount(2) + Pad(1) = 60
	const dataOffset = 60
	p := bytes.NewBuffer(nil)
	binary.Write(p, binary.LittleEndian, uint8(12))              // WordCount
	binary.Write(p, binary.LittleEndian, uint8(0xFF))            // AndX command (none)
	binary.Write(p, binary.LittleEndian, uint8(0))               // Reserved
	binary.Write(p, binary.LittleEndian, uint16(0))              // AndXOffset
	binary.Write(p, binary.LittleEndian, uint16(0))              // Available
	binary.Write(p, binary.LittleEndian, uint16(0))              // DataCompactionMode
	binary.Write(p, binary.LittleEndian, uint16(0))              // Reserved
	binary.Write(p, binary.LittleEndian, uint16(len(readData)))  // DataLength
	binary.Write(p, binary.LittleEndian, uint16(dataOffset))     // DataOffset
	binary.Write(p, binary.LittleEndian, uint16(0))              // DataLengthHigh
	p.Write(make([]byte, 8))                                     // Reserved (8 bytes, total 12 words = 24 bytes)
	response.Parameters = p.Bytes()

	d := bytes.NewBuffer(nil)
	binary.Write(d, binary.LittleEndian, uint16(1+len(readData))) // ByteCount
	d.WriteByte(0) // Pad
	d.Write(readData)
	response.Data = d.Bytes()

	return response, nil
}

func (h *SMB1Handler) handleClose(msg *protocol.SMB1Message) (*protocol.SMB1Message, error) {
	// Extract FID from parameters: params[0]=WC(=3), [1:3]=FID, [3:7]=LastWrite
	if len(msg.Parameters) >= 3 {
		fid := binary.LittleEndian.Uint16(msg.Parameters[1:3])
		delete(h.fileHandles, fid)
		delete(h.pipeData, fid)
	}
	return &protocol.SMB1Message{
		Header: protocol.SMB1Header{
			Protocol: [4]byte{0xFF, 'S', 'M', 'B'},
			Command:  protocol.SMB1_COM_CLOSE,
			Status:   protocol.STATUS_SUCCESS,
			Flags:    0x80,
			Flags2:   msg.Header.Flags2 | 0x4000,
			UID:      msg.Header.UID,
			TID:      msg.Header.TID,
			MID:      msg.Header.MID,
		},
		Parameters: []byte{0},
		Data:       []byte{0, 0},
	}, nil
}

// handleCreateDirectory implements SMB_COM_CREATE_DIRECTORY (0x00): create a
// directory by path. Data = BufferFormat(0x04) + DirectoryName.
func (h *SMB1Handler) handleCreateDirectory(msg *protocol.SMB1Message) (*protocol.SMB1Message, error) {
	tc, err := h.resolveTreeConn(msg)
	if err != nil {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_HANDLE), nil
	}
	dirName := h.extractOldStyleName(msg)
	if dirName == "" {
		return h.createErrorResponse(msg, protocol.STATUS_OBJECT_NAME_NOT_FOUND), nil
	}
	log.Printf("[SMB1] CREATE_DIRECTORY: %q on share %q", dirName, tc.ShareName)
	if err := h.shareManager.CreateDirectory(tc.ShareName, dirName); err != nil {
		return h.createErrorResponse(msg, protocol.STATUS_ACCESS_DENIED), nil
	}
	return &protocol.SMB1Message{
		Header: protocol.SMB1Header{
			Protocol: [4]byte{0xFF, 'S', 'M', 'B'},
			Command:  protocol.SMB1_COM_CREATE_DIRECTORY,
			Status:   protocol.STATUS_SUCCESS,
			Flags:    0x80,
			Flags2:   msg.Header.Flags2 | 0x4000,
			UID:      msg.Header.UID, TID: msg.Header.TID, MID: msg.Header.MID,
		},
		Parameters: []byte{0},    // WordCount = 0
		Data:       []byte{0, 0}, // ByteCount = 0
	}, nil
}

func (h *SMB1Handler) handleDeleteDirectory(msg *protocol.SMB1Message) (*protocol.SMB1Message, error) {
	// SMB_COM_DELETE_DIRECTORY: Data = ByteCount(2) + BufferFormat(1) + DirName
	tc, err := h.resolveTreeConn(msg)
	if err != nil {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_HANDLE), nil
	}
	dirName := h.extractOldStyleName(msg)
	if dirName == "" {
		return h.createErrorResponse(msg, protocol.STATUS_OBJECT_NAME_NOT_FOUND), nil
	}
	log.Printf("[SMB1] DELETE_DIRECTORY: %q", dirName)
	if err := h.shareManager.DeleteDirectory(tc.ShareName, dirName); err != nil {
		return h.createErrorResponse(msg, protocol.STATUS_ACCESS_DENIED), nil
	}
	return &protocol.SMB1Message{
		Header: protocol.SMB1Header{
			Protocol: [4]byte{0xFF, 'S', 'M', 'B'},
			Command:  protocol.SMB1_COM_DELETE_DIRECTORY,
			Status:   protocol.STATUS_SUCCESS,
			Flags:    0x80,
			Flags2:   msg.Header.Flags2 | 0x4000,
			UID:      msg.Header.UID, TID: msg.Header.TID, MID: msg.Header.MID,
		},
		Parameters: []byte{0},
		Data:       []byte{0, 0},
	}, nil
}

// handleCheckDirectory implements SMB_COM_CHECK_DIRECTORY (0x10): verify a path
// exists and is a directory. Impacket's SMB1 client calls check_dir() before
// rmdir; without this the client errors out before ever sending the delete, so
// directory removal over SMB1 appeared to fail. Data = BufferFormat(0x04) +
// DirectoryName (ASCII or UTF-16LE).
func (h *SMB1Handler) handleCheckDirectory(msg *protocol.SMB1Message) (*protocol.SMB1Message, error) {
	tc, err := h.resolveTreeConn(msg)
	if err != nil {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_HANDLE), nil
	}
	dirName := h.extractOldStyleName(msg)
	log.Printf("[SMB1] CHECK_DIRECTORY: %q", dirName)
	// An empty name (or "\") refers to the share root, which is always a
	// directory; otherwise the path must exist and be a directory.
	if dirName != "" && dirName != "\\" {
		info, err := h.shareManager.GetFileInfo(tc.ShareName, dirName)
		if err != nil || !info.IsDirectory {
			return h.createErrorResponse(msg, protocol.STATUS_OBJECT_NAME_NOT_FOUND), nil
		}
	}
	return &protocol.SMB1Message{
		Header: protocol.SMB1Header{
			Protocol: [4]byte{0xFF, 'S', 'M', 'B'},
			Command:  protocol.SMB1_COM_CHECK_DIRECTORY,
			Status:   protocol.STATUS_SUCCESS,
			Flags:    0x80,
			Flags2:   msg.Header.Flags2 | 0x4000,
			UID:      msg.Header.UID, TID: msg.Header.TID, MID: msg.Header.MID,
		},
		Parameters: []byte{0},
		Data:       []byte{0, 0},
	}, nil
}

// handleRename implements SMB_COM_RENAME (0x07): rename/move a file.
// Parameters = SearchAttributes(2); Data = BufferFormat(0x04) + OldName +
// BufferFormat(0x04) + NewName (each name is null-terminated, ASCII or UTF-16LE
// with 2-byte alignment padding).
func (h *SMB1Handler) handleRename(msg *protocol.SMB1Message) (*protocol.SMB1Message, error) {
	tc, err := h.resolveTreeConn(msg)
	if err != nil {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_HANDLE), nil
	}
	data := msg.Data
	if len(data) < 4 || len(msg.Parameters) < 1 {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}
	isUnicode := (msg.Header.Flags2 & 0x8000) != 0
	// Absolute offset of data[i] within the SMB message (header + wordcount byte
	// + words + ByteCount(2)), used for Unicode 2-byte alignment of names.
	base := 32 + 1 + int(msg.Parameters[0])*2
	p := 2 // skip ByteCount; data[2] is the first BufferFormat
	readName := func() (string, bool) {
		if p >= len(data) || data[p] != 0x04 {
			return "", false
		}
		p++ // skip BufferFormat
		if isUnicode {
			if (base+p)%2 != 0 {
				p++ // alignment pad
			}
			var runes []rune
			for p+1 < len(data) {
				ch := binary.LittleEndian.Uint16(data[p : p+2])
				p += 2
				if ch == 0 {
					break
				}
				runes = append(runes, rune(ch))
			}
			return strings.TrimLeft(string(runes), "\\"), true
		}
		start := p
		for p < len(data) && data[p] != 0 {
			p++
		}
		name := string(data[start:p])
		p++ // skip null terminator
		return strings.TrimLeft(name, "\\"), true
	}
	oldName, ok1 := readName()
	newName, ok2 := readName()
	if !ok1 || !ok2 || oldName == "" || newName == "" {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}
	log.Printf("[SMB1] RENAME: %q -> %q on share %q", oldName, newName, tc.ShareName)
	if err := h.shareManager.Rename(tc.ShareName, oldName, newName); err != nil {
		return h.createErrorResponse(msg, protocol.STATUS_OBJECT_NAME_NOT_FOUND), nil
	}
	return &protocol.SMB1Message{
		Header: protocol.SMB1Header{
			Protocol: [4]byte{0xFF, 'S', 'M', 'B'},
			Command:  protocol.SMB1_COM_RENAME,
			Status:   protocol.STATUS_SUCCESS,
			Flags:    0x80,
			Flags2:   msg.Header.Flags2 | 0x4000,
			UID:      msg.Header.UID, TID: msg.Header.TID, MID: msg.Header.MID,
		},
		Parameters: []byte{0},    // WordCount = 0
		Data:       []byte{0, 0}, // ByteCount = 0
	}, nil
}

// handleDelete implements SMB_COM_DELETE (0x06): delete a file by path.
// Request: Parameters = SearchAttributes(2); Data = BufferFormat(0x04) + FileName.
func (h *SMB1Handler) handleDelete(msg *protocol.SMB1Message) (*protocol.SMB1Message, error) {
	tc, err := h.resolveTreeConn(msg)
	if err != nil {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_HANDLE), nil
	}
	fileName := h.extractOldStyleName(msg)
	if fileName == "" {
		return h.createErrorResponse(msg, protocol.STATUS_OBJECT_NAME_NOT_FOUND), nil
	}
	log.Printf("[SMB1] DELETE: %q on share %q", fileName, tc.ShareName)
	if err := h.shareManager.DeleteFile(tc.ShareName, fileName); err != nil {
		return h.createErrorResponse(msg, protocol.STATUS_OBJECT_NAME_NOT_FOUND), nil
	}
	return &protocol.SMB1Message{
		Header: protocol.SMB1Header{
			Protocol: [4]byte{0xFF, 'S', 'M', 'B'},
			Command:  protocol.SMB1_COM_DELETE,
			Status:   protocol.STATUS_SUCCESS,
			Flags:    0x80,
			Flags2:   msg.Header.Flags2 | 0x4000,
			UID:      msg.Header.UID, TID: msg.Header.TID, MID: msg.Header.MID,
		},
		Parameters: []byte{0},    // WordCount = 0
		Data:       []byte{0, 0}, // ByteCount = 0
	}, nil
}

// dosDateTime converts t to MS-DOS SMB_DATE and SMB_TIME (2 bytes each), used
// by the legacy SMB_COM_QUERY_INFORMATION2 response.
func dosDateTime(t time.Time) (uint16, uint16) {
	if t.IsZero() || t.Year() < 1980 {
		t = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	date := uint16((t.Year()-1980)<<9 | int(t.Month())<<5 | t.Day())
	tm := uint16(t.Hour()<<11 | t.Minute()<<5 | t.Second()/2)
	return date, tm
}

// handleQueryInformation2 implements SMB_COM_QUERY_INFORMATION2 (0x23,
// "getattrE"): query a file's attributes/size by FID. smbclient uses this on
// NT1 before downloading a file (its "getattrib" step).
func (h *SMB1Handler) handleQueryInformation2(msg *protocol.SMB1Message) (*protocol.SMB1Message, error) {
	if len(msg.Parameters) < 3 {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}
	fid := binary.LittleEndian.Uint16(msg.Parameters[1:3])
	handle, ok := h.fileHandles[fid]
	if !ok {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_HANDLE), nil
	}
	fi, err := h.shareManager.GetFileInfo(handle.shareName, handle.path)
	if err != nil {
		return h.createErrorResponse(msg, protocol.STATUS_OBJECT_NAME_NOT_FOUND), nil
	}
	cD, cT := dosDateTime(fi.CreatedTime)
	aD, aT := dosDateTime(fi.AccessedTime)
	wD, wT := dosDateTime(fi.ModifiedTime)

	p := bytes.NewBuffer(nil)
	binary.Write(p, binary.LittleEndian, uint8(11)) // WordCount
	binary.Write(p, binary.LittleEndian, cD)        // CreationDate
	binary.Write(p, binary.LittleEndian, cT)        // CreationTime
	binary.Write(p, binary.LittleEndian, aD)        // LastAccessDate
	binary.Write(p, binary.LittleEndian, aT)        // LastAccessTime
	binary.Write(p, binary.LittleEndian, wD)        // LastWriteDate
	binary.Write(p, binary.LittleEndian, wT)        // LastWriteTime
	binary.Write(p, binary.LittleEndian, uint32(fi.Size)) // FileDataSize
	binary.Write(p, binary.LittleEndian, uint32(fi.Size)) // AllocationSize
	binary.Write(p, binary.LittleEndian, uint16(fi.Attributes)) // Attributes

	return &protocol.SMB1Message{
		Header: protocol.SMB1Header{
			Protocol: [4]byte{0xFF, 'S', 'M', 'B'},
			Command:  protocol.SMB1_COM_QUERY_INFORMATION2,
			Status:   protocol.STATUS_SUCCESS,
			Flags:    0x80,
			Flags2:   msg.Header.Flags2 | 0x4000,
			UID:      msg.Header.UID, TID: msg.Header.TID, MID: msg.Header.MID,
		},
		Parameters: p.Bytes(),
		Data:       []byte{0, 0}, // ByteCount = 0
	}, nil
}

func (h *SMB1Handler) handleLogoff(msg *protocol.SMB1Message) (*protocol.SMB1Message, error) {
	delete(h.sessions, msg.Header.UID)
	p := bytes.NewBuffer(nil)
	binary.Write(p, binary.LittleEndian, uint8(2))    // WordCount
	binary.Write(p, binary.LittleEndian, uint8(0xFF))  // AndX (none)
	binary.Write(p, binary.LittleEndian, uint8(0))
	binary.Write(p, binary.LittleEndian, uint16(0))
	return &protocol.SMB1Message{
		Header: protocol.SMB1Header{
			Protocol: [4]byte{0xFF, 'S', 'M', 'B'},
			Command:  protocol.SMB1_COM_LOGOFF_ANDX,
			Status:   protocol.STATUS_SUCCESS,
			Flags:    0x80,
			Flags2:   msg.Header.Flags2 | 0x4000,
			UID:      msg.Header.UID,
			MID:      msg.Header.MID,
		},
		Parameters: p.Bytes(),
		Data:       []byte{0, 0},
	}, nil
}

func (h *SMB1Handler) handleWrite(msg *protocol.SMB1Message) (*protocol.SMB1Message, error) {
	// SMB_COM_WRITE: params[0]=WC(5), [1:3]=FID, [3:5]=Count, [5:9]=Offset, [9:11]=Remaining
	params := msg.Parameters
	if len(params) < 11 {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}
	fid := binary.LittleEndian.Uint16(params[1:3])
	count := binary.LittleEndian.Uint16(params[3:5])
	offset := binary.LittleEndian.Uint32(params[5:9])

	// Data: ByteCount(2) + BufferFormat(1) + DataLength(2) + Data
	if len(msg.Data) < 5+int(count) {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}
	writeData := msg.Data[5 : 5+int(count)]

	handle, ok := h.fileHandles[fid]
	if !ok {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_HANDLE), nil
	}

	if handle.isPipe {
		// Process DCE/RPC for pipes
		if len(writeData) >= 2 && writeData[0] == 5 && writeData[1] == 0 {
			pktType := writeData[2]
			var rpcResp []byte
			switch pktType {
			case 11:
				rpcResp = h.buildRPCBindAck(writeData)
			case 0:
				rpcResp = h.buildRPCResponse(writeData)
			}
			if rpcResp != nil {
				h.pipeData[fid] = rpcResp
			}
		}
	} else {
		// Real file write
		_, err := h.shareManager.WriteFile(handle.shareName, handle.path, int64(offset), writeData)
		if err != nil {
			return h.createErrorResponse(msg, protocol.STATUS_ACCESS_DENIED), nil
		}
	}

	// Build response
	p := bytes.NewBuffer(nil)
	binary.Write(p, binary.LittleEndian, uint8(1))     // WordCount
	binary.Write(p, binary.LittleEndian, uint16(count)) // Count written
	return &protocol.SMB1Message{
		Header: protocol.SMB1Header{
			Protocol: [4]byte{0xFF, 'S', 'M', 'B'},
			Command:  protocol.SMB1_COM_WRITE,
			Status:   protocol.STATUS_SUCCESS,
			Flags:    0x80,
			Flags2:   msg.Header.Flags2 | 0x4000,
			UID:      msg.Header.UID,
			TID:      msg.Header.TID,
			MID:      msg.Header.MID,
		},
		Parameters: p.Bytes(),
		Data:       []byte{0, 0},
	}, nil
}

func (h *SMB1Handler) handleQueryFSVolumeInfo(msg *protocol.SMB1Message) (*protocol.SMB1Message, error) {
	volLabel := "SMB Share"
	volLabelBytes := utf16le.EncodeStringToBytes(volLabel)

	dataOut := bytes.NewBuffer(nil)
	// VolumeCreationTime (8)
	const ftEpoch = 116444736000000000
	binary.Write(dataOut, binary.LittleEndian, uint64(time.Now().UnixNano()/100)+ftEpoch)
	// VolumeSerialNumber (4)
	binary.Write(dataOut, binary.LittleEndian, uint32(0x12345678))
	// VolumeLabelSize (4)
	binary.Write(dataOut, binary.LittleEndian, uint32(len(volLabelBytes)))
	// Reserved (2)
	binary.Write(dataOut, binary.LittleEndian, uint16(0))
	// VolumeLabel
	dataOut.Write(volLabelBytes)

	return h.buildTrans2Response(msg, dataOut.Bytes())
}

func (h *SMB1Handler) handleQueryPathInformation(msg *protocol.SMB1Message) (*protocol.SMB1Message, error) {
	// Parse Trans2 parameters to get InfoLevel and FileName
	params := msg.Parameters
	if len(params) < 27 {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}
	wordCount := params[0]
	paramCount := binary.LittleEndian.Uint16(params[19:21])
	paramOffset := binary.LittleEndian.Uint16(params[21:23])

	baseOffset := 32 + 1 + int(wordCount)*2
	relOff := int(paramOffset) - baseOffset
	if relOff < 0 || relOff+int(paramCount) > len(msg.Data) {
		relOff = 2 // fallback: after ByteCount
	}

	trans2Params := msg.Data[relOff:]
	if len(trans2Params) < 6 {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}
	infoLevel := binary.LittleEndian.Uint16(trans2Params[0:2])
	// reserved 4 bytes, then file name
	nameBytes := trans2Params[6:]

	// Parse file name (Unicode or ASCII)
	isUnicode := (msg.Header.Flags2 & 0x8000) != 0
	var fileName string
	if isUnicode {
		var runes []rune
		for i := 0; i+1 < len(nameBytes); i += 2 {
			ch := rune(binary.LittleEndian.Uint16(nameBytes[i : i+2]))
			if ch == 0 {
				break
			}
			runes = append(runes, ch)
		}
		fileName = string(runes)
	} else {
		for i := 0; i < len(nameBytes); i++ {
			if nameBytes[i] == 0 {
				fileName = string(nameBytes[:i])
				break
			}
		}
	}
	fileName = strings.TrimLeft(fileName, "\\")
	if fileName == "" {
		fileName = "." // root directory
	}

	// Look up tree connection
	tc, err := h.resolveTreeConn(msg)
	if err != nil {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_HANDLE), nil
	}

	// Get file info
	fileInfo, err := h.shareManager.GetFileInfo(tc.ShareName, fileName)
	if err != nil {
		return h.createErrorResponse(msg, protocol.STATUS_OBJECT_NAME_NOT_FOUND), nil
	}

	const epoch = 116444736000000000
	toFT := func(t time.Time) uint64 {
		return uint64(t.UnixNano()/100) + epoch
	}

	dataOut := bytes.NewBuffer(nil)

	switch infoLevel {
	case 0x0101: // SMB_QUERY_FILE_BASIC_INFO
		binary.Write(dataOut, binary.LittleEndian, toFT(fileInfo.CreatedTime))  // Creation
		binary.Write(dataOut, binary.LittleEndian, toFT(fileInfo.AccessedTime)) // LastAccess
		binary.Write(dataOut, binary.LittleEndian, toFT(fileInfo.ModifiedTime)) // LastWrite
		binary.Write(dataOut, binary.LittleEndian, toFT(fileInfo.ModifiedTime)) // Change
		binary.Write(dataOut, binary.LittleEndian, fileInfo.Attributes)         // Attributes
		binary.Write(dataOut, binary.LittleEndian, uint32(0))                   // Reserved

	case 0x0102: // SMB_QUERY_FILE_STANDARD_INFO
		binary.Write(dataOut, binary.LittleEndian, uint64(fileInfo.Size))  // AllocationSize
		binary.Write(dataOut, binary.LittleEndian, uint64(fileInfo.Size))  // EndOfFile
		binary.Write(dataOut, binary.LittleEndian, uint32(1))              // NumberOfLinks
		if fileInfo.IsDirectory {
			dataOut.WriteByte(0) // DeletePending
			dataOut.WriteByte(1) // Directory
		} else {
			dataOut.WriteByte(0)
			dataOut.WriteByte(0)
		}

	case 0x0107: // SMB_QUERY_FILE_ALL_INFO
		// BasicInfo
		binary.Write(dataOut, binary.LittleEndian, toFT(fileInfo.CreatedTime))
		binary.Write(dataOut, binary.LittleEndian, toFT(fileInfo.AccessedTime))
		binary.Write(dataOut, binary.LittleEndian, toFT(fileInfo.ModifiedTime))
		binary.Write(dataOut, binary.LittleEndian, toFT(fileInfo.ModifiedTime))
		binary.Write(dataOut, binary.LittleEndian, fileInfo.Attributes)
		binary.Write(dataOut, binary.LittleEndian, uint32(0)) // Reserved
		// StandardInfo
		binary.Write(dataOut, binary.LittleEndian, uint64(fileInfo.Size))
		binary.Write(dataOut, binary.LittleEndian, uint64(fileInfo.Size))
		binary.Write(dataOut, binary.LittleEndian, uint32(1))
		if fileInfo.IsDirectory {
			dataOut.WriteByte(0)
			dataOut.WriteByte(1)
		} else {
			dataOut.WriteByte(0)
			dataOut.WriteByte(0)
		}
		dataOut.Write(make([]byte, 2)) // padding
		// EaInfo
		binary.Write(dataOut, binary.LittleEndian, uint32(0))
		// AccessInfo (not usually part but pad)
		binary.Write(dataOut, binary.LittleEndian, uint32(0x001f01ff)) // access flags
		// PositionInfo
		binary.Write(dataOut, binary.LittleEndian, uint64(0))
		// ModeInfo
		binary.Write(dataOut, binary.LittleEndian, uint32(0))
		// AlignmentInfo
		binary.Write(dataOut, binary.LittleEndian, uint32(0))
		// NameInfo
		nameU := utf16le.EncodeStringToBytes(fileName)
		binary.Write(dataOut, binary.LittleEndian, uint32(len(nameU)))
		dataOut.Write(nameU)

	default:
		log.Printf("[SMB1] Unsupported QueryPathInfo level: 0x%04x for %q", infoLevel, fileName)
		return h.createErrorResponse(msg, protocol.STATUS_NOT_SUPPORTED), nil
	}

	// Trans2 response with parameter section (2 bytes EA error offset = 0)
	t2Params := []byte{0, 0}
	return h.buildTrans2ResponseWithParams(msg, t2Params, dataOut.Bytes())
}

func (h *SMB1Handler) handleQueryFileInformation(msg *protocol.SMB1Message) (*protocol.SMB1Message, error) {
	// Trans2 QUERY_FILE_INFORMATION: parameters contain FID(2) + InfoLevel(2)
	params := msg.Parameters
	if len(params) < 23 {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}
	wordCount := int(params[0])
	paramOffset := int(binary.LittleEndian.Uint16(params[21:23]))
	baseOffset := 32 + 1 + wordCount*2
	relOff := paramOffset - baseOffset
	if relOff < 0 || relOff+4 > len(msg.Data) {
		relOff = 2
	}
	t2p := msg.Data[relOff:]
	if len(t2p) < 4 {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}
	fid := binary.LittleEndian.Uint16(t2p[0:2])
	infoLevel := binary.LittleEndian.Uint16(t2p[2:4])

	handle, ok := h.fileHandles[fid]
	if !ok {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_HANDLE), nil
	}

	tc, _ := h.resolveTreeConn(msg)
	shareName := ""
	if tc != nil {
		shareName = tc.ShareName
	} else if handle.shareName != "" {
		shareName = handle.shareName
	}

	fileInfo, err := h.shareManager.GetFileInfo(shareName, handle.path)
	if err != nil {
		return h.createErrorResponse(msg, protocol.STATUS_OBJECT_NAME_NOT_FOUND), nil
	}

	const epoch = 116444736000000000
	toFT := func(t time.Time) uint64 { return uint64(t.UnixNano()/100) + epoch }

	dataOut := bytes.NewBuffer(nil)
	switch infoLevel {
	case 0x0101: // SMB_QUERY_FILE_BASIC_INFO
		binary.Write(dataOut, binary.LittleEndian, toFT(fileInfo.CreatedTime))
		binary.Write(dataOut, binary.LittleEndian, toFT(fileInfo.AccessedTime))
		binary.Write(dataOut, binary.LittleEndian, toFT(fileInfo.ModifiedTime))
		binary.Write(dataOut, binary.LittleEndian, toFT(fileInfo.ModifiedTime))
		attrs := fileInfo.Attributes
		if attrs == 0 {
			if fileInfo.IsDirectory {
				attrs = protocol.FILE_ATTRIBUTE_DIRECTORY
			} else {
				attrs = protocol.FILE_ATTRIBUTE_NORMAL
			}
		}
		binary.Write(dataOut, binary.LittleEndian, attrs)
		binary.Write(dataOut, binary.LittleEndian, uint32(0)) // Reserved
	case 0x0102: // SMB_QUERY_FILE_STANDARD_INFO
		binary.Write(dataOut, binary.LittleEndian, uint64(fileInfo.Size))
		binary.Write(dataOut, binary.LittleEndian, uint64(fileInfo.Size))
		binary.Write(dataOut, binary.LittleEndian, uint32(1)) // NumberOfLinks
		deletePending := uint8(0)
		isDir := uint8(0)
		if fileInfo.IsDirectory {
			isDir = 1
		}
		dataOut.WriteByte(deletePending)
		dataOut.WriteByte(isDir)
	default:
		log.Printf("[SMB1] Unsupported QueryFileInfo level: 0x%04x fid=0x%04x", infoLevel, fid)
		return h.createErrorResponse(msg, protocol.STATUS_NOT_SUPPORTED), nil
	}

	return h.buildTrans2ResponseWithParams(msg, []byte{0, 0}, dataOut.Bytes())
}

func (h *SMB1Handler) handleSetFileInformation(msg *protocol.SMB1Message) (*protocol.SMB1Message, error) {
	// Trans2 SET_FILE_INFORMATION: parameters contain FID(2) + InfoLevel(2) + Reserved(2)
	params := msg.Parameters
	if len(params) < 23 {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}
	wordCount := int(params[0])
	paramOffset := int(binary.LittleEndian.Uint16(params[21:23]))
	dataCount := int(binary.LittleEndian.Uint16(params[23:25]))
	dataOffset := int(binary.LittleEndian.Uint16(params[25:27]))
	baseOffset := 32 + 1 + wordCount*2

	relParamOff := paramOffset - baseOffset
	if relParamOff < 0 || relParamOff+4 > len(msg.Data) {
		relParamOff = 2
	}
	t2p := msg.Data[relParamOff:]
	if len(t2p) < 4 {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}
	fid := binary.LittleEndian.Uint16(t2p[0:2])
	infoLevel := binary.LittleEndian.Uint16(t2p[2:4])

	handle, ok := h.fileHandles[fid]
	if !ok {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_HANDLE), nil
	}

	// Get the set data
	relDataOff := dataOffset - baseOffset
	if relDataOff < 0 || relDataOff+dataCount > len(msg.Data) {
		relDataOff = relParamOff + 6 // after params
	}

	log.Printf("[SMB1] SET_FILE_INFO: fid=0x%04x level=0x%04x file=%q", fid, infoLevel, handle.path)

	switch infoLevel {
	case 0x0101: // SMB_SET_FILE_BASIC_INFO (timestamps/attributes) — accept
	case 0x0102: // SMB_SET_FILE_DISPOSITION_INFO (delete on close)
		if relDataOff < len(msg.Data) && msg.Data[relDataOff] != 0 {
			if handle.isDir {
				h.shareManager.DeleteDirectory(handle.shareName, handle.path)
			} else {
				h.shareManager.DeleteFile(handle.shareName, handle.path)
			}
		}
	case 0x0103: // SMB_SET_FILE_ALLOCATION_INFO — accept (no-op)
	case 0x0104: // SMB_SET_FILE_END_OF_FILE_INFO (truncate)
		if relDataOff+8 <= len(msg.Data) {
			newSize := int64(binary.LittleEndian.Uint64(msg.Data[relDataOff : relDataOff+8]))
			h.shareManager.TruncateFile(handle.shareName, handle.path, newSize)
		}
	default:
		log.Printf("[SMB1] Unsupported SetFileInfo level: 0x%04x", infoLevel)
	}

	// Return success with empty params
	return h.buildTrans2ResponseWithParams(msg, []byte{0, 0}, nil)
}

func (h *SMB1Handler) handleSetPathInformation(msg *protocol.SMB1Message) (*protocol.SMB1Message, error) {
	// Trans2 SET_PATH_INFORMATION: similar to QUERY_PATH but for setting attributes
	// For mkdir, XP uses this with InfoLevel to create/set attributes on a path
	params := msg.Parameters
	if len(params) < 27 {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}
	wordCount := int(params[0])
	paramOffset := int(binary.LittleEndian.Uint16(params[21:23]))
	baseOffset := 32 + 1 + wordCount*2
	relOff := paramOffset - baseOffset
	if relOff < 0 {
		relOff = 2
	}

	t2p := msg.Data[relOff:]
	if len(t2p) < 6 {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}
	infoLevel := binary.LittleEndian.Uint16(t2p[0:2])
	// reserved 4 bytes, then filename
	nameBytes := t2p[6:]

	isUnicode := (msg.Header.Flags2 & 0x8000) != 0
	var fileName string
	if isUnicode {
		var runes []rune
		for i := 0; i+1 < len(nameBytes); i += 2 {
			ch := rune(binary.LittleEndian.Uint16(nameBytes[i : i+2]))
			if ch == 0 {
				break
			}
			runes = append(runes, ch)
		}
		fileName = string(runes)
	} else {
		for i := 0; i < len(nameBytes); i++ {
			if nameBytes[i] == 0 {
				fileName = string(nameBytes[:i])
				break
			}
		}
	}
	fileName = strings.TrimLeft(fileName, "\\")

	tc, _ := h.resolveTreeConn(msg)
	if tc == nil {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_HANDLE), nil
	}

	log.Printf("[SMB1] SET_PATH_INFO: level=0x%04x path=%q", infoLevel, fileName)

	switch infoLevel {
	case 0x0101: // SMB_SET_FILE_BASIC_INFO — set timestamps/attributes, just accept
	case 0x0102: // SMB_SET_FILE_END_OF_FILE_INFO
		// Truncate
	default:
		log.Printf("[SMB1] Unsupported SetPathInfo level: 0x%04x", infoLevel)
	}

	return h.buildTrans2ResponseWithParams(msg, []byte{0, 0}, nil)
}

// buildTrans2ResponseWithParams builds a Trans2 response with both parameter and data sections.
func (h *SMB1Handler) buildTrans2ResponseWithParams(msg *protocol.SMB1Message, t2Params, dataBytes []byte) (*protocol.SMB1Message, error) {
	response := &protocol.SMB1Message{
		Header: msg.Header,
	}
	response.Header.Flags = 0x88
	response.Header.Status = protocol.STATUS_SUCCESS

	// Calculate offsets: Header(32) + WC(1) + Words(20) = 53, ByteCount(2) = 55, Pad(1) = 56
	paramOff := uint16(56)
	dataOff := paramOff + uint16(len(t2Params))
	// Align data to even boundary
	pad2 := uint16(0)
	if dataOff%2 != 0 {
		pad2 = 1
		dataOff++
	}

	paramsOut := bytes.NewBuffer(nil)
	binary.Write(paramsOut, binary.LittleEndian, uint8(10))
	binary.Write(paramsOut, binary.LittleEndian, uint16(len(t2Params)))  // TotalParamCount
	binary.Write(paramsOut, binary.LittleEndian, uint16(len(dataBytes))) // TotalDataCount
	binary.Write(paramsOut, binary.LittleEndian, uint16(0))              // Reserved
	binary.Write(paramsOut, binary.LittleEndian, uint16(len(t2Params)))  // ParamCount
	binary.Write(paramsOut, binary.LittleEndian, paramOff)               // ParamOffset
	binary.Write(paramsOut, binary.LittleEndian, uint16(0))              // ParamDisplacement
	binary.Write(paramsOut, binary.LittleEndian, uint16(len(dataBytes))) // DataCount
	binary.Write(paramsOut, binary.LittleEndian, dataOff)                // DataOffset
	binary.Write(paramsOut, binary.LittleEndian, uint16(0))              // DataDisplacement
	binary.Write(paramsOut, binary.LittleEndian, uint8(0))               // SetupCount
	binary.Write(paramsOut, binary.LittleEndian, uint8(0))               // Reserved
	response.Parameters = paramsOut.Bytes()

	d := bytes.NewBuffer(nil)
	byteCount := uint16(1 + len(t2Params) + int(pad2) + len(dataBytes))
	binary.Write(d, binary.LittleEndian, byteCount)
	d.WriteByte(0) // Pad1
	d.Write(t2Params)
	for i := uint16(0); i < pad2; i++ {
		d.WriteByte(0)
	}
	d.Write(dataBytes)
	response.Data = d.Bytes()
	return response, nil
}

func (h *SMB1Handler) handleTreeDisconnect(msg *protocol.SMB1Message) (*protocol.SMB1Message, error) {
	response := &protocol.SMB1Message{
		Header: protocol.SMB1Header{
			Protocol: [4]byte{0xFF, 'S', 'M', 'B'},
			Command:  protocol.SMB1_COM_TREE_DISCONNECT,
			Status:   protocol.STATUS_SUCCESS,
			Flags:    0x80,
			Flags2:   msg.Header.Flags2 | 0x4000,
			UID:      msg.Header.UID,
			TID:      msg.Header.TID,
			MID:      msg.Header.MID,
		},
		Parameters: []byte{0},    // WordCount = 0
		Data:       []byte{0, 0}, // ByteCount = 0
	}
	return response, nil
}

func (h *SMB1Handler) handleNTCreateAndX(msg *protocol.SMB1Message) (*protocol.SMB1Message, error) {
	// Parse the file name from the request.
	// NT_CREATE_ANDX layout (params[0]=WordCount=24):
	//   [1] AndXCommand, [2] Reserved, [3:5] AndXOffset, [5] Reserved,
	//   [6:8] NameLength, [8:12] Flags, [12:16] RootDirFID, ...
	params := msg.Parameters
	if len(params) < 8 {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}
	nameLen := binary.LittleEndian.Uint16(params[6:8])

	// Extract file name from Data section (after ByteCount + optional pad)
	if len(msg.Data) < 2 {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}
	d := msg.Data[2:] // skip ByteCount

	// Unicode alignment: the filename must start at a word boundary relative
	// to the SMB header. Header(32) + WC(1) + Words(WC*2) + ByteCount(2) = offset.
	// If this offset is odd, skip one pad byte.
	isUnicode := (msg.Header.Flags2 & 0x8000) != 0
	if isUnicode {
		wordCount := int(params[0])
		dataStart := 32 + 1 + wordCount*2 + 2 // header + WC + words + ByteCount
		if dataStart%2 != 0 && len(d) > 0 {
			d = d[1:] // skip alignment pad
		}
	}

	var fileName string
	if isUnicode && int(nameLen) <= len(d) {
		runes := make([]rune, 0, nameLen/2)
		for i := 0; i+1 < int(nameLen); i += 2 {
			ch := rune(binary.LittleEndian.Uint16(d[i : i+2]))
			if ch == 0 {
				break
			}
			runes = append(runes, ch)
		}
		fileName = string(runes)
	} else if int(nameLen) <= len(d) {
		// ASCII
		for i := 0; i < int(nameLen) && i < len(d); i++ {
			if d[i] == 0 {
				break
			}
			fileName += string(d[i])
		}
	}
	// Normalize: strip leading backslash
	fileName = strings.TrimLeft(fileName, "\\")
	// Parse CreateOptions and CreateDisposition from params
	// Params layout after WC: AndX(4), Reserved(1), NameLen(2), Flags(4),
	//   RootDirFID(4), DesiredAccess(4), AllocSize(8), ExtAttr(4),
	//   ShareAccess(4), CreateDisp(4), CreateOpts(4), ImpersonationLvl(4), SecurityFlags(1)
	var createDisp, createOpts uint32
	if len(params) >= 44 {
		createDisp = binary.LittleEndian.Uint32(params[36:40])
		createOpts = binary.LittleEndian.Uint32(params[40:44])
	}
	isDirectory := (createOpts & protocol.FILE_DIRECTORY_FILE) != 0
	log.Printf("[SMB1] NT_CREATE_ANDX: file=%q tid=%d disp=%d opts=0x%x isDir=%v", fileName, msg.Header.TID, createDisp, createOpts, isDirectory)

	// Determine if this is a pipe (IPC$) or a regular file
	tc, _ := h.resolveTreeConn(msg)
	isPipe := (tc != nil && tc.IsIPC) || strings.EqualFold(fileName, "srvsvc") || strings.EqualFold(fileName, "wkssvc")

	// Handle file/directory creation based on disposition
	if !isPipe && tc != nil {
		switch createDisp {
		case protocol.FILE_CREATE: // Create new, fail if exists
			if isDirectory {
				if err := h.shareManager.CreateDirectory(tc.ShareName, fileName); err != nil {
					return h.createErrorResponse(msg, protocol.STATUS_ACCESS_DENIED), nil
				}
			} else {
				if _, err := h.shareManager.WriteFile(tc.ShareName, fileName, 0, []byte{}); err != nil {
					return h.createErrorResponse(msg, protocol.STATUS_ACCESS_DENIED), nil
				}
			}
		case protocol.FILE_OPEN_IF: // Open if exists, create if not
			if !h.shareManager.FileExists(tc.ShareName, fileName) {
				if isDirectory {
					h.shareManager.CreateDirectory(tc.ShareName, fileName)
				} else {
					h.shareManager.WriteFile(tc.ShareName, fileName, 0, []byte{})
				}
			}
		case protocol.FILE_OVERWRITE_IF: // Overwrite if exists, create if not
			if !isDirectory {
				h.shareManager.WriteFile(tc.ShareName, fileName, 0, []byte{})
			}
		}
	}

	fid := h.nextFID
	h.nextFID++
	h.fileHandles[fid] = &smb1FileHandle{
		fid: fid, shareName: func() string { if tc != nil { return tc.ShareName }; return "" }(),
		path: fileName, isPipe: isPipe, isDir: isDirectory, treeID: msg.Header.TID,
	}
	if isPipe {
		fid = 0x4000 // keep backwards compat for pipe data map
		h.fileHandles[fid] = h.fileHandles[h.nextFID-1]
		h.fileHandles[fid].fid = fid
	}

	// Build NT_CREATE_ANDX response (WordCount=34)
	response := &protocol.SMB1Message{
		Header: protocol.SMB1Header{
			Protocol: [4]byte{0xFF, 'S', 'M', 'B'},
			Command:  protocol.SMB1_COM_NT_CREATE_ANDX,
			Status:   protocol.STATUS_SUCCESS,
			Flags:    0x80,
			Flags2:   msg.Header.Flags2 | 0x4000,
			UID:      msg.Header.UID,
			TID:      msg.Header.TID,
			MID:      msg.Header.MID,
		},
	}

	// Get real file info for non-pipe files
	var fileSize uint64
	var fileAttrs uint32
	var creationFT, accessFT, writeFT uint64
	var fileType uint16
	var devState uint16
	var isDir uint8
	const ftEpoch2 = 116444736000000000

	if isPipe {
		fileType = 2     // MessageModePipe
		devState = 0x05FF
		fileAttrs = 0x0080
	} else if tc != nil {
		fi, fiErr := h.shareManager.GetFileInfo(tc.ShareName, fileName)
		if fiErr == nil {
			fileSize = uint64(fi.Size)
			fileAttrs = fi.Attributes
			if fileAttrs == 0 {
				if fi.IsDirectory {
					fileAttrs = protocol.FILE_ATTRIBUTE_DIRECTORY
				} else {
					fileAttrs = protocol.FILE_ATTRIBUTE_NORMAL
				}
			}
			creationFT = uint64(fi.CreatedTime.UnixNano()/100) + ftEpoch2
			accessFT = uint64(fi.AccessedTime.UnixNano()/100) + ftEpoch2
			writeFT = uint64(fi.ModifiedTime.UnixNano()/100) + ftEpoch2
			if fi.IsDirectory {
				isDir = 1
			}
		} else {
			fileAttrs = protocol.FILE_ATTRIBUTE_NORMAL
		}
		fileType = 0 // Disk file
	}

	p := bytes.NewBuffer(nil)
	binary.Write(p, binary.LittleEndian, uint8(34))
	binary.Write(p, binary.LittleEndian, uint8(0xFF))
	binary.Write(p, binary.LittleEndian, uint8(0))
	binary.Write(p, binary.LittleEndian, uint16(0))
	binary.Write(p, binary.LittleEndian, uint8(0))       // OplockLevel
	binary.Write(p, binary.LittleEndian, uint16(fid))
	binary.Write(p, binary.LittleEndian, uint32(1))       // CreateAction
	binary.Write(p, binary.LittleEndian, creationFT)
	binary.Write(p, binary.LittleEndian, accessFT)
	binary.Write(p, binary.LittleEndian, writeFT)
	binary.Write(p, binary.LittleEndian, writeFT)         // ChangeTime
	binary.Write(p, binary.LittleEndian, fileAttrs)
	binary.Write(p, binary.LittleEndian, fileSize)        // AllocationSize
	binary.Write(p, binary.LittleEndian, fileSize)        // EndOfFile
	binary.Write(p, binary.LittleEndian, fileType)
	binary.Write(p, binary.LittleEndian, devState)
	binary.Write(p, binary.LittleEndian, isDir)

	response.Parameters = p.Bytes()
	response.Data = []byte{0, 0} // ByteCount = 0

	return response, nil
}

func (h *SMB1Handler) handleTransaction(msg *protocol.SMB1Message) (*protocol.SMB1Message, error) {
	// SMB_COM_TRANSACTION is used for DCE/RPC over named pipes.
	// Windows XP uses this for share enumeration via \PIPE\srvsvc.
	params := msg.Parameters
	if len(params) < 29 {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}

	// Parse Trans request parameters
	// WordCount(1) + TotalParamCount(2) + TotalDataCount(2) + MaxParamCount(2) + MaxDataCount(2) +
	// MaxSetupCount(1) + Reserved(1) + Flags(2) + Timeout(4) + Reserved2(2) +
	// ParamCount(2) + ParamOffset(2) + DataCount(2) + DataOffset(2) + SetupCount(1) + Reserved3(1)
	// = 28 bytes after WordCount
	wordCount := params[0]
	dataCount := binary.LittleEndian.Uint16(params[23:25])
	dataOffset := binary.LittleEndian.Uint16(params[25:27])
	setupCount := params[27]

	// SetupWords follow at offset 29
	var subcommand uint16
	if setupCount >= 2 && len(params) >= 31 {
		subcommand = binary.LittleEndian.Uint16(params[29:31])
	}
	log.Printf("[SMB1] TRANSACTION: WC=%d subcommand=0x%04x dataCount=%d dataOff=%d setupCount=%d", wordCount, subcommand, dataCount, dataOffset, setupCount)

	// Extract DCE/RPC data from the message
	// dataOffset is relative to start of SMB header
	baseOffset := 32 + 1 + int(wordCount)*2 // Header + WordCount + Words
	relOff := int(dataOffset) - baseOffset
	if relOff < 0 || relOff+int(dataCount) > len(msg.Data) {
		// Try from Data section directly (after ByteCount)
		if len(msg.Data) >= 2+int(dataCount) {
			relOff = 2
		} else {
			return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
		}
	}
	rpcData := msg.Data[relOff : relOff+int(dataCount)]

	// Check for DCE/RPC header (version 5.0)
	if len(rpcData) < 24 || rpcData[0] != 5 || rpcData[1] != 0 {
		log.Printf("[SMB1] TRANSACTION: not DCE/RPC data (first bytes: %x)", rpcData[:min(8, len(rpcData))])
		return h.createErrorResponse(msg, protocol.STATUS_NOT_SUPPORTED), nil
	}

	pktType := rpcData[2]
	log.Printf("[SMB1] TRANSACTION: DCE/RPC type=%d", pktType)

	switch pktType {
	case 11: // BIND
		return h.handleRPCBind(msg, rpcData)
	case 0: // REQUEST
		resp := h.buildRPCResponse(rpcData)
		if resp == nil {
			return h.createErrorResponse(msg, protocol.STATUS_NOT_SUPPORTED), nil
		}
		return h.buildTransactionResponse(msg, resp)
	default:
		log.Printf("[SMB1] TRANSACTION: unsupported RPC type %d", pktType)
		return h.createErrorResponse(msg, protocol.STATUS_NOT_SUPPORTED), nil
	}
}

func (h *SMB1Handler) handleRPCBind(msg *protocol.SMB1Message, rpcData []byte) (*protocol.SMB1Message, error) {
	// Parse BIND request: extract call_id
	callID := binary.LittleEndian.Uint32(rpcData[12:16])

	// Build BIND_ACK response
	rpcResp := bytes.NewBuffer(nil)
	// DCE/RPC header
	rpcResp.WriteByte(5)    // Version
	rpcResp.WriteByte(0)    // Minor
	rpcResp.WriteByte(12)   // PacketType = BIND_ACK
	rpcResp.WriteByte(0x03) // Flags (FirstFrag|LastFrag)
	binary.Write(rpcResp, binary.LittleEndian, uint32(0x00000010)) // DataRepresentation (LE, ASCII, IEEE)
	binary.Write(rpcResp, binary.LittleEndian, uint16(0))          // FragLength (placeholder)
	binary.Write(rpcResp, binary.LittleEndian, uint16(0))          // AuthLength
	binary.Write(rpcResp, binary.LittleEndian, callID)             // CallID

	// BIND_ACK body
	binary.Write(rpcResp, binary.LittleEndian, uint16(4280)) // MaxXmitFrag
	binary.Write(rpcResp, binary.LittleEndian, uint16(4280)) // MaxRecvFrag
	binary.Write(rpcResp, binary.LittleEndian, uint32(0))    // AssocGroup

	// Secondary address (port): "\PIPE\srvsvc"
	secAddr := []byte("\\PIPE\\srvsvc\x00")
	binary.Write(rpcResp, binary.LittleEndian, uint16(len(secAddr)))
	rpcResp.Write(secAddr)
	// Align to 4 bytes
	for rpcResp.Len()%4 != 0 {
		rpcResp.WriteByte(0)
	}

	// Result list: 1 context, accept
	binary.Write(rpcResp, binary.LittleEndian, uint8(1))  // NumResults
	binary.Write(rpcResp, binary.LittleEndian, uint8(0))  // Reserved
	binary.Write(rpcResp, binary.LittleEndian, uint16(0)) // Reserved2
	binary.Write(rpcResp, binary.LittleEndian, uint16(0)) // Result = acceptance
	binary.Write(rpcResp, binary.LittleEndian, uint16(0)) // Reason
	// Transfer syntax UUID + version (NDR 2.0)
	rpcResp.Write([]byte{0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
		0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60}) // NDR UUID
	binary.Write(rpcResp, binary.LittleEndian, uint32(2)) // NDR version

	// Fix FragLength
	resp := rpcResp.Bytes()
	binary.LittleEndian.PutUint16(resp[8:10], uint16(len(resp)))

	return h.buildTransactionResponse(msg, resp)
}

func (h *SMB1Handler) handleRPCRequest(msg *protocol.SMB1Message, rpcData []byte) (*protocol.SMB1Message, error) {
	if len(rpcData) < 24 {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}
	callID := binary.LittleEndian.Uint32(rpcData[12:16])
	opNum := binary.LittleEndian.Uint16(rpcData[22:24])

	log.Printf("[SMB1] RPC REQUEST: opNum=%d callID=%d", opNum, callID)

	// OpNum 15 = NetrShareEnum (NetShareEnumAll)
	if opNum != 15 {
		log.Printf("[SMB1] RPC REQUEST: unsupported opNum %d", opNum)
		return h.createErrorResponse(msg, protocol.STATUS_NOT_SUPPORTED), nil
	}

	// Build NetrShareEnum response with share list
	shareList := h.shareManager.ListShares()

	stub := bytes.NewBuffer(nil)
	// InfoStruct Level
	binary.Write(stub, binary.LittleEndian, uint32(1)) // Level
	binary.Write(stub, binary.LittleEndian, uint32(1)) // Switch (Level 1)

	// SHARE_INFO_1_CONTAINER
	binary.Write(stub, binary.LittleEndian, uint32(len(shareList))) // EntriesRead
	binary.Write(stub, binary.LittleEndian, uint32(1))              // Buffer pointer (non-null)
	binary.Write(stub, binary.LittleEndian, uint32(len(shareList))) // MaxCount (NDR array)

	// First pass: fixed-size share entries (type + name/comment pointers)
	for _, share := range shareList {
		namePtr := uint32(1) // non-null pointer
		commentPtr := uint32(1)

		binary.Write(stub, binary.LittleEndian, namePtr)
		// Share type
		shareType := uint32(0) // STYPE_DISKTREE
		if share.Name == "IPC$" {
			shareType = 3 // STYPE_IPC
		}
		binary.Write(stub, binary.LittleEndian, shareType)
		binary.Write(stub, binary.LittleEndian, commentPtr)
	}

	// Second pass: variable-length strings (NDR conformant strings)
	for _, share := range shareList {
		name := utf16le.EncodeStringToBytes(share.Name)
		nameChars := uint32(len(name)/2 + 1) // include null terminator
		binary.Write(stub, binary.LittleEndian, nameChars) // MaxCount
		binary.Write(stub, binary.LittleEndian, uint32(0)) // Offset
		binary.Write(stub, binary.LittleEndian, nameChars) // ActualCount
		stub.Write(name)
		stub.Write([]byte{0, 0}) // null terminator
		// Align to 4 bytes
		for stub.Len()%4 != 0 {
			stub.WriteByte(0)
		}

		comment := utf16le.EncodeStringToBytes(share.Comment)
		commentChars := uint32(len(comment)/2 + 1)
		binary.Write(stub, binary.LittleEndian, commentChars)
		binary.Write(stub, binary.LittleEndian, uint32(0))
		binary.Write(stub, binary.LittleEndian, commentChars)
		stub.Write(comment)
		stub.Write([]byte{0, 0})
		for stub.Len()%4 != 0 {
			stub.WriteByte(0)
		}
	}

	// TotalEntries
	binary.Write(stub, binary.LittleEndian, uint32(len(shareList)))
	// ResumeHandle (NULL pointer)
	binary.Write(stub, binary.LittleEndian, uint32(0))
	// Return status (WERR_OK = 0)
	binary.Write(stub, binary.LittleEndian, uint32(0))

	// Build DCE/RPC RESPONSE
	rpcResp := bytes.NewBuffer(nil)
	rpcResp.WriteByte(5)    // Version
	rpcResp.WriteByte(0)    // Minor
	rpcResp.WriteByte(2)    // PacketType = RESPONSE
	rpcResp.WriteByte(0x03) // Flags
	binary.Write(rpcResp, binary.LittleEndian, uint32(0x00000010)) // DataRepresentation
	binary.Write(rpcResp, binary.LittleEndian, uint16(0))          // FragLength (placeholder)
	binary.Write(rpcResp, binary.LittleEndian, uint16(0))          // AuthLength
	binary.Write(rpcResp, binary.LittleEndian, callID)

	// Response body
	binary.Write(rpcResp, binary.LittleEndian, uint32(stub.Len())) // AllocHint
	binary.Write(rpcResp, binary.LittleEndian, uint16(0))          // ContextID
	binary.Write(rpcResp, binary.LittleEndian, uint8(0))           // CancelCount
	rpcResp.WriteByte(0)                                           // Reserved
	rpcResp.Write(stub.Bytes())

	resp := rpcResp.Bytes()
	binary.LittleEndian.PutUint16(resp[8:10], uint16(len(resp)))

	return h.buildTransactionResponse(msg, resp)
}

func (h *SMB1Handler) handleWriteAndX(msg *protocol.SMB1Message) (*protocol.SMB1Message, error) {
	// WRITE_ANDX for named pipe: receives DCE/RPC data, processes it, stores response for READ_ANDX.
	// Params layout (params[0]=WordCount=14):
	//   [1] AndXCommand, [2] Reserved, [3:5] AndXOffset
	//   [5:7] FID, [7:11] Offset, [11:15] Reserved
	//   [15:17] WriteMode, [17:19] Remaining, [19:21] DataLenHigh
	//   [21:23] DataLength, [23:25] DataOffset
	params := msg.Parameters
	if len(params) < 25 {
		return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
	}
	fid := binary.LittleEndian.Uint16(params[5:7])
	dataLen := binary.LittleEndian.Uint16(params[21:23])
	dataOff := binary.LittleEndian.Uint16(params[23:25])

	// Extract write data
	wordCount := params[0]
	baseOffset := 32 + 1 + int(wordCount)*2 // SMB Header + WC + Words
	relOff := int(dataOff) - baseOffset
	if relOff < 0 || relOff+int(dataLen) > len(msg.Data) {
		if len(msg.Data) >= 2+int(dataLen) {
			relOff = 2 // skip ByteCount
		} else {
			return h.createErrorResponse(msg, protocol.STATUS_INVALID_PARAMETER), nil
		}
	}
	writeData := msg.Data[relOff : relOff+int(dataLen)]

	log.Printf("[SMB1] WRITE_ANDX: fid=0x%04x len=%d", fid, dataLen)

	// Check if this is a pipe or regular file
	handle, hasHandle := h.fileHandles[fid]
	if hasHandle && handle.isPipe {
		// Process DCE/RPC for pipe
		if len(writeData) >= 2 && writeData[0] == 5 && writeData[1] == 0 {
			pktType := writeData[2]
			log.Printf("[SMB1] WRITE_ANDX: DCE/RPC type=%d", pktType)
			var rpcResp []byte
			switch pktType {
			case 11:
				rpcResp = h.buildRPCBindAck(writeData)
			case 0:
				rpcResp = h.buildRPCResponse(writeData)
			}
			if rpcResp != nil {
				h.pipeData[fid] = rpcResp
			}
		}
	} else if hasHandle && !handle.isPipe {
		// Real file write
		fileOffset := binary.LittleEndian.Uint32(params[7:11])
		_, err := h.shareManager.WriteFile(handle.shareName, handle.path, int64(fileOffset), writeData)
		if err != nil {
			return h.createErrorResponse(msg, protocol.STATUS_ACCESS_DENIED), nil
		}
	}

	// Build WRITE_ANDX response
	response := &protocol.SMB1Message{
		Header: protocol.SMB1Header{
			Protocol: [4]byte{0xFF, 'S', 'M', 'B'},
			Command:  protocol.SMB1_COM_WRITE_ANDX,
			Status:   protocol.STATUS_SUCCESS,
			Flags:    0x80,
			Flags2:   msg.Header.Flags2 | 0x4000,
			UID:      msg.Header.UID,
			TID:      msg.Header.TID,
			MID:      msg.Header.MID,
		},
	}

	p := bytes.NewBuffer(nil)
	binary.Write(p, binary.LittleEndian, uint8(6))       // WordCount
	binary.Write(p, binary.LittleEndian, uint8(0xFF))     // AndXCommand (none)
	binary.Write(p, binary.LittleEndian, uint8(0))        // Reserved
	binary.Write(p, binary.LittleEndian, uint16(0))       // AndXOffset
	binary.Write(p, binary.LittleEndian, uint16(dataLen)) // Count written
	binary.Write(p, binary.LittleEndian, uint16(0))       // Available
	binary.Write(p, binary.LittleEndian, uint16(0))       // CountHigh
	binary.Write(p, binary.LittleEndian, uint16(0))       // Reserved
	response.Parameters = p.Bytes()
	response.Data = []byte{0, 0} // ByteCount = 0
	return response, nil
}

func (h *SMB1Handler) buildRPCBindAck(rpcData []byte) []byte {
	if len(rpcData) < 16 {
		return nil
	}
	callID := binary.LittleEndian.Uint32(rpcData[12:16])

	rpcResp := bytes.NewBuffer(nil)
	rpcResp.WriteByte(5)    // Version
	rpcResp.WriteByte(0)    // Minor
	rpcResp.WriteByte(12)   // BIND_ACK
	rpcResp.WriteByte(0x03) // FirstFrag|LastFrag
	binary.Write(rpcResp, binary.LittleEndian, uint32(0x00000010))
	binary.Write(rpcResp, binary.LittleEndian, uint16(0)) // FragLength placeholder
	binary.Write(rpcResp, binary.LittleEndian, uint16(0)) // AuthLength
	binary.Write(rpcResp, binary.LittleEndian, callID)

	binary.Write(rpcResp, binary.LittleEndian, uint16(4280))
	binary.Write(rpcResp, binary.LittleEndian, uint16(4280))
	binary.Write(rpcResp, binary.LittleEndian, uint32(0))

	secAddr := []byte("\\PIPE\\srvsvc\x00")
	binary.Write(rpcResp, binary.LittleEndian, uint16(len(secAddr)))
	rpcResp.Write(secAddr)
	for rpcResp.Len()%4 != 0 {
		rpcResp.WriteByte(0)
	}

	binary.Write(rpcResp, binary.LittleEndian, uint8(1))
	binary.Write(rpcResp, binary.LittleEndian, uint8(0))
	binary.Write(rpcResp, binary.LittleEndian, uint16(0))
	binary.Write(rpcResp, binary.LittleEndian, uint16(0)) // Result=accept
	binary.Write(rpcResp, binary.LittleEndian, uint16(0))
	rpcResp.Write([]byte{0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
		0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60})
	binary.Write(rpcResp, binary.LittleEndian, uint32(2))

	resp := rpcResp.Bytes()
	binary.LittleEndian.PutUint16(resp[8:10], uint16(len(resp)))
	return resp
}

func (h *SMB1Handler) buildRPCResponse(rpcData []byte) []byte {
	if len(rpcData) < 24 {
		return nil
	}
	callID := binary.LittleEndian.Uint32(rpcData[12:16])
	opNum := binary.LittleEndian.Uint16(rpcData[22:24])

	log.Printf("[SMB1] buildRPCResponse: opNum=%d", opNum)
	if opNum != 15 { // NetrShareEnum
		return nil
	}

	align4 := func(b *bytes.Buffer) {
		for b.Len()%4 != 0 {
			b.WriteByte(0)
		}
	}
	writeUnicodeString := func(b *bytes.Buffer, s string) {
		runes := []rune(s)
		maxCount := uint32(len(runes) + 1) // include null terminator
		binary.Write(b, binary.LittleEndian, maxCount)
		binary.Write(b, binary.LittleEndian, uint32(0))
		binary.Write(b, binary.LittleEndian, maxCount)
		for _, r := range runes {
			var tmp [2]byte
			binary.LittleEndian.PutUint16(tmp[:], uint16(r))
			b.Write(tmp[:])
		}
		b.Write([]byte{0x00, 0x00}) // null terminator
		align4(b)
	}

	shares := h.shareManager.ListShares()
	visible := make([]*protocol.Share, 0, len(shares))
	for _, s := range shares {
		if !s.Hidden {
			visible = append(visible, s)
		}
	}

	// Build NDR stub (same format as working SMB2 handler)
	stub := &bytes.Buffer{}
	// InfoStruct (level 1)
	binary.Write(stub, binary.LittleEndian, uint32(1))             // level
	binary.Write(stub, binary.LittleEndian, uint32(1))             // union arm = 1
	binary.Write(stub, binary.LittleEndian, uint32(0x20000))       // referent ID for SHARE_INFO_1_CONTAINER pointer
	binary.Write(stub, binary.LittleEndian, uint32(len(visible)))  // EntriesRead
	binary.Write(stub, binary.LittleEndian, uint32(0x20004))       // Buffer pointer referent ID
	binary.Write(stub, binary.LittleEndian, uint32(len(visible)))  // max_count (conformant array)

	// Array of SHARE_INFO_1 structures (fixed-size part with pointers)
	for range visible {
		binary.Write(stub, binary.LittleEndian, uint32(0x30000)) // shi1_netname pointer
		binary.Write(stub, binary.LittleEndian, uint32(0))       // shi1_type = STYPE_DISKTREE
		binary.Write(stub, binary.LittleEndian, uint32(0x30004)) // shi1_remark pointer
	}

	// Variable-length strings (pointer encounter order: netname, remark for each)
	for _, s := range visible {
		writeUnicodeString(stub, s.Name)
		writeUnicodeString(stub, s.Comment)
	}

	// TotalEntries
	binary.Write(stub, binary.LittleEndian, uint32(len(visible)))
	// ResumeHandle (unique pointer, NULL)
	binary.Write(stub, binary.LittleEndian, uint32(0))
	// Return status (NERR_Success)
	binary.Write(stub, binary.LittleEndian, uint32(0))

	log.Printf("[SMB1] NDR stub: %d shares, stubLen=%d, first32=%x", len(visible), stub.Len(), stub.Bytes()[:min(32, stub.Len())])

	// DCE/RPC RESPONSE PDU
	rpcResp := bytes.NewBuffer(nil)
	rpcResp.Write([]byte{0x05, 0x00, 0x02, 0x03})                     // RESPONSE, FirstFrag|LastFrag
	binary.Write(rpcResp, binary.LittleEndian, uint32(0x00000010))     // DataRepresentation
	binary.Write(rpcResp, binary.LittleEndian, uint16(0))              // FragLength placeholder
	binary.Write(rpcResp, binary.LittleEndian, uint16(0))              // AuthLength
	binary.Write(rpcResp, binary.LittleEndian, callID)
	binary.Write(rpcResp, binary.LittleEndian, uint32(stub.Len()))     // AllocHint
	binary.Write(rpcResp, binary.LittleEndian, uint16(0))              // ContextID
	binary.Write(rpcResp, binary.LittleEndian, uint8(0))               // CancelCount
	rpcResp.WriteByte(0)                                               // Reserved
	rpcResp.Write(stub.Bytes())

	resp := rpcResp.Bytes()
	binary.LittleEndian.PutUint16(resp[8:10], uint16(len(resp)))
	return resp
}

// buildTransactionResponse wraps DCE/RPC data in an SMB_COM_TRANSACTION response
func (h *SMB1Handler) buildTransactionResponse(msg *protocol.SMB1Message, rpcData []byte) (*protocol.SMB1Message, error) {
	response := &protocol.SMB1Message{
		Header: protocol.SMB1Header{
			Protocol: [4]byte{0xFF, 'S', 'M', 'B'},
			Command:  protocol.SMB1_COM_TRANSACTION,
			Status:   protocol.STATUS_SUCCESS,
			Flags:    0x80,
			Flags2:   msg.Header.Flags2 | 0x4000,
			UID:      msg.Header.UID,
			TID:      msg.Header.TID,
			MID:      msg.Header.MID,
		},
	}

	// Calculate offsets
	// Header(32) + WordCount(1) + Words(10*2=20) = 53
	// ByteCount(2) = 55
	// Pad(1) = 56 → DataOffset
	const dataOffset = 56

	p := bytes.NewBuffer(nil)
	binary.Write(p, binary.LittleEndian, uint8(10))               // WordCount
	binary.Write(p, binary.LittleEndian, uint16(0))                // TotalParamCount
	binary.Write(p, binary.LittleEndian, uint16(len(rpcData)))     // TotalDataCount
	binary.Write(p, binary.LittleEndian, uint16(0))                // Reserved
	binary.Write(p, binary.LittleEndian, uint16(0))                // ParamCount
	binary.Write(p, binary.LittleEndian, uint16(dataOffset))       // ParamOffset
	binary.Write(p, binary.LittleEndian, uint16(0))                // ParamDisplacement
	binary.Write(p, binary.LittleEndian, uint16(len(rpcData)))     // DataCount
	binary.Write(p, binary.LittleEndian, uint16(dataOffset))       // DataOffset
	binary.Write(p, binary.LittleEndian, uint16(0))                // DataDisplacement
	binary.Write(p, binary.LittleEndian, uint8(0))                 // SetupCount
	binary.Write(p, binary.LittleEndian, uint8(0))                 // Reserved

	response.Parameters = p.Bytes()

	d := bytes.NewBuffer(nil)
	byteCount := uint16(1 + len(rpcData)) // pad + data
	binary.Write(d, binary.LittleEndian, byteCount)
	d.WriteByte(0) // Pad
	d.Write(rpcData)

	response.Data = d.Bytes()
	return response, nil
}

func (h *SMB1Handler) createErrorResponse(request *protocol.SMB1Message, status uint32) *protocol.SMB1Message {
	return &protocol.SMB1Message{
		Header: protocol.SMB1Header{
			Protocol: [4]byte{0xFF, 'S', 'M', 'B'},
			Command:  request.Header.Command,
			Status:   status,
			Flags:    0x80,
			Flags2:   0x0001,
			UID:      request.Header.UID,
			TID:      request.Header.TID,
			MID:      request.Header.MID,
		},
		Parameters: []byte{0},    // Word count = 0
		Data:       []byte{0, 0}, // Byte count = 0
	}
}

func (h *SMB1Handler) parseDialects(data []byte) []string {
	var dialects []string
	offset := 2 // Skip byte count

	for offset < len(data) {
		if data[offset] != 0x02 { // Dialect string marker
			break
		}
		offset++ // Skip marker

		// Find null terminator
		start := offset
		for offset < len(data) && data[offset] != 0 {
			offset++
		}

		if offset > start {
			dialects = append(dialects, string(data[start:offset]))
		}
		offset++ // Skip null terminator
	}

	return dialects
}

// utf16LE encodes string to UTF-16LE bytes
func utf16LE(s string) []byte {
	runes := []rune(s)
	b := make([]byte, len(runes)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(b[i*2:], uint16(r))
	}
	return b
}

func (h *SMB1Handler) handleQueryFSAttributeInfo(msg *protocol.SMB1Message) (*protocol.SMB1Message, error) {
	fsName := "NTFS"
	fsNameBytes := utf16LE(fsName)

	dataOut := bytes.NewBuffer(nil)
	// FileSystemAttributes (4 bytes)
	// FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES | FILE_UNICODE_ON_DISK | FILE_PERSISTENT_ACLS
	// 0x00000007 (Case Sensitive | Case Preserved | Unicode)
	attrs := uint32(0x00000007)
	binary.Write(dataOut, binary.LittleEndian, attrs)

	// MaxFileNameLenInBytes (4 bytes)
	binary.Write(dataOut, binary.LittleEndian, uint32(255))

	// FileSystemNameLenInBytes (4 bytes)
	binary.Write(dataOut, binary.LittleEndian, uint32(len(fsNameBytes)))

	// FileSystemName
	dataOut.Write(fsNameBytes)

	return h.buildTrans2Response(msg, dataOut.Bytes())
}
