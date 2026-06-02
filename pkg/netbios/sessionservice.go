package netbios

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// NetBIOS Session Service implementation
type SessionService struct {
	serverName string
	domain     string
	port       int
	listener   net.Listener
	smbHandler SMBHandler
	sessions   map[string]*NetBIOSSession
}

// Interface for SMB protocol handlers
type SMBHandler interface {
	HandleConnection(conn net.Conn) error
}

// NetBIOS Session state
type NetBIOSSession struct {
	ID          string
	CallingName *NetBIOSName
	CalledName  *NetBIOSName
	Conn        net.Conn
	Established bool
	CreatedAt   time.Time
}

func NewSessionService(serverName, domain string, port int, smbHandler SMBHandler) *SessionService {
	return &SessionService{
		serverName: strings.ToUpper(serverName),
		domain:     strings.ToUpper(domain),
		port:       port,
		smbHandler: smbHandler,
		sessions:   make(map[string]*NetBIOSSession),
	}
}

func (ss *SessionService) Start() error {
	var err error
	ss.listener, err = net.Listen("tcp", fmt.Sprintf(":%d", ss.port))
	if err != nil {
		return fmt.Errorf("failed to listen on NetBIOS session port: %v", err)
	}

	fmt.Printf("NetBIOS Session Service listening on port %d\n", ss.port)

	// Accept connections
	go ss.acceptConnections()

	return nil
}

func (ss *SessionService) Stop() error {
	if ss.listener != nil {
		return ss.listener.Close()
	}
	return nil
}

func (ss *SessionService) acceptConnections() {
	for {
		conn, err := ss.listener.Accept()
		if err != nil {
			fmt.Printf("NetBIOS session accept error: %v\n", err)
			continue
		}

		fmt.Printf("New NetBIOS session connection from %s\n", conn.RemoteAddr())
		go ss.handleConnection(conn)
	}
}

func (ss *SessionService) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Set initial timeout for session establishment
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	session := &NetBIOSSession{
		ID:        fmt.Sprintf("%s-%d", conn.RemoteAddr().String(), time.Now().UnixNano()),
		Conn:      conn,
		CreatedAt: time.Now(),
	}

	// Handle NetBIOS session establishment
	if !ss.establishSession(session) {
		return
	}

	// Remove read timeout after session is established
	conn.SetReadDeadline(time.Time{})

	fmt.Printf("NetBIOS session established: %s -> %s\n",
		session.CallingName, session.CalledName)

	// Store session
	ss.sessions[session.ID] = session
	defer delete(ss.sessions, session.ID)

	// Handle SMB messages over the established NetBIOS session
	ss.handleSMBMessages(session)
}

func (ss *SessionService) establishSession(session *NetBIOSSession) bool {
	// Read NetBIOS session request
	header, err := ss.readSessionHeader(session.Conn)
	if err != nil {
		fmt.Printf("Failed to read NetBIOS session header: %v\n", err)
		return false
	}

	if header.Type == NETBIOS_SESSION_MESSAGE {
		// Direct SMB message - create implicit session
		fmt.Printf("Direct SMB message received, establishing implicit session\n")
		session.CallingName = CreateNetBIOSName("CLIENT", 0x00)
		session.CalledName = CreateNetBIOSName(ss.serverName, 0x20)
		session.Established = true

		// Process this SMB message immediately
		err := ss.handleSMBMessage(session, header)
		if err != nil {
			fmt.Printf("Error handling direct SMB message: %v\n", err)
			return false
		}

		// For direct SMB, handle subsequent messages in the same session
		fmt.Printf("Direct SMB session established: %s -> %s\n",
			session.CallingName, session.CalledName)

		// Store session
		ss.sessions[session.ID] = session
		defer delete(ss.sessions, session.ID)

		// Continue handling subsequent messages normally
		ss.handleSMBMessages(session)
		return false // Don't continue with normal flow as we handle everything here
	}

	if header.Type != NETBIOS_SESSION_REQUEST {
		fmt.Printf("Expected session request, got type: %02x\n", header.Type)
		ss.sendNegativeSessionResponse(session.Conn, NETBIOS_ERR_UNSPECIFIED)
		return false
	}

	// Read session request data
	data := make([]byte, header.Length)
	_, err = io.ReadFull(session.Conn, data)
	if err != nil {
		fmt.Printf("Failed to read session request data: %v\n", err)
		return false
	}

	// Parse calling and called names
	calledName, callingName, err := ss.parseSessionRequest(data)
	if err != nil {
		fmt.Printf("Failed to parse session request: %v\n", err)
		ss.sendNegativeSessionResponse(session.Conn, NETBIOS_ERR_UNSPECIFIED)
		return false
	}

	session.CalledName = calledName
	session.CallingName = callingName

	fmt.Printf("NetBIOS session request: %s -> %s\n", callingName, calledName)

	// Validate the called name (should be our server name, "*SMBSERVER", IP address, or "*")
	calledNameStr := strings.TrimSpace(string(calledName.Name[:15]))
	validName := (calledNameStr == ss.serverName ||
		calledNameStr == "*SMBSERVER" ||
		calledNameStr == "*" ||
		calledNameStr == "127.0.0.1" ||
		strings.Contains(calledNameStr, ".")) // Accept any IP address pattern

	if !validName {
		fmt.Printf("Called name not recognized: %s\n", calledNameStr)
		ss.sendNegativeSessionResponse(session.Conn, NETBIOS_ERR_CALLED_NOT_PRESENT)
		return false
	}

	// Send positive session response
	err = ss.sendPositiveSessionResponse(session.Conn)
	if err != nil {
		fmt.Printf("Failed to send positive session response: %v\n", err)
		return false
	}

	session.Established = true
	return true
}

func (ss *SessionService) parseSessionRequest(data []byte) (*NetBIOSName, *NetBIOSName, error) {
	if len(data) < 68 { // Minimum length for two NetBIOS names
		return nil, nil, fmt.Errorf("session request data too short")
	}

	// Parse called name (first 34 bytes: length + 32 encoded + terminator)
	if data[0] != 32 {
		return nil, nil, fmt.Errorf("invalid called name length: %d", data[0])
	}

	calledNameStr, calledNameType, err := DecodeNetBIOSName(data[1:33])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode called name: %v", err)
	}

	calledName := CreateNetBIOSName(calledNameStr, calledNameType)

	// Parse calling name (starts after called name terminator)
	offset := 34
	if offset >= len(data) || data[offset] != 32 {
		return nil, nil, fmt.Errorf("invalid calling name length")
	}

	callingNameStr, callingNameType, err := DecodeNetBIOSName(data[offset+1 : offset+33])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode calling name: %v", err)
	}

	callingName := CreateNetBIOSName(callingNameStr, callingNameType)

	return calledName, callingName, nil
}

func (ss *SessionService) sendPositiveSessionResponse(conn net.Conn) error {
	header := &NetBIOSSessionHeader{
		Type:   NETBIOS_POSITIVE_SESSION_RESP,
		Flags:  0,
		Length: 0,
	}

	return ss.writeSessionHeader(conn, header)
}

func (ss *SessionService) sendNegativeSessionResponse(conn net.Conn, errorCode byte) error {
	header := &NetBIOSSessionHeader{
		Type:   NETBIOS_NEGATIVE_SESSION_RESP,
		Flags:  0,
		Length: 1,
	}

	err := ss.writeSessionHeader(conn, header)
	if err != nil {
		return err
	}

	// Write error code
	_, err = conn.Write([]byte{errorCode})
	return err
}

func (ss *SessionService) handleSMBMessages(session *NetBIOSSession) {
	for {
		// Read NetBIOS session message header
		header, err := ss.readSessionHeader(session.Conn)
		if err != nil {
			if err == io.EOF {
				fmt.Printf("NetBIOS session %s closed by client\n", session.ID)
			} else {
				fmt.Printf("Error reading NetBIOS session header: %v\n", err)
			}
			return
		}

		switch header.Type {
		case NETBIOS_SESSION_MESSAGE:
			// This is an SMB message wrapped in NetBIOS session service
			err = ss.handleSMBMessage(session, header)
			if err != nil {
				fmt.Printf("Error handling SMB message: %v\n", err)
				return
			}

		case NETBIOS_SESSION_KEEP_ALIVE:
			// Keep-alive message, just acknowledge
			fmt.Printf("NetBIOS keep-alive from session %s\n", session.ID)

		default:
			fmt.Printf("Unknown NetBIOS session message type: %02x\n", header.Type)
			return
		}
	}
}

func (ss *SessionService) handleSMBMessage(session *NetBIOSSession, header *NetBIOSSessionHeader) error {
	// Read the SMB message data
	smbData := make([]byte, header.Length)
	_, err := io.ReadFull(session.Conn, smbData)
	if err != nil {
		return fmt.Errorf("failed to read SMB data: %v", err)
	}

	fmt.Printf("NetBIOS SMB message: %d bytes, first 16: %02x...\n", len(smbData), smbData[:16])

	// Create synthetic NetBIOS header for the initial SMB data
	// Standard NetBIOS Session Service format: 4 bytes where length is in lower 24 bits
	nbHeader := make([]byte, 4)
	length := uint32(len(smbData))
	binary.BigEndian.PutUint32(nbHeader, length) // This puts length in the lower 24 bits

	// Combine NetBIOS header + raw SMB data for SMB handlers
	wrappedData := make([]byte, 4+len(smbData))
	copy(wrappedData[0:4], nbHeader)
	copy(wrappedData[4:], smbData)

	fmt.Printf("DEBUG Initial wrap: NB header %02x %02x %02x %02x + %d SMB bytes\n",
		nbHeader[0], nbHeader[1], nbHeader[2], nbHeader[3], len(smbData))

	// Create a wrapper that provides the properly formatted data
	wrapper := &NetBIOSWrapper{
		session: session,
		smbData: wrappedData,
		readPos: 0,
	}

	// Pass to the main SMB handler - it will detect the protocol
	return ss.smbHandler.HandleConnection(wrapper)
}

func (ss *SessionService) readSessionHeader(conn net.Conn) (*NetBIOSSessionHeader, error) {
	headerData := make([]byte, 4)
	_, err := io.ReadFull(conn, headerData)
	if err != nil {
		return nil, err
	}

	// NetBIOS session header length is 17 bits:
	// - High bit is bit 0 of flags (headerData[1] & 0x01)
	// - Low 16 bits are in headerData[2:4]
	length := uint32(binary.BigEndian.Uint16(headerData[2:4]))
	if headerData[1]&0x01 != 0 {
		length |= 0x10000 // Set bit 16
	}

	fmt.Printf("DEBUG: NetBIOS header bytes: %02x %02x %02x %02x, parsed length: %d\n",
		headerData[0], headerData[1], headerData[2], headerData[3], length)

	return &NetBIOSSessionHeader{
		Type:   headerData[0],
		Flags:  headerData[1] & 0xFE, // Clear the length bit
		Length: length,
	}, nil
}

func (ss *SessionService) writeSessionHeader(conn net.Conn, header *NetBIOSSessionHeader) error {
	headerData := make([]byte, 4)
	headerData[0] = header.Type

	// NetBIOS session header length is 17 bits:
	// - High bit goes into bit 0 of flags
	// - Low 16 bits go into headerData[2:4]
	flags := header.Flags & 0xFE // Clear bit 0
	if header.Length&0x10000 != 0 {
		flags |= 0x01 // Set bit 0 if high bit of length is set
	}
	headerData[1] = flags

	binary.BigEndian.PutUint16(headerData[2:4], uint16(header.Length&0xFFFF))

	_, err := conn.Write(headerData)
	return err
}

// NetBIOSWrapper wraps a NetBIOS session to look like a regular net.Conn for SMB handlers
type NetBIOSWrapper struct {
	session *NetBIOSSession
	smbData []byte
	readPos int
}

func (nw *NetBIOSWrapper) Read(p []byte) (int, error) {
	if nw.readPos >= len(nw.smbData) {
		// No more data in current message, read next NetBIOS session message
		header, err := nw.readSessionHeader()
		if err != nil {
			return 0, err
		}

		if header.Type != NETBIOS_SESSION_MESSAGE {
			return 0, fmt.Errorf("expected session message, got type: %02x", header.Type)
		}

		// Read raw SMB data from NetBIOS session
		rawSMBData := make([]byte, header.Length)
		_, err = io.ReadFull(nw.session.Conn, rawSMBData)
		if err != nil {
			return 0, err
		}

		// Create synthetic NetBIOS header for SMB handlers
		// Standard NetBIOS Session Service format: 4 bytes where length is in lower 24 bits
		nbHeader := make([]byte, 4)
		length := uint32(len(rawSMBData))
		binary.BigEndian.PutUint32(nbHeader, length)

		// Combine NetBIOS header + raw SMB data
		nw.smbData = make([]byte, 4+len(rawSMBData))
		copy(nw.smbData[0:4], nbHeader)
		copy(nw.smbData[4:], rawSMBData)
		nw.readPos = 0

		fmt.Printf("DEBUG Wrapper: Synthetic NB header %02x %02x %02x %02x + %d SMB bytes\n",
			nbHeader[0], nbHeader[1], nbHeader[2], nbHeader[3], len(rawSMBData))
	}

	// Copy available data
	available := len(nw.smbData) - nw.readPos
	toCopy := len(p)
	if toCopy > available {
		toCopy = available
	}

	fmt.Printf("DEBUG Wrapper Read: requested=%d, available=%d, copying=%d, readPos=%d, totalData=%d\n",
		len(p), available, toCopy, nw.readPos, len(nw.smbData))

	copy(p, nw.smbData[nw.readPos:nw.readPos+toCopy])
	nw.readPos += toCopy

	return toCopy, nil
}

func (nw *NetBIOSWrapper) Write(p []byte) (int, error) {
	// Write SMB response wrapped in NetBIOS session message
	header := &NetBIOSSessionHeader{
		Type:   NETBIOS_SESSION_MESSAGE,
		Flags:  0,
		Length: uint32(len(p)),
	}

	// Write NetBIOS header
	err := nw.writeSessionHeader(header)
	if err != nil {
		return 0, err
	}

	// Write SMB data
	return nw.session.Conn.Write(p)
}

func (nw *NetBIOSWrapper) Close() error {
	return nw.session.Conn.Close()
}

func (nw *NetBIOSWrapper) LocalAddr() net.Addr {
	return nw.session.Conn.LocalAddr()
}

func (nw *NetBIOSWrapper) RemoteAddr() net.Addr {
	return nw.session.Conn.RemoteAddr()
}

func (nw *NetBIOSWrapper) SetDeadline(t time.Time) error {
	return nw.session.Conn.SetDeadline(t)
}

func (nw *NetBIOSWrapper) SetReadDeadline(t time.Time) error {
	return nw.session.Conn.SetReadDeadline(t)
}

func (nw *NetBIOSWrapper) SetWriteDeadline(t time.Time) error {
	return nw.session.Conn.SetWriteDeadline(t)
}

func (nw *NetBIOSWrapper) readSessionHeader() (*NetBIOSSessionHeader, error) {
	headerData := make([]byte, 4)
	_, err := io.ReadFull(nw.session.Conn, headerData)
	if err != nil {
		return nil, err
	}

	// NetBIOS session header length is 17 bits:
	// - High bit is bit 0 of flags (headerData[1] & 0x01)
	// - Low 16 bits are in headerData[2:4]
	length := uint32(binary.BigEndian.Uint16(headerData[2:4]))
	if headerData[1]&0x01 != 0 {
		length |= 0x10000 // Set bit 16
	}

	return &NetBIOSSessionHeader{
		Type:   headerData[0],
		Flags:  headerData[1] & 0xFE, // Clear the length bit
		Length: length,
	}, nil
}

func (nw *NetBIOSWrapper) writeSessionHeader(header *NetBIOSSessionHeader) error {
	headerData := make([]byte, 4)
	headerData[0] = header.Type

	// NetBIOS session header length is 17 bits:
	// - High bit goes into bit 0 of flags
	// - Low 16 bits go into headerData[2:4]
	flags := header.Flags & 0xFE // Clear bit 0
	if header.Length&0x10000 != 0 {
		flags |= 0x01 // Set bit 0 if high bit of length is set
	}
	headerData[1] = flags

	binary.BigEndian.PutUint16(headerData[2:4], uint16(header.Length&0xFFFF))

	_, err := nw.session.Conn.Write(headerData)
	return err
}
