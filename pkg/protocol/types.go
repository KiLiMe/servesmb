package protocol

import (
	"encoding/binary"
	"io"
	"net"
	"strings"
	"time"
)

// Common interfaces for SMB protocol handling
type SMBHandler interface {
	HandleConnection(conn net.Conn) error
	GetDialects() []string
	GetVersion() string
}

// SMBMessage represents a generic SMB message
type SMBMessage interface {
	Marshal() ([]byte, error)
	Unmarshal(data []byte) error
	GetCommand() uint16
	GetStatus() uint32
	GetMessageID() uint64
}

// Session represents an authenticated SMB session
type Session struct {
	ID              uint64
	UserID          uint16
	Username        string
	Domain          string
	IsGuest         bool
	IsAnonymous     bool
	CreatedAt       time.Time
	LastActivity    time.Time
	TreeConnections map[uint32]*TreeConnection
	// SMB2 signing
	SigningRequired bool
	SessionKey      []byte
	Dialect         uint16
	// SMB3 encryption keys (derived from SessionKey via KDF)
	EncryptionKey     []byte // server-to-client
	DecryptionKey     []byte // client-to-server
	EncryptionEnabled bool   // whether this session uses encryption
	// SMB 3.1.1 negotiated parameters
	PreauthHash []byte // 64-byte preauth integrity hash at session-setup completion
	CipherID    uint16 // negotiated encryption cipher (1=AES-128-CCM,2=AES-128-GCM,3=AES-256-CCM,4=AES-256-GCM)
	SigningID   uint16 // negotiated signing algorithm (0=HMAC-SHA256,1=AES-CMAC,2=AES-GMAC)
}

// TreeConnection represents a connection to a share
type TreeConnection struct {
	ID        uint32
	ShareName string
	SharePath string
	Session   *Session
	IsIPC     bool
	Options   uint32
}

// File handle for opened files
type FileHandle struct {
	ID             []byte
	Path           string
	IsDirectory    bool
	AccessMask     uint32
	ShareAccess    uint32
	CreateOptions  uint32
	FileInfo       *FileInfo
	TreeConnection *TreeConnection
	// Directory enumeration state (for SMB2 QUERY_DIRECTORY)
	DirIndex    int
	DirSnapshot []*FileInfo
	// StreamName is the NTFS-style named stream this handle refers to (e.g.
	// "AFP_AfpInfo" for an open of "file:AFP_AfpInfo"). Empty for the
	// unnamed/default data stream. Used by the Apple SMB extensions so macOS
	// can read/write FinderInfo and resource forks needed for Time Machine.
	StreamName string
	// OSFile is a cached OS-level file descriptor for this handle. Opened once
	// at CREATE time and held until CLOSE so that READ and WRITE requests can
	// use ReadAt/WriteAt directly instead of opening and closing the file on
	// every request (the latter is O(n) file-open syscalls for n writes to the
	// same band file, which is the primary bottleneck for Time Machine backups).
	// Nil for directories, IPC pipes, and named streams.
	OSFile interface {
		io.ReaderAt
		io.WriterAt
		io.Closer
	}
}

// FileInfo represents file metadata
type FileInfo struct {
	Name         string
	Size         int64
	Attributes   uint32
	CreatedTime  time.Time
	ModifiedTime time.Time
	AccessedTime time.Time
	IsDirectory  bool
}

// Share configuration
type Share struct {
	Name        string
	Path        string
	Comment     string
	ReadOnly    bool
	GuestAccess bool
	Hidden      bool
	Users       []string
	// Type selects optional share behaviors. "timemachine" enables the Apple
	// SMB extensions (AAPL create context, full-sync volume capability, Time
	// Machine model) so macOS recognizes the share as a Time Machine target.
	Type string
}

// IsTimeMachine reports whether the share is configured as a macOS Time
// Machine target (and thus needs the Apple SMB / fruit extensions).
func (s *Share) IsTimeMachine() bool {
	return strings.EqualFold(s.Type, "timemachine")
}

// SMB1 specific structures

// SMB1Header represents the SMB1 message header
type SMB1Header struct {
	Protocol         [4]byte // 0xFF + "SMB"
	Command          uint8   // Command code
	Status           uint32  // NT Status or DOS Error
	Flags            uint8   // Flags
	Flags2           uint16  // Extended flags
	PIDHigh          uint16  // Process ID high
	SecurityFeatures [8]byte // Signature or security features
	Reserved         uint16  // Must be zero
	TID              uint16  // Tree ID
	PIDLow           uint16  // Process ID low
	UID              uint16  // User ID
	MID              uint16  // Multiplex ID
}

// SMB1Message represents a complete SMB1 message
type SMB1Message struct {
	Header     SMB1Header
	Parameters []byte
	Data       []byte
}

func (m *SMB1Message) Marshal() ([]byte, error) {
	buf := make([]byte, 32)
	copy(buf[0:4], m.Header.Protocol[:])
	buf[4] = m.Header.Command
	binary.LittleEndian.PutUint32(buf[5:9], m.Header.Status)
	buf[9] = m.Header.Flags
	binary.LittleEndian.PutUint16(buf[10:12], m.Header.Flags2)
	binary.LittleEndian.PutUint16(buf[12:14], m.Header.PIDHigh)
	copy(buf[14:22], m.Header.SecurityFeatures[:])
	binary.LittleEndian.PutUint16(buf[22:24], m.Header.Reserved)
	binary.LittleEndian.PutUint16(buf[24:26], m.Header.TID)
	binary.LittleEndian.PutUint16(buf[26:28], m.Header.PIDLow)
	binary.LittleEndian.PutUint16(buf[28:30], m.Header.UID)
	binary.LittleEndian.PutUint16(buf[30:32], m.Header.MID)

	buf = append(buf, m.Parameters...)
	buf = append(buf, m.Data...)
	return buf, nil
}

func (m *SMB1Message) Unmarshal(data []byte) error {
	if len(data) < 32 {
		return io.ErrShortBuffer
	}

	copy(m.Header.Protocol[:], data[0:4])
	m.Header.Command = data[4]
	m.Header.Status = binary.LittleEndian.Uint32(data[5:9])
	m.Header.Flags = data[9]
	m.Header.Flags2 = binary.LittleEndian.Uint16(data[10:12])
	m.Header.PIDHigh = binary.LittleEndian.Uint16(data[12:14])
	copy(m.Header.SecurityFeatures[:], data[14:22])
	m.Header.Reserved = binary.LittleEndian.Uint16(data[22:24])
	m.Header.TID = binary.LittleEndian.Uint16(data[24:26])
	m.Header.PIDLow = binary.LittleEndian.Uint16(data[26:28])
	m.Header.UID = binary.LittleEndian.Uint16(data[28:30])
	m.Header.MID = binary.LittleEndian.Uint16(data[30:32])

	// Parse parameters and data using WordCount and ByteCount
	pos := 32
	if pos >= len(data) {
		m.Parameters = nil
		m.Data = nil
		return nil
	}

	// WordCount (in bytes)
	wordCount := int(data[pos])
	pos++
	// Parameters length is WordCount * 2 bytes
	paramsLen := wordCount * 2
	if pos+paramsLen > len(data) {
		return io.ErrShortBuffer
	}
	// Include WordCount byte in Parameters slice so callers see the counter
	m.Parameters = data[pos-1 : pos+paramsLen]
	pos += paramsLen

	if pos+2 <= len(data) {
		// ByteCount is next 2 bytes
		if pos+2 > len(data) {
			return io.ErrShortBuffer
		}
		byteCount := int(binary.LittleEndian.Uint16(data[pos : pos+2]))
		if pos+2+byteCount > len(data) {
			return io.ErrShortBuffer
		}
		// Include ByteCount in Data slice so callers can skip first 2 bytes if needed
		m.Data = data[pos : pos+2+byteCount]
	} else {
		m.Data = nil
	}

	return nil
}

func (m *SMB1Message) GetCommand() uint16 {
	return uint16(m.Header.Command)
}

func (m *SMB1Message) GetStatus() uint32 {
	return m.Header.Status
}

func (m *SMB1Message) GetMessageID() uint64 {
	return uint64(m.Header.MID)
}

// SMB2/SMB3 specific structures

// SMB2Header represents the SMB2/SMB3 message header
type SMB2Header struct {
	ProtocolID    [4]byte  // 0xFE + "SMB"
	StructureSize uint16   // Must be 64
	CreditCharge  uint16   // Credit charge
	Status        uint32   // NT Status
	Command       uint16   // Command code
	CreditRequest uint16   // Credit request/response
	Flags         uint32   // Flags
	NextCommand   uint32   // Offset to next command
	MessageID     uint64   // Message ID
	ProcessID     uint32   // Process ID (deprecated in SMB3)
	TreeID        uint32   // Tree ID
	SessionID     uint64   // Session ID
	Signature     [16]byte // Message signature
}

// SMB2Message represents a complete SMB2/SMB3 message
type SMB2Message struct {
	Header SMB2Header
	Data   []byte
	Raw    []byte // Original raw message for signature verification

	// Prebuilt is a PDU already laid out in wire format (64-byte SMB2 header
	// included). READ responses fill it directly while reading the file, so the
	// payload is never copied into Data and then copied again by Marshal.
	// When set, Marshal is not called for this message.
	Prebuilt []byte

	// Release returns the buffer behind Prebuilt to the pool. The connection
	// loop calls it after the response has been written (nil when Prebuilt is
	// nil or the buffer is not pooled).
	Release func()
}

func (m *SMB2Message) Marshal() ([]byte, error) {
	buf := make([]byte, 64)
	copy(buf[0:4], m.Header.ProtocolID[:])
	binary.LittleEndian.PutUint16(buf[4:6], m.Header.StructureSize)
	binary.LittleEndian.PutUint16(buf[6:8], m.Header.CreditCharge)
	binary.LittleEndian.PutUint32(buf[8:12], m.Header.Status)
	binary.LittleEndian.PutUint16(buf[12:14], m.Header.Command)
	binary.LittleEndian.PutUint16(buf[14:16], m.Header.CreditRequest)
	binary.LittleEndian.PutUint32(buf[16:20], m.Header.Flags)
	binary.LittleEndian.PutUint32(buf[20:24], m.Header.NextCommand)
	binary.LittleEndian.PutUint64(buf[24:32], m.Header.MessageID)
	binary.LittleEndian.PutUint32(buf[32:36], m.Header.ProcessID)
	binary.LittleEndian.PutUint32(buf[36:40], m.Header.TreeID)
	binary.LittleEndian.PutUint64(buf[40:48], m.Header.SessionID)
	copy(buf[48:64], m.Header.Signature[:])

	buf = append(buf, m.Data...)
	return buf, nil
}

func (m *SMB2Message) Unmarshal(data []byte) error {
	if len(data) < 64 {
		return io.ErrShortBuffer
	}

	// Capture raw data
	m.Raw = data

	copy(m.Header.ProtocolID[:], data[0:4])
	m.Header.StructureSize = binary.LittleEndian.Uint16(data[4:6])
	m.Header.CreditCharge = binary.LittleEndian.Uint16(data[6:8])
	m.Header.Status = binary.LittleEndian.Uint32(data[8:12])
	m.Header.Command = binary.LittleEndian.Uint16(data[12:14])
	m.Header.CreditRequest = binary.LittleEndian.Uint16(data[14:16])
	m.Header.Flags = binary.LittleEndian.Uint32(data[16:20])
	m.Header.NextCommand = binary.LittleEndian.Uint32(data[20:24])
	m.Header.MessageID = binary.LittleEndian.Uint64(data[24:32])
	m.Header.ProcessID = binary.LittleEndian.Uint32(data[32:36])
	m.Header.TreeID = binary.LittleEndian.Uint32(data[36:40])
	m.Header.SessionID = binary.LittleEndian.Uint64(data[40:48])
	copy(m.Header.Signature[:], data[48:64])

	if len(data) > 64 {
		m.Data = data[64:]
	}

	return nil
}

func (m *SMB2Message) GetCommand() uint16 {
	return m.Header.Command
}

func (m *SMB2Message) GetStatus() uint32 {
	return m.Header.Status
}

func (m *SMB2Message) GetMessageID() uint64 {
	return m.Header.MessageID
}

// Utility functions
func IsProtocolSMB1(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	return string(data[0:4]) == SMB1_PROTOCOL_ID
}

func IsProtocolSMB2(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	return string(data[0:4]) == SMB2_PROTOCOL_ID
}
