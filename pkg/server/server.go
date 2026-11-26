package server

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/3xport/servesmb/pkg/auth"
	"github.com/3xport/servesmb/pkg/hooks"
	"github.com/3xport/servesmb/pkg/mdns"
	"github.com/3xport/servesmb/pkg/netbios"
	"github.com/3xport/servesmb/pkg/protocol"
	"github.com/3xport/servesmb/pkg/shares"
	"github.com/3xport/servesmb/pkg/smb1"
	"github.com/3xport/servesmb/pkg/smb2"
	"github.com/3xport/servesmb/pkg/smb3"
)

// ErrSMB1Disabled means the client's first frame only listed SMB1 dialects
// while SMB1 file service is turned off. Callers use it to tell "the client is
// too old" apart from transport failures.
var ErrSMB1Disabled = errors.New("client only offers SMB1 and SMB1 is disabled")

// SMB1DisabledError carries the dialects the client proposed, so callers can
// name them in their own diagnostics. It matches ErrSMB1Disabled via errors.Is.
type SMB1DisabledError struct {
	Dialects []string
}

func (e *SMB1DisabledError) Error() string {
	if len(e.Dialects) == 0 {
		return ErrSMB1Disabled.Error()
	}
	return fmt.Sprintf("%s: %s", ErrSMB1Disabled, strings.Join(e.Dialects, ", "))
}

func (e *SMB1DisabledError) Is(target error) bool { return target == ErrSMB1Disabled }

// DialectNames lists the dialects the client proposed, in the order it sent them.
func (e *SMB1DisabledError) DialectNames() []string { return e.Dialects }

type AuthConfig struct {
	Password string
	NTHash   []byte
}

type Config struct {
	ListenAddress   string
	Port            int
	SharesPath      string
	Domain          string
	ServerName      string
	EnableSMB1      bool
	EnableSMB2      bool
	EnableSMB3      bool
	EnableNetBIOS   bool
	NetBIOSPort     int
	EnableMDNS      bool                  // Advertise server/shares via mDNS / DNS-SD (Bonjour)
	Users           map[string]AuthConfig // username -> config
	Debug           int                   // 0..10
	LogHash         bool                  // Log NTLMv2 hashes
	StaticChallenge string                // Static 16-char hex challenge
	EnableMIC       bool                  // Enable NTLM MIC request (default false for compatibility)
	NativeOS        string                // Custom Native OS string
	NativeLanMan    string                // Custom Native LanMan string
	DefinedShares   []*protocol.Share     // Explicitly defined shares from config
	ShareManager    *shares.ShareManager  // Custom ShareManager (optional)
	Hooks           hooks.EventHooks      // Optional event hooks
}

func DefaultConfig() *Config {
	return &Config{
		ListenAddress:   "0.0.0.0",
		Port:            protocol.SMB_PORT,
		SharesPath:      "./shares",
		Domain:          "WORKGROUP",
		ServerName:      "SMB-SERVER",
		EnableSMB1:      true,
		EnableSMB2:      true,
		EnableSMB3:      true,
		EnableNetBIOS:   true,
		NetBIOSPort:     protocol.NETBIOS_PORT,
		Users:           make(map[string]AuthConfig), // No default users
		LogHash:         false,
		StaticChallenge: "",
		EnableMIC:       false,
		NativeOS:        "Go SMB Server",
		NativeLanMan:    "Go SMB",
		Hooks:           &hooks.NoOpEventHooks{},
	}
}

type SMBServer struct {
	config         *Config
	shareManager   *shares.ShareManager
	authenticator  *auth.NTLMAuthenticator
	smb1Handler    *smb1.SMB1Handler
	smb2Handler    *smb2.SMB2Handler
	smb3Handler    *smb3.SMB3Handler
	listener       net.Listener
	netbiosNS      *netbios.NameService
	netbiosSession *netbios.SessionService
	mdnsResponder  *mdns.Responder
	running        bool
}

func NewSMBServer(config *Config) (*SMBServer, error) {
	if config == nil {
		config = DefaultConfig()
	}
	// Ensure hooks are set to prevent nil pointer checks everywhere
	if config.Hooks == nil {
		config.Hooks = &hooks.NoOpEventHooks{}
	}

	// Create shares directory if it doesn't exist and path is specified
	// Only if we are creating a default ShareManager or if SharesPath is relevant
	if config.ShareManager == nil && config.SharesPath != "" {
		if err := os.MkdirAll(config.SharesPath, 0755); err != nil {
			return nil, fmt.Errorf("failed to create shares directory: %v", err)
		}
	}

	// Initialize components
	var shareManager *shares.ShareManager
	if config.ShareManager != nil {
		shareManager = config.ShareManager
	} else {
		shareManager = shares.NewShareManager(config.SharesPath)
	}
	authenticator := auth.NewNTLMAuthenticator(config.Domain, config.ServerName)

	// Add users to authenticator
	for username, userConfig := range config.Users {
		if userConfig.NTHash != nil {
			authenticator.AddUserWithHash(username, userConfig.NTHash)
		} else {
			authenticator.AddUser(username, userConfig.Password)
		}
	}

	// Configure Authentication Options
	if config.LogHash {
		authenticator.SetLogHash(true)
	}
	if config.StaticChallenge != "" {
		authenticator.SetStaticChallenge(config.StaticChallenge)
	}

	// Add default shares
	if err := shareManager.AddDefaultShares(); err != nil {
		return nil, fmt.Errorf("failed to add default shares: %v", err)
	}

	// Auto-discover shares from SharesPath
	if config.SharesPath != "" && shareManager != nil {
		entries, err := os.ReadDir(config.SharesPath)
		if err == nil {
			for _, entry := range entries {
				if entry.IsDir() {
					name := entry.Name()
					share := &protocol.Share{
						Name:        name,
						Path:        name, // Relative to SharesPath
						Comment:     "Auto-exported share",
						ReadOnly:    false,
						GuestAccess: true, // Auto-exported are guest accessible by default? Or stricter?
						// For servesmb, usually we want easy access unless configured otherwise.
					}
					shareManager.AddShare(share)
				}
			}
		}
	}

	server := &SMBServer{
		config:        config,
		shareManager:  shareManager,
		authenticator: authenticator,
	}

	// Initialize protocol handlers
	if config.EnableSMB1 {
		server.smb1Handler = smb1.NewSMB1Handler(shareManager, authenticator, config.NativeOS, config.NativeLanMan)
	}
	if config.EnableSMB2 {
		server.smb2Handler = smb2.NewSMB2Handler(shareManager, authenticator, false, config.Debug, config.EnableMIC, config.Hooks)
	}
	if config.EnableSMB3 {
		server.smb3Handler = smb3.NewSMB3Handler(shareManager, authenticator, config.Debug, config.EnableMIC, config.Hooks)
	}

	// Initialize NetBIOS services if enabled
	if config.EnableNetBIOS {
		localIP := netbios.GetLocalIPAddress()
		server.netbiosNS = netbios.NewNameService(config.ServerName, config.Domain, localIP)

		// Use SMB3 handler as default for NetBIOS sessions, fall back to SMB2, then SMB1
		var netbiosHandler netbios.SMBHandler
		if server.smb3Handler != nil {
			netbiosHandler = server.smb3Handler
		} else if server.smb2Handler != nil {
			netbiosHandler = server.smb2Handler
		} else if server.smb1Handler != nil {
			netbiosHandler = server.smb1Handler
		}

		if netbiosHandler != nil {
			server.netbiosSession = netbios.NewSessionService(config.ServerName, config.Domain, config.NetBIOSPort, netbiosHandler)
		}
	}

	return server, nil
}

func (s *SMBServer) AddShare(share *protocol.Share) error {
	return s.shareManager.AddShare(share)
}

func (s *SMBServer) AddUser(username, password string) {
	s.authenticator.AddUser(username, password)
	s.config.Users[username] = AuthConfig{Password: password}
}

func (s *SMBServer) AddUserWithHash(username string, ntHash []byte) {
	s.authenticator.AddUserWithHash(username, ntHash)
	s.config.Users[username] = AuthConfig{NTHash: ntHash}
}

func (s *SMBServer) Start() error {
	address := fmt.Sprintf("%s:%d", s.config.ListenAddress, s.config.Port)

	var err error
	s.listener, err = net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %v", address, err)
	}

	s.running = true

	log.Printf("SMB Server starting on %s", address)
	log.Printf("Supported protocols: SMB1=%v, SMB2=%v, SMB3=%v, NetBIOS=%v",
		s.config.EnableSMB1, s.config.EnableSMB2, s.config.EnableSMB3, s.config.EnableNetBIOS)
	log.Printf("Shares path: %s", s.config.SharesPath)

	// Start NetBIOS services
	if s.config.EnableNetBIOS {
		if s.netbiosNS != nil {
			err := s.netbiosNS.Start()
			if err != nil {
				log.Printf("Warning: Failed to start NetBIOS Name Service: %v", err)
			}
		}
		if s.netbiosSession != nil {
			err := s.netbiosSession.Start()
			if err != nil {
				log.Printf("Warning: Failed to start NetBIOS Session Service: %v", err)
			}
		}
	}

	// List available shares
	shares := s.shareManager.ListShares()
	log.Printf("Available shares:")
	for _, share := range shares {
		log.Printf("  - %s: %s (%s)", share.Name, share.Comment,
			filepath.Join(s.config.SharesPath, share.Path))
	}

	// Advertise over mDNS / DNS-SD if enabled. Shares are registered before
	// Start() is called, so the share list (and Time Machine flags) is final.
	if s.config.EnableMDNS {
		var infos []mdns.ShareInfo
		for _, share := range shares {
			if share.Name == "IPC$" {
				continue
			}
			infos = append(infos, mdns.ShareInfo{Name: share.Name, TimeMachine: share.IsTimeMachine()})
		}
		s.mdnsResponder = mdns.New(s.config.ServerName, s.config.Port, localIPv4s(), infos, s.config.Debug)
		if err := s.mdnsResponder.Start(); err != nil {
			log.Printf("Warning: Failed to start mDNS advertisement: %v", err)
			s.mdnsResponder = nil
		}
	}

	for s.running {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.running {
				log.Printf("Error accepting connection: %v", err)
			}
			continue
		}

		log.Printf("New connection from %s", conn.RemoteAddr())
		go s.handleConnection(conn)
	}

	return nil
}

func (s *SMBServer) Stop() error {
	s.running = false

	// Stop NetBIOS services
	if s.netbiosNS != nil {
		s.netbiosNS.Stop()
	}
	if s.netbiosSession != nil {
		s.netbiosSession.Stop()
	}

	// Stop mDNS advertisement
	if s.mdnsResponder != nil {
		s.mdnsResponder.Stop()
	}

	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// localIPv4s returns the host's non-loopback, non-link-local IPv4 addresses for
// advertising in mDNS A records.
func localIPv4s() []net.IP {
	var ips []net.IP
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ips
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		ip4 := ip.To4()
		if ip4 == nil || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() {
			continue
		}
		ips = append(ips, ip4)
	}
	return ips
}

func (s *SMBServer) handleConnection(conn net.Conn) {
	if err := s.ServeConn(conn); err != nil {
		log.Printf("Error handling connection from %s: %v", conn.RemoteAddr(), err)
	}
}

// ServeConn handles a TCP session from a caller-owned listener. It closes conn
// when the session ends. SMB2/3 state belongs to this connection.
func (s *SMBServer) ServeConn(conn net.Conn) error {
	defer conn.Close()

	// Set connection timeout
	conn.SetReadDeadline(time.Now().Add(protocol.DEFAULT_TIMEOUT))

	// Detect protocol version by reading the first message and wrap the
	// connection so handlers can re-read the already consumed bytes.
	protocolVersion, wrappedConn, err := s.detectProtocol(conn)
	if err != nil {
		return err
	}

	// Route to appropriate handler
	var handler protocol.SMBHandler

	switch protocolVersion {
	case "SMB1":
		if !s.config.EnableSMB1 || s.smb1Handler == nil {
			return ErrSMB1Disabled
		}
		handler = s.smb1Handler
	case "SMB2":
		if !s.config.EnableSMB2 || s.smb2Handler == nil {
			return fmt.Errorf("SMB2 is disabled")
		}
		handler = s.smb2Handler.NewConnectionHandler()
	case "SMB3":
		if !s.config.EnableSMB3 || s.smb3Handler == nil {
			return fmt.Errorf("SMB3 is disabled")
		}
		handler = s.smb3Handler.NewConnectionHandler()
	default:
		return fmt.Errorf("unsupported protocol %s", protocolVersion)
	}

	// Clear read deadline; let protocol handlers manage their own timeouts
	conn.SetReadDeadline(time.Time{})
	// Handle the connection with the appropriate handler using the wrapped conn
	// which feeds back the initial negotiate bytes to the handler.
	if wrappedConn != nil {
		conn = wrappedConn
	}
	return handler.HandleConnection(conn)
}

func (s *SMBServer) detectProtocol(conn net.Conn) (string, net.Conn, error) {
	// Read NetBIOS header (4 bytes)
	nbHeader := make([]byte, 4)
	_, err := io.ReadFull(conn, nbHeader)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read NetBIOS header: %w", err)
	}

	// Extract message length
	msgLen := uint32(nbHeader[1])<<16 | uint32(nbHeader[2])<<8 | uint32(nbHeader[3])
	if msgLen > protocol.MAX_BUFFER_SIZE || msgLen < 4 {
		return "", nil, fmt.Errorf("invalid message length: %d", msgLen)
	}

	// Read first 4 bytes of SMB message to detect protocol
	protocolID := make([]byte, 4)
	_, err = io.ReadFull(conn, protocolID)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read protocol ID: %w", err)
	}

	// Read rest of message to avoid breaking the stream
	remaining := make([]byte, msgLen-4)
	_, err = io.ReadFull(conn, remaining)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read remaining message: %w", err)
	}

	// Reconstruct full message and create a new connection wrapper
	fullMessage := make([]byte, 4+msgLen)
	copy(fullMessage[0:4], nbHeader)
	copy(fullMessage[4:8], protocolID)
	copy(fullMessage[8:], remaining)

	// Create a buffered connection that includes the read data
	bufferedConn := &bufferedConnection{
		Conn:   conn,
		buffer: fullMessage,
		offset: 0,
	}

	// Detect protocol based on signature
	protocolStr := string(protocolID)
	switch protocolStr {
	case protocol.SMB1_PROTOCOL_ID:
		// Peek inside SMB1 negotiate to see if client proposes SMB2 dialects.
		// SMB1 header is 32 bytes; dialect strings are in Data after Parameters.
		if len(fullMessage) >= 39 && fullMessage[8] == 0x72 {
			// The SMB1 NEGOTIATE dialect list starts after WordCount and ByteCount.
			// Both modern dialect names have the 0x02 format marker.
			dialects := fullMessage[39:]
			if bytes.Contains(dialects, []byte("\x02SMB 2.002\x00")) ||
				bytes.Contains(dialects, []byte("\x02SMB 2.???\x00")) {
				// Reply with SMB2 NEGOTIATE. Use the handler that will
				// actually process the connection so dialect state is shared.
				if s.smb3Handler != nil {
					resp := s.smb3Handler.BuildNegotiateResponseBytes()
					if len(resp) > 0 {
						if _, err := conn.Write(resp); err != nil {
							return "", nil, err
						}
						return "SMB3", conn, nil
					}
				} else if s.smb2Handler != nil {
					resp := s.smb2Handler.BuildNegotiateResponseBytes()
					if len(resp) > 0 {
						if _, err := conn.Write(resp); err != nil {
							return "", nil, err
						}
						return "SMB2", conn, nil
					}
				}
			}
		}
		if !s.config.EnableSMB1 || s.smb1Handler == nil {
			// SMB1 file service is off. A pure SMB1 client would otherwise be
			// left hanging until its own timeout (Windows reports the very
			// unhelpful ERROR_BAD_NETPATH). Answer its NEGOTIATE with
			// STATUS_NOT_SUPPORTED so it gives up immediately, and say which
			// dialects it asked for.
			if len(fullMessage) >= 33 && fullMessage[8] == protocol.SMB1_COM_NEGOTIATE {
				if _, err := conn.Write(smb1Refusal(fullMessage[4:36])); err != nil {
					return "", nil, err
				}
			}
			return "", nil, &SMB1DisabledError{Dialects: smb1DialectNames(fullMessage)}
		}
		return "SMB1", bufferedConn, nil
	case protocol.SMB2_PROTOCOL_ID:
		// For SMB2/SMB3, we need to look at the negotiate request to determine exact version
		// For now, default to SMB2, the handler will negotiate the exact version
		if s.config.EnableSMB3 {
			return "SMB3", bufferedConn, nil // SMB3 handler supports both SMB2 and SMB3
		}
		return "SMB2", bufferedConn, nil
	default:
		return "", nil, fmt.Errorf("unknown protocol signature: %x", protocolID)
	}
}

// bufferedConnection wraps a connection with a buffer for already-read data
type bufferedConnection struct {
	net.Conn
	buffer []byte
	offset int
}

func (bc *bufferedConnection) Read(p []byte) (int, error) {
	// First, serve data from buffer
	if bc.offset < len(bc.buffer) {
		n := copy(p, bc.buffer[bc.offset:])
		bc.offset += n
		return n, nil
	}

	// Buffer is exhausted, read from underlying connection
	return bc.Conn.Read(p)
}

func (s *SMBServer) IsRunning() bool {
	return s.running
}

func (s *SMBServer) GetConfig() *Config {
	return s.config
}

func (s *SMBServer) GetShareManager() *shares.ShareManager {
	return s.shareManager
}

func (s *SMBServer) GetStats() map[string]interface{} {
	stats := make(map[string]interface{})

	stats["running"] = s.running
	stats["listen_address"] = s.config.ListenAddress
	stats["port"] = s.config.Port
	stats["domain"] = s.config.Domain
	stats["server_name"] = s.config.ServerName

	// Protocol support
	protocols := make(map[string]bool)
	protocols["SMB1"] = s.config.EnableSMB1
	protocols["SMB2"] = s.config.EnableSMB2
	protocols["SMB3"] = s.config.EnableSMB3
	stats["protocols"] = protocols

	// Share information
	shares := s.shareManager.ListShares()
	shareInfo := make([]map[string]interface{}, len(shares))
	for i, share := range shares {
		shareInfo[i] = map[string]interface{}{
			"name":         share.Name,
			"path":         share.Path,
			"comment":      share.Comment,
			"readonly":     share.ReadOnly,
			"guest_access": share.GuestAccess,
		}
	}
	stats["shares"] = shareInfo

	// User count
	stats["user_count"] = len(s.config.Users)

	return stats
}

// smb1Refusal builds the SMB1 NEGOTIATE answer used when SMB1 file service is
// off: the client's own header (so it can match MID/TID/PID/UID) with
// STATUS_NOT_SUPPORTED, SMB_FLAGS_SERVER_TO_REDIR set, WordCount=0 and
// ByteCount=0 — i.e. no dialect agreed. Without this the connection is simply
// closed and Windows reports error 53 (ERROR_BAD_NETPATH) after a timeout.
func smb1Refusal(request []byte) []byte {
	msg := make([]byte, 32)
	copy(msg, request)
	copy(msg[0:4], protocol.SMB1_PROTOCOL_ID)
	binary.LittleEndian.PutUint32(msg[5:9], protocol.STATUS_NOT_SUPPORTED)
	msg[9] |= 0x80             // SMB_FLAGS_SERVER_TO_REDIR
	msg = append(msg, 0, 0, 0) // WordCount = 0, ByteCount = 0

	frame := make([]byte, 4, 4+len(msg))
	frame[1] = byte(len(msg) >> 16)
	frame[2] = byte(len(msg) >> 8)
	frame[3] = byte(len(msg))
	return append(frame, msg...)
}

// smb1DialectNames lists the dialects an SMB1 NEGOTIATE request proposed, so
// the caller's log can say what the client can actually speak. The list is a
// buffer of <0x02><name><NUL> entries, not a WORD array; it starts after the
// NBSS header (4), the SMB1 header (32), WordCount (1) and ByteCount (2).
func smb1DialectNames(fullMessage []byte) []string {
	if len(fullMessage) < 39 || fullMessage[8] != protocol.SMB1_COM_NEGOTIATE {
		return nil
	}
	var names []string
	for _, entry := range bytes.Split(fullMessage[39:], []byte{0}) {
		if len(entry) == 0 || entry[0] != 0x02 {
			continue
		}
		names = append(names, string(entry[1:]))
	}
	return names
}
