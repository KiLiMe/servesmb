package netbios

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// NetBIOS Name Service implementation
type NameService struct {
	serverName string
	domain     string
	ipAddress  net.IP
	names      map[string]*NetBIOSName
	conn       *net.UDPConn
}

func NewNameService(serverName, domain string, ipAddress net.IP) *NameService {
	ns := &NameService{
		serverName: strings.ToUpper(serverName),
		domain:     strings.ToUpper(domain),
		ipAddress:  ipAddress,
		names:      make(map[string]*NetBIOSName),
	}

	// Register default NetBIOS names
	ns.registerDefaultNames()

	return ns
}

func (ns *NameService) registerDefaultNames() {
	// Register server name with different service types
	ns.names[ns.serverName+string(rune(NETBIOS_WORKSTATION))] = CreateNetBIOSName(ns.serverName, NETBIOS_WORKSTATION)
	ns.names[ns.serverName+string(rune(NETBIOS_FILE_SERVER))] = CreateNetBIOSName(ns.serverName, NETBIOS_FILE_SERVER)
	ns.names[ns.serverName+string(rune(NETBIOS_MESSENGER))] = CreateNetBIOSName(ns.serverName, NETBIOS_MESSENGER)

	// Register domain/workgroup names
	if ns.domain != "" {
		ns.names[ns.domain+string(rune(NETBIOS_DOMAIN_MASTER))] = CreateNetBIOSName(ns.domain, NETBIOS_DOMAIN_MASTER)
		ns.names[ns.domain+string(rune(NETBIOS_MASTER_BROWSER))] = CreateNetBIOSName(ns.domain, NETBIOS_MASTER_BROWSER)
	}
}

func (ns *NameService) Start() error {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", NETBIOS_NS_PORT))
	if err != nil {
		return fmt.Errorf("failed to resolve NetBIOS NS address: %v", err)
	}

	ns.conn, err = net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on NetBIOS NS port: %v", err)
	}

	fmt.Printf("NetBIOS Name Service listening on port %d\n", NETBIOS_NS_PORT)

	// Handle incoming packets
	go ns.handlePackets()

	return nil
}

func (ns *NameService) Stop() error {
	if ns.conn != nil {
		return ns.conn.Close()
	}
	return nil
}

func (ns *NameService) handlePackets() {
	buffer := make([]byte, 1024)

	for {
		n, addr, err := ns.conn.ReadFromUDP(buffer)
		if err != nil {
			fmt.Printf("NetBIOS NS read error: %v\n", err)
			continue
		}

		go ns.processPacket(buffer[:n], addr)
	}
}

func (ns *NameService) processPacket(data []byte, addr *net.UDPAddr) {
	if len(data) < 12 {
		return // Too short for NetBIOS header
	}

	header, err := parseNetBIOSHeader(data)
	if err != nil {
		return
	}

	// Handle different NetBIOS operations
	opcode := (header.Flags >> 11) & 0x0F

	switch opcode {
	case 0: // Query
		ns.handleNameQuery(header, data[12:], addr)
	case 5: // Registration
		ns.handleNameRegistration(header, data[12:], addr)
	case 6: // Release
		ns.handleNameRelease(header, data[12:], addr)
	}
}

func (ns *NameService) handleNameQuery(header *NetBIOSHeader, data []byte, addr *net.UDPAddr) {
	if header.Questions == 0 {
		return
	}

	// Parse question
	name, nameType, err := ns.parseQuestion(data)
	if err != nil {
		return
	}

	fmt.Printf("NetBIOS query for %s<%02x> from %s\n", name, nameType, addr)

	// Check if we have this name registered
	key := strings.ToUpper(name) + string(rune(nameType))
	if _, exists := ns.names[key]; exists {
		ns.sendNameQueryResponse(header.TransactionID, name, nameType, addr)
	}
}

func (ns *NameService) handleNameRegistration(header *NetBIOSHeader, data []byte, addr *net.UDPAddr) {
	// For now, just acknowledge registration attempts
	// In a full implementation, we'd handle name conflicts
	fmt.Printf("NetBIOS registration from %s\n", addr)
}

func (ns *NameService) handleNameRelease(header *NetBIOSHeader, data []byte, addr *net.UDPAddr) {
	fmt.Printf("NetBIOS release from %s\n", addr)
}

func (ns *NameService) sendNameQueryResponse(transactionID uint16, name string, nameType byte, addr *net.UDPAddr) {
	response := ns.buildNameQueryResponse(transactionID, name, nameType)

	_, err := ns.conn.WriteToUDP(response, addr)
	if err != nil {
		fmt.Printf("Failed to send NetBIOS response: %v\n", err)
	}
}

func (ns *NameService) buildNameQueryResponse(transactionID uint16, name string, nameType byte) []byte {
	response := make([]byte, 0, 512)

	// NetBIOS header
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], transactionID)
	binary.BigEndian.PutUint16(header[2:4], 0x8500)   // Response, Authoritative, Recursion Desired
	binary.BigEndian.PutUint16(header[4:6], 0x0000)   // Questions = 0
	binary.BigEndian.PutUint16(header[6:8], 0x0001)   // Answer RRs = 1
	binary.BigEndian.PutUint16(header[8:10], 0x0000)  // Authority RRs = 0
	binary.BigEndian.PutUint16(header[10:12], 0x0000) // Additional RRs = 0

	response = append(response, header...)

	// Answer section
	// Name (encoded)
	encodedName := ns.encodeQuestionName(name, nameType)
	response = append(response, encodedName...)

	// Type (NB = 0x0020)
	response = append(response, 0x00, 0x20)

	// Class (IN = 0x0001)
	response = append(response, 0x00, 0x01)

	// TTL (300 seconds)
	response = append(response, 0x00, 0x00, 0x01, 0x2C)

	// RD Length (6 bytes for IP)
	response = append(response, 0x00, 0x06)

	// RD Data (IP address with flags)
	response = append(response, 0x60, 0x00) // G=0, ONT=3 (B-node), others=0
	response = append(response, ns.ipAddress.To4()...)

	return response
}

func (ns *NameService) parseQuestion(data []byte) (string, byte, error) {
	if len(data) < 4 {
		return "", 0, fmt.Errorf("question too short")
	}

	// Parse name length
	nameLen := int(data[0])
	if len(data) < nameLen+1 {
		return "", 0, fmt.Errorf("name data too short")
	}

	// Decode NetBIOS name
	encoded := data[1 : nameLen+1]
	name, nameType, err := DecodeNetBIOSName(encoded)
	if err != nil {
		return "", 0, err
	}

	return name, nameType, nil
}

func (ns *NameService) encodeQuestionName(name string, nameType byte) []byte {
	encoded := EncodeNetBIOSName(name, nameType, "")

	// Add length byte and terminator
	result := make([]byte, 0, len(encoded)+2)
	result = append(result, byte(len(encoded)))
	result = append(result, encoded...)
	result = append(result, 0x00) // Terminator

	return result
}

func parseNetBIOSHeader(data []byte) (*NetBIOSHeader, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("header too short")
	}

	return &NetBIOSHeader{
		TransactionID: binary.BigEndian.Uint16(data[0:2]),
		Flags:         binary.BigEndian.Uint16(data[2:4]),
		Questions:     binary.BigEndian.Uint16(data[4:6]),
		AnswerRRs:     binary.BigEndian.Uint16(data[6:8]),
		AuthorityRRs:  binary.BigEndian.Uint16(data[8:10]),
		AdditionalRRs: binary.BigEndian.Uint16(data[10:12]),
	}, nil
}

// Node Status Service - responds to NetBIOS adapter status queries
func (ns *NameService) HandleNodeStatusQuery(transactionID uint16, addr *net.UDPAddr) {
	response := ns.buildNodeStatusResponse(transactionID)

	_, err := ns.conn.WriteToUDP(response, addr)
	if err != nil {
		fmt.Printf("Failed to send node status response: %v\n", err)
	}
}

func (ns *NameService) buildNodeStatusResponse(transactionID uint16) []byte {
	response := make([]byte, 0, 512)

	// NetBIOS header
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], transactionID)
	binary.BigEndian.PutUint16(header[2:4], 0x8500)   // Response flags
	binary.BigEndian.PutUint16(header[4:6], 0x0000)   // Questions = 0
	binary.BigEndian.PutUint16(header[6:8], 0x0001)   // Answer RRs = 1
	binary.BigEndian.PutUint16(header[8:10], 0x0000)  // Authority RRs = 0
	binary.BigEndian.PutUint16(header[10:12], 0x0000) // Additional RRs = 0

	response = append(response, header...)

	// Answer section with node status
	// Name
	response = append(response, 0x20) // Name length
	response = append(response, EncodeNetBIOSName("*", 0x00, "")...)
	response = append(response, 0x00) // Terminator

	// Type (NBSTAT = 0x0021)
	response = append(response, 0x00, 0x21)

	// Class (IN = 0x0001)
	response = append(response, 0x00, 0x01)

	// TTL (0)
	response = append(response, 0x00, 0x00, 0x00, 0x00)

	// Build node status data
	nodeStatus := ns.buildNodeStatusData()

	// RD Length
	binary.BigEndian.PutUint16(response[len(response):len(response)+2], uint16(len(nodeStatus)))
	response = append(response, 0x00, 0x00) // Placeholder, will be filled
	binary.BigEndian.PutUint16(response[len(response)-2:], uint16(len(nodeStatus)))

	// RD Data
	response = append(response, nodeStatus...)

	return response
}

func (ns *NameService) buildNodeStatusData() []byte {
	data := make([]byte, 0, 256)

	// Number of names
	nameCount := len(ns.names)
	data = append(data, byte(nameCount))

	// Name entries
	for _, name := range ns.names {
		// Name (15 bytes + name type)
		nameBytes := make([]byte, 16)
		copy(nameBytes, name.Name[:])
		data = append(data, nameBytes...)

		// Flags (G=0, ONT=00, others as appropriate)
		flags := uint16(0x0000)
		if name.NameType == NETBIOS_DOMAIN_MASTER || name.NameType == NETBIOS_MASTER_BROWSER {
			flags |= 0x8000 // Group name
		}
		binary.BigEndian.PutUint16(data[len(data):len(data)+2], flags)
		data = append(data, 0x00, 0x00) // Placeholder, will be filled
		binary.BigEndian.PutUint16(data[len(data)-2:], flags)
	}

	// Statistics (simplified)
	stats := make([]byte, 46)                                    // NetBIOS statistics structure
	copy(stats[0:6], []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) // Unit ID
	stats[6] = 0x00                                              // Jumpers
	stats[7] = 0x00                                              // Test result
	// ... fill in other statistics fields as needed

	data = append(data, stats...)

	return data
}

// Utility function to get local IP address
func GetLocalIPAddress() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return net.ParseIP("127.0.0.1")
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP
}
