package netbios

import (
	"fmt"
	"strings"
)

// NetBIOS constants and definitions

const (
	// NetBIOS ports
	NETBIOS_NS_PORT  = 137 // Name Service
	NETBIOS_DGM_PORT = 138 // Datagram Service
	NETBIOS_SSN_PORT = 139 // Session Service

	// NetBIOS Name Service packet types
	NETBIOS_QUERY           = 0x0000
	NETBIOS_REGISTRATION    = 0x2900
	NETBIOS_RELEASE         = 0x3000
	NETBIOS_WACK            = 0x3700
	NETBIOS_REFRESH         = 0x3900
	NETBIOS_MULTI_HOMED_REG = 0x2F00

	// NetBIOS Name Service response codes
	NETBIOS_RCODE_SUCCESS = 0x0
	NETBIOS_RCODE_FMT_ERR = 0x1
	NETBIOS_RCODE_SRV_ERR = 0x2
	NETBIOS_RCODE_NAM_ERR = 0x3
	NETBIOS_RCODE_IMP_ERR = 0x4
	NETBIOS_RCODE_RFS_ERR = 0x5
	NETBIOS_RCODE_ACT_ERR = 0x6
	NETBIOS_RCODE_CFT_ERR = 0x7

	// NetBIOS Node Types
	NETBIOS_B_NODE = 0x0000 // Broadcast
	NETBIOS_P_NODE = 0x2000 // Point-to-point
	NETBIOS_M_NODE = 0x4000 // Mixed
	NETBIOS_H_NODE = 0x6000 // Hybrid

	// NetBIOS Name types (16th byte of NetBIOS name)
	NETBIOS_WORKSTATION    = 0x00
	NETBIOS_MESSENGER      = 0x03
	NETBIOS_FILE_SERVER    = 0x20
	NETBIOS_DOMAIN_MASTER  = 0x1B
	NETBIOS_MASTER_BROWSER = 0x1D
	NETBIOS_BROWSER_BACKUP = 0x1E

	// NetBIOS Session Service
	NETBIOS_SESSION_MESSAGE       = 0x00
	NETBIOS_SESSION_REQUEST       = 0x81
	NETBIOS_POSITIVE_SESSION_RESP = 0x82
	NETBIOS_NEGATIVE_SESSION_RESP = 0x83
	NETBIOS_RETARGET_SESSION_RESP = 0x84
	NETBIOS_SESSION_KEEP_ALIVE    = 0x85

	// NetBIOS name length
	NETBIOS_NAME_LENGTH         = 16
	NETBIOS_ENCODED_NAME_LENGTH = 32

	// NetBIOS Session Service errors
	NETBIOS_ERR_NOT_LISTENING          = 0x80
	NETBIOS_ERR_NOT_LISTENING_CALLED   = 0x81
	NETBIOS_ERR_CALLED_NOT_PRESENT     = 0x82
	NETBIOS_ERR_INSUFFICIENT_RESOURCES = 0x83
	NETBIOS_ERR_UNSPECIFIED            = 0x8F
)

// NetBIOS name structure
type NetBIOSName struct {
	Name     [16]byte
	NameType byte
	Scope    string
}

// NetBIOS Name Service header
type NetBIOSHeader struct {
	TransactionID uint16
	Flags         uint16
	Questions     uint16
	AnswerRRs     uint16
	AuthorityRRs  uint16
	AdditionalRRs uint16
}

// NetBIOS Resource Record
type NetBIOSResourceRecord struct {
	Name     string
	Type     uint16
	Class    uint16
	TTL      uint32
	RDLength uint16
	RData    []byte
}

// NetBIOS Session Service header
type NetBIOSSessionHeader struct {
	Type   byte
	Flags  byte
	Length uint32 // 17-bit length field, stored as uint32
}

// NetBIOS Node status response
type NetBIOSNodeStatus struct {
	Names []NetBIOSNameEntry
	Stats NetBIOSStatistics
}

type NetBIOSNameEntry struct {
	Name     [15]byte
	NameType byte
	Flags    uint16
}

type NetBIOSStatistics struct {
	UnitID              [6]byte
	Jumpers             byte
	TestResult          byte
	VersionNumber       uint16
	PeriodOfStats       uint16
	CRCErrors           uint16
	AlignmentErrors     uint16
	Collisions          uint16
	SendAborts          uint16
	GoodSends           uint32
	GoodReceives        uint32
	Retransmits         uint16
	NoResourceCond      uint16
	FreeCommandBlks     uint16
	TotalCommandBlks    uint16
	MaxTotalSessions    uint16
	SessionDataPktSize  uint16
	PendingSessions     uint16
	MaxSessionsPossible uint16
	SessionDataPkts     uint16
}

// Helper functions for NetBIOS name encoding/decoding
func EncodeNetBIOSName(name string, nameType byte, scope string) []byte {
	// Pad name to 15 characters
	encodedName := make([]byte, 15)
	copy(encodedName, []byte(name))
	for i := len(name); i < 15; i++ {
		encodedName[i] = ' '
	}

	// Add name type as 16th byte
	encodedName = append(encodedName, nameType)

	// NetBIOS first-level encoding: each byte becomes two bytes
	encoded := make([]byte, 0, 32)
	for _, b := range encodedName {
		encoded = append(encoded, 'A'+(b>>4))
		encoded = append(encoded, 'A'+(b&0x0F))
	}

	return encoded
}

func DecodeNetBIOSName(encoded []byte) (string, byte, error) {
	if len(encoded) < 32 {
		return "", 0, fmt.Errorf("encoded name too short")
	}

	// Decode first-level encoding
	decoded := make([]byte, 16)
	for i := 0; i < 16; i++ {
		if i*2+1 >= len(encoded) {
			break
		}
		high := encoded[i*2] - 'A'
		low := encoded[i*2+1] - 'A'
		decoded[i] = (high << 4) | low
	}

	// Extract name (first 15 bytes, trimmed)
	name := string(decoded[:15])
	name = strings.TrimRight(name, " ")

	// Extract name type (16th byte)
	nameType := decoded[15]

	return name, nameType, nil
}

// Create NetBIOS name with proper encoding
func CreateNetBIOSName(name string, nameType byte) *NetBIOSName {
	netbiosName := &NetBIOSName{
		NameType: nameType,
		Scope:    "",
	}

	// Pad and copy name
	padded := name
	if len(padded) > 15 {
		padded = padded[:15]
	}
	for len(padded) < 15 {
		padded += " "
	}

	copy(netbiosName.Name[:15], []byte(padded))
	netbiosName.Name[15] = nameType

	return netbiosName
}

func (n *NetBIOSName) String() string {
	name := strings.TrimRight(string(n.Name[:15]), " ")
	return fmt.Sprintf("%s<%02x>", name, n.NameType)
}
