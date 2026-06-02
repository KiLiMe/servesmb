package test

import (
	"testing"

	"github.com/3xport/servesmb/pkg/protocol"
)

func TestSMB1MessageMarshalUnmarshal(t *testing.T) {
	// Create a test SMB1 message
	msg := &protocol.SMB1Message{
		Header: protocol.SMB1Header{
			Protocol: [4]byte{0xFF, 'S', 'M', 'B'},
			Command:  protocol.SMB1_COM_NEGOTIATE,
			Status:   protocol.STATUS_SUCCESS,
			Flags:    0x80,
			Flags2:   0x0001,
			MID:      1,
		},
		Parameters: []byte{0x00},
		Data:       []byte{0x00, 0x00},
	}

	// Marshal the message
	data, err := msg.Marshal()
	if err != nil {
		t.Fatalf("Failed to marshal SMB1 message: %v", err)
	}

	// Verify minimum length
	if len(data) < protocol.SMB1_HEADER_SIZE {
		t.Fatalf("Marshaled data too short: %d bytes", len(data))
	}

	// Unmarshal into a new message
	newMsg := &protocol.SMB1Message{}
	err = newMsg.Unmarshal(data)
	if err != nil {
		t.Fatalf("Failed to unmarshal SMB1 message: %v", err)
	}

	// Verify fields
	if newMsg.Header.Command != msg.Header.Command {
		t.Errorf("Command mismatch: expected %d, got %d", msg.Header.Command, newMsg.Header.Command)
	}
	if newMsg.Header.Status != msg.Header.Status {
		t.Errorf("Status mismatch: expected %d, got %d", msg.Header.Status, newMsg.Header.Status)
	}
	if newMsg.Header.MID != msg.Header.MID {
		t.Errorf("MID mismatch: expected %d, got %d", msg.Header.MID, newMsg.Header.MID)
	}
}

func TestSMB2MessageMarshalUnmarshal(t *testing.T) {
	// Create a test SMB2 message
	msg := &protocol.SMB2Message{
		Header: protocol.SMB2Header{
			ProtocolID:    [4]byte{0xFE, 'S', 'M', 'B'},
			StructureSize: 64,
			Command:       protocol.SMB2_NEGOTIATE,
			Status:        protocol.STATUS_SUCCESS,
			MessageID:     1,
		},
		Data: []byte{0x41, 0x00, 0x01, 0x00},
	}

	// Marshal the message
	data, err := msg.Marshal()
	if err != nil {
		t.Fatalf("Failed to marshal SMB2 message: %v", err)
	}

	// Verify minimum length
	if len(data) < protocol.SMB2_HEADER_SIZE {
		t.Fatalf("Marshaled data too short: %d bytes", len(data))
	}

	// Unmarshal into a new message
	newMsg := &protocol.SMB2Message{}
	err = newMsg.Unmarshal(data)
	if err != nil {
		t.Fatalf("Failed to unmarshal SMB2 message: %v", err)
	}

	// Verify fields
	if newMsg.Header.Command != msg.Header.Command {
		t.Errorf("Command mismatch: expected %d, got %d", msg.Header.Command, newMsg.Header.Command)
	}
	if newMsg.Header.Status != msg.Header.Status {
		t.Errorf("Status mismatch: expected %d, got %d", msg.Header.Status, newMsg.Header.Status)
	}
	if newMsg.Header.MessageID != msg.Header.MessageID {
		t.Errorf("MessageID mismatch: expected %d, got %d", msg.Header.MessageID, newMsg.Header.MessageID)
	}
}

func TestProtocolDetection(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
		protocol string
	}{
		{
			name:     "SMB1 Protocol",
			data:     []byte{0xFF, 'S', 'M', 'B'},
			expected: true,
			protocol: "SMB1",
		},
		{
			name:     "SMB2 Protocol",
			data:     []byte{0xFE, 'S', 'M', 'B'},
			expected: true,
			protocol: "SMB2",
		},
		{
			name:     "Invalid Protocol",
			data:     []byte{0x00, 'X', 'Y', 'Z'},
			expected: false,
			protocol: "",
		},
		{
			name:     "Short Data",
			data:     []byte{0xFF, 'S'},
			expected: false,
			protocol: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.protocol {
			case "SMB1":
				result := protocol.IsProtocolSMB1(tt.data)
				if result != tt.expected {
					t.Errorf("IsProtocolSMB1() = %v, expected %v", result, tt.expected)
				}
			case "SMB2":
				result := protocol.IsProtocolSMB2(tt.data)
				if result != tt.expected {
					t.Errorf("IsProtocolSMB2() = %v, expected %v", result, tt.expected)
				}
			default:
				// Test both should return false for invalid protocols
				if protocol.IsProtocolSMB1(tt.data) || protocol.IsProtocolSMB2(tt.data) {
					t.Errorf("Invalid protocol detected as valid")
				}
			}
		})
	}
}

func TestMessageInterfaces(t *testing.T) {
	// Test SMB1 message implements SMBMessage interface
	var msg1 protocol.SMBMessage = &protocol.SMB1Message{
		Header: protocol.SMB1Header{
			Command: protocol.SMB1_COM_NEGOTIATE,
			Status:  protocol.STATUS_SUCCESS,
			MID:     123,
		},
	}

	if msg1.GetCommand() != uint16(protocol.SMB1_COM_NEGOTIATE) {
		t.Errorf("SMB1 GetCommand() = %d, expected %d", msg1.GetCommand(), protocol.SMB1_COM_NEGOTIATE)
	}
	if msg1.GetStatus() != protocol.STATUS_SUCCESS {
		t.Errorf("SMB1 GetStatus() = %d, expected %d", msg1.GetStatus(), protocol.STATUS_SUCCESS)
	}
	if msg1.GetMessageID() != 123 {
		t.Errorf("SMB1 GetMessageID() = %d, expected %d", msg1.GetMessageID(), 123)
	}

	// Test SMB2 message implements SMBMessage interface
	var msg2 protocol.SMBMessage = &protocol.SMB2Message{
		Header: protocol.SMB2Header{
			Command:   protocol.SMB2_NEGOTIATE,
			Status:    protocol.STATUS_SUCCESS,
			MessageID: 456,
		},
	}

	if msg2.GetCommand() != protocol.SMB2_NEGOTIATE {
		t.Errorf("SMB2 GetCommand() = %d, expected %d", msg2.GetCommand(), protocol.SMB2_NEGOTIATE)
	}
	if msg2.GetStatus() != protocol.STATUS_SUCCESS {
		t.Errorf("SMB2 GetStatus() = %d, expected %d", msg2.GetStatus(), protocol.STATUS_SUCCESS)
	}
	if msg2.GetMessageID() != 456 {
		t.Errorf("SMB2 GetMessageID() = %d, expected %d", msg2.GetMessageID(), 456)
	}
}
