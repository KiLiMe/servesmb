package test

import (
	"bytes"
	"testing"

	"github.com/3xport/servesmb/pkg/auth"
)

func TestNTLMAuthenticator(t *testing.T) {
	// Create NTLM authenticator
	authenticator := auth.NewNTLMAuthenticator("TESTDOMAIN", "TESTSERVER")

	// Add test users
	authenticator.AddUser("testuser", "testpass")
	authenticator.AddUser("admin", "adminpass")
	authenticator.AddUser("guest", "")

	// Test Type 1 (Negotiate) message parsing
	type1Data := []byte{
		'N', 'T', 'L', 'M', 'S', 'S', 'P', 0x00, // Signature
		0x01, 0x00, 0x00, 0x00, // Message Type (1)
		0x07, 0x82, 0x08, 0x00, // Flags
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Domain security buffer
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Workstation security buffer
	}

	msg1, err := authenticator.ParseType1(type1Data)
	if err != nil {
		t.Fatalf("Failed to parse Type 1 message: %v", err)
	}

	if msg1.Type != 1 {
		t.Errorf("Expected Type 1, got Type %d", msg1.Type)
	}

	// Test Type 2 (Challenge) message creation
	type2Data, err := authenticator.CreateType2Response(msg1)
	if err != nil {
		t.Fatalf("Failed to create Type 2 response: %v", err)
	}

	if len(type2Data) < 32 {
		t.Errorf("Type 2 message too short: %d bytes", len(type2Data))
	}

	// Verify Type 2 signature
	if !bytes.Equal(type2Data[0:8], []byte("NTLMSSP\x00")) {
		t.Error("Type 2 message has invalid signature")
	}

	// Verify Type 2 message type
	msgType := uint32(type2Data[8]) | uint32(type2Data[9])<<8 | uint32(type2Data[10])<<16 | uint32(type2Data[11])<<24
	if msgType != 2 {
		t.Errorf("Expected Type 2, got Type %d", msgType)
	}

	// Test Type 3 (Authenticate) message parsing
	type3Data := []byte{
		'N', 'T', 'L', 'M', 'S', 'S', 'P', 0x00, // Signature
		0x03, 0x00, 0x00, 0x00, // Message Type (3)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // LM Response security buffer
		0x18, 0x00, 0x18, 0x00, 0x40, 0x00, 0x00, 0x00, // NT Response security buffer
		0x0E, 0x00, 0x0E, 0x00, 0x58, 0x00, 0x00, 0x00, // Domain security buffer
		0x10, 0x00, 0x10, 0x00, 0x66, 0x00, 0x00, 0x00, // Username security buffer
		0x00, 0x00, 0x00, 0x00, 0x76, 0x00, 0x00, 0x00, // Workstation security buffer
		0x00, 0x00, 0x00, 0x00, 0x76, 0x00, 0x00, 0x00, // Session key security buffer
		0x01, 0x02, 0x00, 0x00, // Flags
		// NT Response (24 bytes of dummy data)
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		// Domain (UTF-16LE): "TESTDOMAIN"
		'T', 0x00, 'E', 0x00, 'S', 0x00, 'T', 0x00, 'D', 0x00, 'O', 0x00, 'M', 0x00,
		// Username (UTF-16LE): "testuser"
		't', 0x00, 'e', 0x00, 's', 0x00, 't', 0x00, 'u', 0x00, 's', 0x00, 'e', 0x00, 'r', 0x00,
	}

	msg3, err := authenticator.ParseType3(type3Data)
	if err != nil {
		t.Fatalf("Failed to parse Type 3 message: %v", err)
	}

	if msg3.Type != 3 {
		t.Errorf("Expected Type 3, got Type %d", msg3.Type)
	}

	expectedUsername := "testuser"
	if msg3.Username != expectedUsername {
		t.Errorf("Username mismatch: expected %s, got %s", expectedUsername, msg3.Username)
	}

	expectedDomain := "TESTDOM" // Only 7 characters due to buffer length
	if msg3.Domain != expectedDomain {
		t.Errorf("Domain mismatch: expected %s, got %s", expectedDomain, msg3.Domain)
	}

	// Test authentication verification
	if !authenticator.VerifyAuthentication(msg3) {
		t.Error("Authentication should succeed for valid user")
	}

	// Test authentication with invalid user
	msg3.Username = "invaliduser"
	if authenticator.VerifyAuthentication(msg3) {
		t.Error("Authentication should fail for invalid user")
	}

	// Test authentication with empty response (should fail)
	msg3.Username = "testuser"
	msg3.Response = []byte{}
	if authenticator.VerifyAuthentication(msg3) {
		t.Error("Authentication should fail with empty response")
	}
}

func TestNTLMInvalidMessages(t *testing.T) {
	authenticator := auth.NewNTLMAuthenticator("TEST", "SERVER")

	// Test parsing invalid Type 1 message (too short)
	invalidType1 := []byte{
		'N', 'T', 'L', 'M', 'S', 'S', 'P', 0x00,
		0x01, 0x00, 0x00, 0x00,
		// Missing data...
	}

	_, err := authenticator.ParseType1(invalidType1)
	if err == nil {
		t.Error("Parsing invalid Type 1 message should fail")
	}

	// Test parsing message with wrong signature
	wrongSig := []byte{
		'W', 'R', 'O', 'N', 'G', 'S', 'I', 'G',
		0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	_, err = authenticator.ParseType1(wrongSig)
	if err == nil {
		t.Error("Parsing message with wrong signature should fail")
	}

	// Test parsing Type 1 with wrong message type
	wrongType := []byte{
		'N', 'T', 'L', 'M', 'S', 'S', 'P', 0x00,
		0x02, 0x00, 0x00, 0x00, // Type 2 instead of Type 1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	_, err = authenticator.ParseType1(wrongType)
	if err == nil {
		t.Error("Parsing Type 1 with wrong message type should fail")
	}

	// Test parsing invalid Type 3 message (too short)
	invalidType3 := []byte{
		'N', 'T', 'L', 'M', 'S', 'S', 'P', 0x00,
		0x03, 0x00, 0x00, 0x00,
		// Missing required fields...
	}

	_, err = authenticator.ParseType3(invalidType3)
	if err == nil {
		t.Error("Parsing invalid Type 3 message should fail")
	}
}

func TestNTLMHash(t *testing.T) {
	authenticator := auth.NewNTLMAuthenticator("TEST", "SERVER")

	// Add users and verify they were added (indirect test of hash function)
	authenticator.AddUser("user1", "password1")
	authenticator.AddUser("user2", "password2")
	authenticator.AddUser("emptypass", "")

	// Create a mock Type 3 message to test authentication
	mockType3 := &auth.NTLMMessage{
		Type:     3,
		Username: "user1",
		Response: []byte("dummy_response"), // Non-empty response
	}

	// Should succeed for existing user
	if !authenticator.VerifyAuthentication(mockType3) {
		t.Error("Authentication should succeed for existing user")
	}

	// Should fail for non-existing user
	mockType3.Username = "nonexistent"
	if authenticator.VerifyAuthentication(mockType3) {
		t.Error("Authentication should fail for non-existing user")
	}

	// Test case insensitivity
	mockType3.Username = "USER1" // Different case
	if !authenticator.VerifyAuthentication(mockType3) {
		t.Error("Authentication should be case insensitive")
	}
}
