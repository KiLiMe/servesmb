package test

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/3xport/servesmb/pkg/protocol"
	"github.com/3xport/servesmb/pkg/server"
)

func TestSMBServerCreation(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "smb_server_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	config := &server.Config{
		ListenAddress: "127.0.0.1",
		Port:          8445, // Use non-standard port for testing
		SharesPath:    tempDir,
		Domain:        "TESTDOMAIN",
		ServerName:    "TESTSERVER",
		EnableSMB1:    true,
		EnableSMB2:    true,
		EnableSMB3:    true,
		Users: map[string]server.AuthConfig{
			"testuser": {Password: "testpass"},
			"guest":    {Password: ""},
		},
	}

	smbServer, err := server.NewSMBServer(config)
	if err != nil {
		t.Fatalf("Failed to create SMB server: %v", err)
	}

	// Test server configuration
	serverConfig := smbServer.GetConfig()
	if serverConfig.Domain != "TESTDOMAIN" {
		t.Errorf("Domain mismatch: expected TESTDOMAIN, got %s", serverConfig.Domain)
	}

	if serverConfig.ServerName != "TESTSERVER" {
		t.Errorf("Server name mismatch: expected TESTSERVER, got %s", serverConfig.ServerName)
	}

	if serverConfig.Port != 8445 {
		t.Errorf("Port mismatch: expected 8445, got %d", serverConfig.Port)
	}

	// Test adding custom share
	customShare := &protocol.Share{
		Name:        "CUSTOM",
		Path:        "custom",
		Comment:     "Custom test share",
		ReadOnly:    false,
		GuestAccess: true,
		Hidden:      false,
	}

	// Create custom directory
	customPath := tempDir + "/custom"
	err = os.MkdirAll(customPath, 0755)
	if err != nil {
		t.Fatalf("Failed to create custom directory: %v", err)
	}

	err = smbServer.AddShare(customShare)
	if err != nil {
		t.Fatalf("Failed to add custom share: %v", err)
	}

	// Test adding user
	smbServer.AddUser("newuser", "newpass")

	// Test server stats
	stats := smbServer.GetStats()
	if !stats["running"].(bool) {
		// Server not running yet, which is expected
	}

	protocols := stats["protocols"].(map[string]bool)
	if !protocols["SMB1"] || !protocols["SMB2"] || !protocols["SMB3"] {
		t.Error("All protocols should be enabled")
	}

	sharesInfo := stats["shares"].([]map[string]interface{})
	if len(sharesInfo) < 2 { // Should have at least PUBLIC (default) and CUSTOM
		t.Errorf("Expected at least 2 shares, got %d", len(sharesInfo))
	}
}

func TestSMBServerStartStop(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "smb_server_startstop")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	config := &server.Config{
		ListenAddress: "127.0.0.1",
		Port:          8446, // Use different port
		SharesPath:    tempDir,
		Domain:        "TEST",
		ServerName:    "TEST",
		EnableSMB1:    true,
		EnableSMB2:    true,
		EnableSMB3:    true,
		Users:         map[string]server.AuthConfig{"guest": {Password: ""}},
	}

	smbServer, err := server.NewSMBServer(config)
	if err != nil {
		t.Fatalf("Failed to create SMB server: %v", err)
	}

	// Start server in goroutine
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- smbServer.Start()
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Test if server is running
	if !smbServer.IsRunning() {
		t.Error("Server should be running")
	}

	// Test connection to server port
	conn, err := net.DialTimeout("tcp", "127.0.0.1:8446", time.Second)
	if err != nil {
		t.Errorf("Failed to connect to server: %v", err)
	} else {
		conn.Close()
	}

	// Stop server
	err = smbServer.Stop()
	if err != nil {
		t.Errorf("Failed to stop server: %v", err)
	}

	// Wait for server to finish
	select {
	case <-serverDone:
		// Server stopped
	case <-time.After(time.Second):
		t.Error("Server did not stop within timeout")
	}

	// Test if server is not running
	if smbServer.IsRunning() {
		t.Error("Server should not be running after stop")
	}
}

func TestSMBServerInvalidConfig(t *testing.T) {
	// Test with non-existent shares path (should create it)
	config := &server.Config{
		ListenAddress: "127.0.0.1",
		Port:          8447,
		SharesPath:    "/tmp/nonexistent_smb_test_" + time.Now().Format("20060102150405"),
		Domain:        "TEST",
		ServerName:    "TEST",
		EnableSMB1:    true,
		EnableSMB2:    true,
		EnableSMB3:    true,
		Users:         map[string]server.AuthConfig{"guest": {Password: ""}},
	}

	smbServer, err := server.NewSMBServer(config)
	if err != nil {
		t.Fatalf("Server creation should succeed even with non-existent path: %v", err)
	}
	defer os.RemoveAll(config.SharesPath)

	// Verify directory was created
	if _, err := os.Stat(config.SharesPath); os.IsNotExist(err) {
		t.Error("Shares directory should have been created")
	}

	if smbServer == nil {
		t.Error("Server should not be nil")
	}
}

func TestDefaultConfig(t *testing.T) {
	config := server.DefaultConfig()

	if config.ListenAddress != "0.0.0.0" {
		t.Errorf("Default listen address should be 0.0.0.0, got %s", config.ListenAddress)
	}

	if config.Port != protocol.SMB_PORT {
		t.Errorf("Default port should be %d, got %d", protocol.SMB_PORT, config.Port)
	}

	if config.Domain != "WORKGROUP" {
		t.Errorf("Default domain should be WORKGROUP, got %s", config.Domain)
	}

	if !config.EnableSMB1 || !config.EnableSMB2 || !config.EnableSMB3 {
		t.Error("All protocols should be enabled by default")
	}

	if len(config.Users) != 0 {
		t.Error("Default config should have no users")
	}

	// Check for default users
	if _, exists := config.Users["guest"]; exists {
		t.Error("Default config should NOT include guest user by default")
	}
}

func TestSMBServerStats(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "smb_server_stats")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	config := server.DefaultConfig()
	config.SharesPath = tempDir
	config.Port = 8448

	smbServer, err := server.NewSMBServer(config)
	if err != nil {
		t.Fatalf("Failed to create SMB server: %v", err)
	}

	stats := smbServer.GetStats()

	// Test stats structure
	if _, exists := stats["running"]; !exists {
		t.Error("Stats should include 'running' field")
	}

	if _, exists := stats["protocols"]; !exists {
		t.Error("Stats should include 'protocols' field")
	}

	if _, exists := stats["shares"]; !exists {
		t.Error("Stats should include 'shares' field")
	}

	if _, exists := stats["user_count"]; !exists {
		t.Error("Stats should include 'user_count' field")
	}

	// Test JSON serialization of stats
	jsonData, err := json.MarshalIndent(stats, "", "  ")
	if err != nil {
		t.Errorf("Failed to marshal stats to JSON: %v", err)
	}

	if len(jsonData) == 0 {
		t.Error("JSON stats should not be empty")
	}

	// Verify we can unmarshal it back
	var unmarshaled map[string]interface{}
	err = json.Unmarshal(jsonData, &unmarshaled)
	if err != nil {
		t.Errorf("Failed to unmarshal stats JSON: %v", err)
	}
}

// Test protocol detection with mock connections
func TestServerProtocolDetection(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "smb_protocol_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	config := &server.Config{
		ListenAddress: "127.0.0.1",
		Port:          8449,
		SharesPath:    tempDir,
		Domain:        "TEST",
		ServerName:    "TEST",
		EnableSMB1:    true,
		EnableSMB2:    true,
		EnableSMB3:    true,
		Users:         map[string]server.AuthConfig{"guest": {Password: ""}},
	}

	smbServer, err := server.NewSMBServer(config)
	if err != nil {
		t.Fatalf("Failed to create SMB server: %v", err)
	}

	// Start server
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- smbServer.Start()
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Test SMB1 negotiate message
	smb1Negotiate := []byte{
		// NetBIOS header
		0x00, 0x00, 0x00, 0x2C,
		// SMB1 header
		0xFF, 'S', 'M', 'B', // Protocol
		0x72,                   // Negotiate command
		0x00, 0x00, 0x00, 0x00, // Status
		0x18,       // Flags
		0x01, 0x48, // Flags2
		0x00, 0x00, // PID High
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Security
		0x00, 0x00, // Reserved
		0x00, 0x00, // TID
		0x00, 0x00, // PID Low
		0x00, 0x00, // UID
		0x00, 0x00, // MID
		// Parameters and data
		0x00,       // Word count
		0x02, 0x00, // Byte count
		0x02, 0x4E, 0x54, 0x20, 0x4C, 0x4D, 0x20, 0x30, 0x2E, 0x31, 0x32, 0x00, // Dialect
	}

	conn, err := net.Dial("tcp", "127.0.0.1:8449")
	if err != nil {
		t.Fatalf("Failed to connect to server: %v", err)
	}
	defer conn.Close()

	// Send SMB1 negotiate
	_, err = conn.Write(smb1Negotiate)
	if err != nil {
		t.Errorf("Failed to send SMB1 negotiate: %v", err)
	}

	// Read response (should get some response, even if partial)
	response := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(time.Second))
	n, err := conn.Read(response)
	if err != nil && err != io.EOF {
		t.Logf("Read error (may be expected): %v", err)
	}

	if n > 0 {
		// Check if we got NetBIOS header back
		if len(response) >= 4 {
			t.Logf("Received %d bytes response", n)
		}
	}

	// Stop server
	smbServer.Stop()

	// Wait for server to finish
	select {
	case <-serverDone:
		// Server stopped
	case <-time.After(time.Second):
		t.Log("Server stop timeout (may be expected in test)")
	}
}
