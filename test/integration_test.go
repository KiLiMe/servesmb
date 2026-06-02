package test

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/3xport/servesmb/pkg/server"
)

// Integration test for full SMB server functionality
func TestSMBServerIntegration(t *testing.T) {
	// Skip if running in short mode
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tempDir, err := os.MkdirTemp("", "smb_integration_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create test files and directories
	setupTestFiles(t, tempDir)

	config := &server.Config{
		ListenAddress: "127.0.0.1",
		Port:          8450,
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

	// Start server
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- smbServer.Start()
	}()

	// Give server time to start
	time.Sleep(200 * time.Millisecond)

	// Test multiple concurrent connections
	t.Run("ConcurrentConnections", func(t *testing.T) {
		testConcurrentConnections(t, "127.0.0.1:8450")
	})

	// Test SMB1 protocol flow
	t.Run("SMB1Protocol", func(t *testing.T) {
		testSMB1ProtocolFlow(t, "127.0.0.1:8450")
	})

	// Test SMB2 protocol flow
	t.Run("SMB2Protocol", func(t *testing.T) {
		testSMB2ProtocolFlow(t, "127.0.0.1:8450")
	})

	// Stop server
	err = smbServer.Stop()
	if err != nil {
		t.Errorf("Failed to stop server: %v", err)
	}

	// Wait for server to finish
	select {
	case <-serverDone:
		// Server stopped
	case <-time.After(2 * time.Second):
		t.Log("Server stop timeout")
	}
}

func setupTestFiles(t *testing.T, baseDir string) {
	// Create public directory with test files
	publicDir := filepath.Join(baseDir, "public")
	err := os.MkdirAll(publicDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create public directory: %v", err)
	}

	// Create test files
	files := map[string]string{
		"small.txt":  "This is a small test file.",
		"medium.txt": "This is a medium test file with more content to test reading capabilities.",
		"large.txt":  generateLargeContent(1024), // 1KB file
	}

	for filename, content := range files {
		filePath := filepath.Join(publicDir, filename)
		err = os.WriteFile(filePath, []byte(content), 0644)
		if err != nil {
			t.Fatalf("Failed to create test file %s: %v", filename, err)
		}
	}

	// Create subdirectory
	subDir := filepath.Join(publicDir, "subdir")
	err = os.MkdirAll(subDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create subdirectory: %v", err)
	}

	// Add file in subdirectory
	subFile := filepath.Join(subDir, "subfile.txt")
	err = os.WriteFile(subFile, []byte("File in subdirectory"), 0644)
	if err != nil {
		t.Fatalf("Failed to create file in subdirectory: %v", err)
	}
}

func generateLargeContent(size int) string {
	var buf bytes.Buffer
	for buf.Len() < size {
		buf.WriteString("This is a test line to generate content. ")
	}
	return buf.String()[:size]
}

func testConcurrentConnections(t *testing.T, address string) {
	const numConnections = 5
	results := make(chan error, numConnections)

	// Start multiple concurrent connections
	for i := 0; i < numConnections; i++ {
		go func(id int) {
			conn, err := net.DialTimeout("tcp", address, time.Second)
			if err != nil {
				results <- err
				return
			}
			defer conn.Close()

			// Send a simple packet and see if connection is accepted
			testPacket := []byte{
				0x00, 0x00, 0x00, 0x04, // NetBIOS header
				0xFF, 'S', 'M', 'B', // SMB1 signature
			}

			_, err = conn.Write(testPacket)
			results <- err
		}(i)
	}

	// Collect results
	successCount := 0
	for i := 0; i < numConnections; i++ {
		err := <-results
		if err == nil {
			successCount++
		} else {
			t.Logf("Connection %d failed: %v", i, err)
		}
	}

	// At least some connections should succeed
	if successCount == 0 {
		t.Error("No concurrent connections succeeded")
	}

	t.Logf("Concurrent connections: %d/%d successful", successCount, numConnections)
}

func testSMB1ProtocolFlow(t *testing.T, address string) {
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// Set timeouts
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))

	// Send SMB1 Negotiate
	negotiate := createSMB1Negotiate()
	_, err = conn.Write(negotiate)
	if err != nil {
		t.Fatalf("Failed to send negotiate: %v", err)
	}

	// Read response
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		t.Errorf("Failed to read negotiate response: %v", err)
		return
	}

	if n < 4 {
		t.Errorf("Response too short: %d bytes", n)
		return
	}

	// Check NetBIOS header
	responseLen := int(response[1])<<16 | int(response[2])<<8 | int(response[3])
	if responseLen == 0 {
		t.Error("Invalid NetBIOS response length")
		return
	}

	// Check SMB signature in response
	if n >= 8 {
		if !bytes.Equal(response[4:8], []byte{0xFF, 'S', 'M', 'B'}) {
			t.Error("Invalid SMB1 signature in response")
		} else {
			t.Log("SMB1 negotiate successful")
		}
	}
}

func testSMB2ProtocolFlow(t *testing.T, address string) {
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// Set timeouts
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))

	// Send SMB2 Negotiate
	negotiate := createSMB2Negotiate()
	_, err = conn.Write(negotiate)
	if err != nil {
		t.Fatalf("Failed to send SMB2 negotiate: %v", err)
	}

	// Read response
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		t.Errorf("Failed to read SMB2 negotiate response: %v", err)
		return
	}

	if n < 4 {
		t.Errorf("SMB2 response too short: %d bytes", n)
		return
	}

	// Check NetBIOS header
	responseLen := int(response[1])<<16 | int(response[2])<<8 | int(response[3])
	if responseLen == 0 {
		t.Error("Invalid NetBIOS response length")
		return
	}

	// Check SMB2 signature in response
	if n >= 8 {
		if !bytes.Equal(response[4:8], []byte{0xFE, 'S', 'M', 'B'}) {
			t.Error("Invalid SMB2 signature in response")
		} else {
			t.Log("SMB2 negotiate successful")
		}
	}
}

func createSMB1Negotiate() []byte {
	// Create a basic SMB1 negotiate request
	negotiate := []byte{
		// NetBIOS session request header
		0x00, 0x00, 0x00, 0x52, // Length = 82 bytes (32 header + 1 wordcount + 2 bytecount + 47 dialects)

		// SMB Header (32 bytes)
		0xFF, 'S', 'M', 'B', // Protocol
		0x72,                   // Command: SMB_COM_NEGOTIATE
		0x00, 0x00, 0x00, 0x00, // Status
		0x18,       // Flags
		0x01, 0x20, // Flags2
		0x00, 0x00, // PID High
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Security signature
		0x00, 0x00, // Reserved
		0x00, 0x00, // TID
		0x00, 0x00, // PID Low
		0x00, 0x00, // UID
		0x00, 0x00, // MID

		// Parameters (1 byte)
		0x00, // Word count

		// Data section
		0x2F, 0x00, // Byte count (47 bytes of dialect strings)

		// Dialect strings
		0x02, 'P', 'C', ' ', 'N', 'E', 'T', 'W', 'O', 'R', 'K', ' ', 'P', 'R', 'O', 'G', 'R', 'A', 'M', ' ', '1', '.', '0', 0x00,
		0x02, 'L', 'A', 'N', 'M', 'A', 'N', '1', '.', '0', 0x00,
		0x02, 'N', 'T', ' ', 'L', 'M', ' ', '0', '.', '1', '2', 0x00,
	}

	return negotiate
}

func createSMB2Negotiate() []byte {
	// Create a basic SMB2 negotiate request
	negotiate := []byte{
		// NetBIOS session request header
		0x00, 0x00, 0x00, 0x48, // Length = 72 bytes

		// SMB2 Header (64 bytes)
		0xFE, 'S', 'M', 'B', // Protocol ID
		0x40, 0x00, // Structure Size (64)
		0x00, 0x00, // Credit Charge
		0x00, 0x00, 0x00, 0x00, // Status
		0x00, 0x00, // Command: NEGOTIATE
		0x01, 0x00, // Credit Request
		0x00, 0x00, 0x00, 0x00, // Flags
		0x00, 0x00, 0x00, 0x00, // Next Command
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Message ID
		0x00, 0x00, 0x00, 0x00, // Process ID
		0x00, 0x00, 0x00, 0x00, // Tree ID
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Session ID
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature (part 1)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature (part 2)

		// Negotiate request body (8 bytes)
		0x24, 0x00, // Structure Size (36)
		0x01, 0x00, // Dialect Count
		0x00, 0x00, // Security Mode
		0x00, 0x00, // Reserved
		0x00, 0x00, 0x00, 0x00, // Capabilities
		// Client GUID (16 bytes)
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
		// Negotiate Context Offset and Count
		0x00, 0x00, 0x00, 0x00, // Context Offset
		0x00, 0x00, // Context Count
		0x00, 0x00, // Reserved

		// Dialects
		0x02, 0x02, // SMB 2.002
	}

	return negotiate
}

// Benchmark tests for performance measurement
func BenchmarkSMBServerConnection(b *testing.B) {
	tempDir, err := os.MkdirTemp("", "smb_benchmark")
	if err != nil {
		b.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	config := &server.Config{
		ListenAddress: "127.0.0.1",
		Port:          8451,
		SharesPath:    tempDir,
		Domain:        "BENCH",
		ServerName:    "BENCH",
		EnableSMB1:    true,
		EnableSMB2:    true,
		EnableSMB3:    true,
		Users:         map[string]server.AuthConfig{"guest": {Password: ""}},
	}

	smbServer, err := server.NewSMBServer(config)
	if err != nil {
		b.Fatalf("Failed to create SMB server: %v", err)
	}

	// Start server
	go smbServer.Start()
	time.Sleep(100 * time.Millisecond)

	b.ResetTimer()

	// Benchmark connection establishment
	for i := 0; i < b.N; i++ {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:8451", time.Second)
		if err != nil {
			b.Fatalf("Failed to connect: %v", err)
		}
		conn.Close()
	}

	smbServer.Stop()
}
