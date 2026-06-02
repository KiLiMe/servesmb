package test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/3xport/servesmb/pkg/protocol"
	"github.com/3xport/servesmb/pkg/shares"
)

func TestShareManager(t *testing.T) {
	// Create temporary directory for testing
	tempDir, err := os.MkdirTemp("", "smb_test_shares")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create test directories and files
	publicDir := filepath.Join(tempDir, "public")
	err = os.MkdirAll(publicDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create public directory: %v", err)
	}

	testFile := filepath.Join(publicDir, "test.txt")
	err = os.WriteFile(testFile, []byte("Hello, SMB World!"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Create share manager
	sm := shares.NewShareManager(tempDir)

	// Test adding a share
	share := &protocol.Share{
		Name:        "PUBLIC",
		Path:        "public",
		Comment:     "Test public share",
		ReadOnly:    false,
		GuestAccess: true,
		Hidden:      false,
	}

	err = sm.AddShare(share)
	if err != nil {
		t.Fatalf("Failed to add share: %v", err)
	}

	// Test getting a share
	retrievedShare, err := sm.GetShare("PUBLIC")
	if err != nil {
		t.Fatalf("Failed to get share: %v", err)
	}

	if retrievedShare.Name != "PUBLIC" {
		t.Errorf("Share name mismatch: expected PUBLIC, got %s", retrievedShare.Name)
	}

	// Test case insensitive share lookup
	retrievedShare, err = sm.GetShare("public")
	if err != nil {
		t.Fatalf("Failed to get share with lowercase name: %v", err)
	}

	// Test listing shares
	shareList := sm.ListShares()
	if len(shareList) != 1 {
		t.Errorf("Expected 1 share, got %d", len(shareList))
	}

	// Test getting file info
	fileInfo, err := sm.GetFileInfo("PUBLIC", "test.txt")
	if err != nil {
		t.Fatalf("Failed to get file info: %v", err)
	}

	if fileInfo.Name != "test.txt" {
		t.Errorf("File name mismatch: expected test.txt, got %s", fileInfo.Name)
	}

	if fileInfo.Size != 17 { // "Hello, SMB World!" is 17 bytes
		t.Errorf("File size mismatch: expected 17, got %d", fileInfo.Size)
	}

	// Test directory listing
	files, err := sm.ListDirectory("PUBLIC", "")
	if err != nil {
		t.Fatalf("Failed to list directory: %v", err)
	}

	if len(files) != 1 {
		t.Errorf("Expected 1 file, got %d", len(files))
	}

	if files[0].Name != "test.txt" {
		t.Errorf("File name mismatch: expected test.txt, got %s", files[0].Name)
	}

	// Test reading file
	data, err := sm.ReadFile("PUBLIC", "test.txt", 0, 1024)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}

	expectedContent := "Hello, SMB World!"
	if string(data) != expectedContent {
		t.Errorf("File content mismatch: expected %s, got %s", expectedContent, string(data))
	}

	// Test partial read
	data, err = sm.ReadFile("PUBLIC", "test.txt", 7, 3)
	if err != nil {
		t.Fatalf("Failed to read file partially: %v", err)
	}

	expectedPartial := "SMB"
	if string(data) != expectedPartial {
		t.Errorf("Partial read mismatch: expected %s, got %s", expectedPartial, string(data))
	}

	// Test file exists
	if !sm.FileExists("PUBLIC", "test.txt") {
		t.Error("FileExists should return true for existing file")
	}

	if sm.FileExists("PUBLIC", "nonexistent.txt") {
		t.Error("FileExists should return false for non-existent file")
	}

	// Test writing file (non-readonly share)
	writeData := []byte("New content!")
	written, err := sm.WriteFile("PUBLIC", "newfile.txt", 0, writeData)
	if err != nil {
		t.Fatalf("Failed to write file: %v", err)
	}

	if written != len(writeData) {
		t.Errorf("Write length mismatch: expected %d, got %d", len(writeData), written)
	}

	// Verify written file
	readData, err := sm.ReadFile("PUBLIC", "newfile.txt", 0, 1024)
	if err != nil {
		t.Fatalf("Failed to read written file: %v", err)
	}

	if string(readData) != string(writeData) {
		t.Errorf("Written file content mismatch: expected %s, got %s", string(writeData), string(readData))
	}
}

func TestShareManagerReadOnlyShare(t *testing.T) {
	// Create temporary directory for testing
	tempDir, err := os.MkdirTemp("", "smb_test_readonly")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create test directory
	roDir := filepath.Join(tempDir, "readonly")
	err = os.MkdirAll(roDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create readonly directory: %v", err)
	}

	// Create share manager
	sm := shares.NewShareManager(tempDir)

	// Add readonly share
	share := &protocol.Share{
		Name:        "READONLY",
		Path:        "readonly",
		Comment:     "Read-only test share",
		ReadOnly:    true,
		GuestAccess: true,
		Hidden:      false,
	}

	err = sm.AddShare(share)
	if err != nil {
		t.Fatalf("Failed to add readonly share: %v", err)
	}

	// Test writing to readonly share should fail
	writeData := []byte("Should not work")
	_, err = sm.WriteFile("READONLY", "test.txt", 0, writeData)
	if err == nil {
		t.Error("Writing to readonly share should fail")
	}

	// Test creating directory in readonly share should fail
	err = sm.CreateDirectory("READONLY", "newdir")
	if err == nil {
		t.Error("Creating directory in readonly share should fail")
	}
}

func TestShareManagerSecurity(t *testing.T) {
	// Create temporary directory for testing
	tempDir, err := os.MkdirTemp("", "smb_test_security")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create test directories
	shareDir := filepath.Join(tempDir, "testshare")
	outsideDir := filepath.Join(tempDir, "outside")
	err = os.MkdirAll(shareDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create share directory: %v", err)
	}
	err = os.MkdirAll(outsideDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create outside directory: %v", err)
	}

	// Create share manager
	sm := shares.NewShareManager(tempDir)

	// Add test share
	share := &protocol.Share{
		Name:        "TEST",
		Path:        "testshare",
		Comment:     "Test share for security",
		ReadOnly:    false,
		GuestAccess: true,
		Hidden:      false,
	}

	err = sm.AddShare(share)
	if err != nil {
		t.Fatalf("Failed to add test share: %v", err)
	}

	// Test path traversal attempts should be blocked
	// Using afero.BasePathFs, trying to access files outside the base path should fail
	// or be effectively sandboxed (redirected to within the share or fail).
	// We'll try to read a file that exists outside the share.
	outsideTxT := filepath.Join(outsideDir, "file.txt")
	err = os.WriteFile(outsideTxT, []byte("Outside"), 0644)
	if err != nil {
		t.Fatalf("Failed to create outside file: %v", err)
	}

	_, err = sm.ReadFile("TEST", "../outside/file.txt", 0, 100)
	if err == nil {
		t.Error("Path traversal should fail to read file outside share")
	}

	_, err = sm.GetFileInfo("TEST", "../outside/file.txt")
	if err == nil {
		t.Error("Path traversal should fail to get info for file outside share")
	}

	// Valid relative paths should work
	// Create a file via OS first
	subdir := filepath.Join(shareDir, "subdir")
	os.MkdirAll(subdir, 0755)
	os.WriteFile(filepath.Join(subdir, "file.txt"), []byte("Inside"), 0644)

	data, err := sm.ReadFile("TEST", "subdir/file.txt", 0, 100)
	if err != nil {
		t.Fatalf("Valid relative path should work: %v", err)
	}
	if string(data) != "Inside" {
		t.Errorf("Content mismatch")
	}
}

func TestShareManagerNonExistentShare(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "smb_test_nonexistent")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	sm := shares.NewShareManager(tempDir)

	// Test accessing non-existent share
	_, err = sm.GetShare("NONEXISTENT")
	if err == nil {
		t.Error("Getting non-existent share should fail")
	}

	_, err = sm.GetFileInfo("NONEXISTENT", "test.txt")
	if err == nil {
		t.Error("Getting file info from non-existent share should fail")
	}

	_, err = sm.ListDirectory("NONEXISTENT", "")
	if err == nil {
		t.Error("Listing directory in non-existent share should fail")
	}
}
