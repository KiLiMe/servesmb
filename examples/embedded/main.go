package main

import (
	"log"

	"github.com/3xport/servesmb/pkg/protocol"
	"github.com/3xport/servesmb/pkg/server"
	"github.com/3xport/servesmb/pkg/shares"
	"github.com/spf13/afero"
)

func main() {
	// 1. Create ShareManager
	sm := shares.NewShareManager("")

	// 2. Create an in-memory filesystem
	memFs := afero.NewMemMapFs()
	afero.WriteFile(memFs, "welcome.txt", []byte("Welcome to In-Memory SMB!"), 0644)

	// 3. Add a share backed by MemMapFs
	err := sm.AddShareWithFs(&protocol.Share{
		Name:        "MEMSHARE",
		Path:        "/", // Root of the fs
		Comment:     "In-Memory Share",
		ReadOnly:    false,
		GuestAccess: true,
	}, memFs)
	if err != nil {
		log.Fatalf("Failed to add share: %v", err)
	}

	// 4. Configure Server
	config := &server.Config{
		ListenAddress: "0.0.0.0",
		Port:          8446,
		ServerName:    "EMBEDDED",
		ShareManager:  sm, // Use our custom ShareManager
		EnableSMB2:    true,
		EnableSMB3:    false, // Default for simple test
		Users: map[string]server.AuthConfig{
			"test": {Password: "test"},
		},
	}

	// 5. Create and Start Server
	srv, err := server.NewSMBServer(config)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	log.Printf("Starting embedded server on port 8446...")
	if err := srv.Start(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
