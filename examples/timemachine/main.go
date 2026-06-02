// Command timemachine shows how to run servesmb embedded as a macOS Time
// Machine destination.
//
// The two pieces that make a share a Time Machine target are:
//
//  1. protocol.Share.Type = "timemachine" — turns on the Apple SMB extensions
//     macOS needs (AAPL create context, full-sync volume capability, durable
//     handles + leases, real free-space reporting).
//  2. server.Config.EnableMDNS = true — advertises the destination over
//     mDNS / DNS-SD (Bonjour) so it auto-appears in the macOS Time Machine
//     disk list. For a Time Machine share this publishes _smb._tcp,
//     _device-info._tcp (model=TimeCapsule6) and _adisk._tcp.
//
// Run it (Time Machine uses the standard SMB port, so this needs root/admin):
//
//	sudo go run ./examples/timemachine
//
// Then on macOS: System Settings → Time Machine → Add Backup Disk, or
//
//	sudo tmutil setdestination -a "smb://backup:backuppass@<server-ip>/TIMEMACHINE"
package main

import (
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/3xport/servesmb/pkg/protocol"
	"github.com/3xport/servesmb/pkg/server"
)

func main() {
	// Directory that will hold the backups. Point this at a disk with room for
	// the backup: macOS sizes its sparsebundle against the volume's real free
	// space, which the server reports for this path.
	backupDir, err := filepath.Abs("./tm-backups")
	if err != nil {
		log.Fatalf("resolve backup path: %v", err)
	}
	if err := os.MkdirAll(backupDir, 0o755); err != nil {
		log.Fatalf("create backup dir: %v", err)
	}

	config := &server.Config{
		ListenAddress: "0.0.0.0",
		Port:          445, // macOS Time Machine connects on the standard SMB port
		ServerName:    "GOSMB",
		Domain:        "WORKGROUP",

		// SMB3 is required — macOS negotiates SMB 3.1.1 for Time Machine.
		// Leaving SMB1 on helps whole-Mac protocol negotiation; it is optional.
		EnableSMB1: true,
		EnableSMB2: true,
		EnableSMB3: true,

		// The option that advertises this server (and its Time Machine share)
		// over Bonjour so it shows up automatically on the Mac.
		EnableMDNS: true,

		// Time Machine must authenticate as a real user (not guest).
		Users: map[string]server.AuthConfig{
			"backup": {Password: "backuppass"},
		},
	}

	srv, err := server.NewSMBServer(config)
	if err != nil {
		log.Fatalf("create server: %v", err)
	}

	// Mark the backup share as a Time Machine target. The directory must already
	// exist (created above); AddShare roots an OS filesystem at it.
	if err := srv.AddShare(&protocol.Share{
		Name:        "TIMEMACHINE",
		Path:        backupDir,
		Comment:     "Apple Time Machine target",
		ReadOnly:    false,
		GuestAccess: false, // authenticated access only
		Type:        "timemachine",
	}); err != nil {
		log.Fatalf("add Time Machine share: %v", err)
	}

	// Start in the background so we can shut down cleanly on Ctrl-C. Stopping the
	// server also sends the mDNS goodbye records so the destination disappears
	// from the Mac promptly.
	go func() {
		log.Printf("Time Machine SMB server listening on :%d", config.Port)
		log.Printf("  share TIMEMACHINE -> %s", backupDir)
		log.Printf("  connect from macOS as Registered User backup / backuppass")
		if err := srv.Start(); err != nil {
			log.Fatalf("server error: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	log.Println("shutting down...")
	if err := srv.Stop(); err != nil {
		log.Printf("stop: %v", err)
	}
}
