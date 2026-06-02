package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/3xport/servesmb/pkg/hooks"
	"github.com/3xport/servesmb/pkg/server"
)

// AuditHooks implements hooks.EventHooks to log events
type AuditHooks struct{}

func (h *AuditHooks) OnLoginSuccess(conn hooks.ConnInfo, username, domain, workstation string) {
	log.Printf("[AUDIT] LOGIN SUCCESS | SessionID: %d | Client: %s:%d | User: %s | Domain: %s | Workstation: %s",
		conn.SessionID, conn.ClientIP, conn.ClientPort, username, domain, workstation)
}

func (h *AuditHooks) OnLoginFailure(conn hooks.ConnInfo, username, domain, workstation string, err error) {
	log.Printf("[AUDIT] LOGIN FAILURE | SessionID: %d | Client: %s:%d | User: %s | Domain: %s | Workstation: %s | Error: %v",
		conn.SessionID, conn.ClientIP, conn.ClientPort, username, domain, workstation, err)
}

func (h *AuditHooks) OnFileUpload(conn hooks.ConnInfo, share, path string, size int64) {
	log.Printf("[AUDIT] UPLOAD | SessionID: %d | Share: %s | Path: %s | Size: %d bytes",
		conn.SessionID, share, path, size)
}

func (h *AuditHooks) OnFileDownload(conn hooks.ConnInfo, share, path string, size int64) {
	log.Printf("[AUDIT] DOWNLOAD | SessionID: %d | Share: %s | Path: %s | Size: %d bytes",
		conn.SessionID, share, path, size)
}

func (h *AuditHooks) OnFileDelete(conn hooks.ConnInfo, share, path string) {
	log.Printf("[AUDIT] DELETE FILE | SessionID: %d | Share: %s | Path: %s",
		conn.SessionID, share, path)
}

func (h *AuditHooks) OnFileCreate(conn hooks.ConnInfo, share, path string) {
	log.Printf("[AUDIT] CREATE FILE | SessionID: %d | Share: %s | Path: %s",
		conn.SessionID, share, path)
}

func (h *AuditHooks) OnFileOverwrite(conn hooks.ConnInfo, share, path string) {
	log.Printf("[AUDIT] OVERWRITE FILE | SessionID: %d | Share: %s | Path: %s",
		conn.SessionID, share, path)
}

func (h *AuditHooks) OnFolderCreate(conn hooks.ConnInfo, share, path string) {
	log.Printf("[AUDIT] CREATE FOLDER | SessionID: %d | Share: %s | Path: %s",
		conn.SessionID, share, path)
}

func (h *AuditHooks) OnFolderDelete(conn hooks.ConnInfo, share, path string) {
	log.Printf("[AUDIT] DELETE FOLDER | SessionID: %d | Share: %s | Path: %s",
		conn.SessionID, share, path)
}

func main() {
	// Create a temporary directory for shares
	sharesDir := "./audit_shares"
	os.MkdirAll(sharesDir, 0755)

	conf := server.DefaultConfig()
	conf.SharesPath = sharesDir
	conf.Port = 4455        // Use non-privileged port for testing
	conf.EnableSMB1 = false // SMB1 is less interesting for this test
	conf.Debug = 1

	// Enable Audit Hooks
	conf.Hooks = &AuditHooks{}

	// Create test user
	conf.Users["testuser"] = server.AuthConfig{
		Password: "password123",
	}

	srv, err := server.NewSMBServer(conf)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	go func() {
		log.Printf("Starting Audit Logging SMB Server on :%d", conf.Port)
		if err := srv.Start(); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Wait for interrupt
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	log.Println("Shutting down...")
	srv.Stop()
	time.Sleep(1 * time.Second)
}
