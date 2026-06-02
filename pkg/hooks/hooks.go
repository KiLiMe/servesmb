package hooks

// ConnInfo contains information about the client connection and session
type ConnInfo struct {
	ClientIP   string
	ClientPort int
	LocalIP    string
	ServerPort int
	SessionID  uint64
	Dialect    uint16 // Negotiated dialect for this connection
}

// EventHooks defines the interface for handling server events
type EventHooks interface {
	// OnLoginSuccess is called when a user successfully authenticates
	OnLoginSuccess(conn ConnInfo, username, domain, workstation string)

	// OnLoginFailure is called when authentication fails
	OnLoginFailure(conn ConnInfo, username, domain, workstation string, err error)

	// OnFileUpload is called when a file is successfully written (uploaded)
	OnFileUpload(conn ConnInfo, share, path string, size int64)

	// OnFileDownload is called when a file is successfully read (downloaded)
	OnFileDownload(conn ConnInfo, share, path string, size int64)

	// OnFileDelete is called when a file is deleted
	OnFileDelete(conn ConnInfo, share, path string)

	// OnFileCreate is called when a file is created
	OnFileCreate(conn ConnInfo, share, path string)

	// OnFileOverwrite is called when a file is overwritten/truncated
	OnFileOverwrite(conn ConnInfo, share, path string)

	// OnFolderCreate is called when a directory is created
	OnFolderCreate(conn ConnInfo, share, path string)

	// OnFolderDelete is called when a directory is deleted
	OnFolderDelete(conn ConnInfo, share, path string)
}

// NoOpEventHooks is a default implementation that does nothing
type NoOpEventHooks struct{}

func (h *NoOpEventHooks) OnLoginSuccess(conn ConnInfo, username, domain, workstation string) {}
func (h *NoOpEventHooks) OnLoginFailure(conn ConnInfo, username, domain, workstation string, err error) {
}
func (h *NoOpEventHooks) OnFileUpload(conn ConnInfo, share, path string, size int64)   {}
func (h *NoOpEventHooks) OnFileDownload(conn ConnInfo, share, path string, size int64) {}
func (h *NoOpEventHooks) OnFileDelete(conn ConnInfo, share, path string)               {}
func (h *NoOpEventHooks) OnFileCreate(conn ConnInfo, share, path string)               {}
func (h *NoOpEventHooks) OnFileOverwrite(conn ConnInfo, share, path string)            {}
func (h *NoOpEventHooks) OnFolderCreate(conn ConnInfo, share, path string)             {}
func (h *NoOpEventHooks) OnFolderDelete(conn ConnInfo, share, path string)             {}
