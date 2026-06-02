package smb3

import (
	"github.com/3xport/servesmb/pkg/auth"
	"github.com/3xport/servesmb/pkg/hooks"
	"github.com/3xport/servesmb/pkg/shares"
	"github.com/3xport/servesmb/pkg/smb2"
)

// SMB3Handler extends SMB2Handler with SMB3-specific features
type SMB3Handler struct {
	*smb2.SMB2Handler
	encryptionEnabled bool
	signingRequired   bool
}

func NewSMB3Handler(shareManager *shares.ShareManager, authenticator *auth.NTLMAuthenticator, debug int, enableMIC bool, eventHooks hooks.EventHooks) *SMB3Handler {
	return &SMB3Handler{
		SMB2Handler:       smb2.NewSMB2Handler(shareManager, authenticator, true, debug, enableMIC, eventHooks),
		encryptionEnabled: true,
		signingRequired:   true,
	}
}

func (h *SMB3Handler) GetVersion() string {
	return "SMB3"
}

func (h *SMB3Handler) GetDialects() []string {
	return []string{
		"SMB 3.0",
		"SMB 3.0.2",
		"SMB 3.1.1",
	}
}

func (h *SMB3Handler) IsEncryptionEnabled() bool {
	return h.encryptionEnabled
}

func (h *SMB3Handler) IsSigningRequired() bool {
	return h.signingRequired
}

func (h *SMB3Handler) SetEncryption(enabled bool) {
	h.encryptionEnabled = enabled
}

func (h *SMB3Handler) SetSigningRequired(required bool) {
	h.signingRequired = required
}
