package server

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/3xport/servesmb/pkg/protocol"
	"github.com/3xport/servesmb/pkg/shares"
)

// smb1Frame builds a NetBIOS-framed SMB1 message with the given command byte
// and dialect list (each entry is <0x02><name><NUL>, like real clients).
func smb1Frame(cmd byte, dialects []string) []byte {
	msg := make([]byte, 33)
	copy(msg[0:4], protocol.SMB1_PROTOCOL_ID)
	msg[4] = cmd
	msg[10], msg[11] = 0x18, 0x53
	msg[24], msg[25] = 0xFF, 0xFF
	msg[26], msg[27] = 0xFF, 0xFE

	var list []byte
	for _, d := range dialects {
		list = append(list, 0x02)
		list = append(list, d...)
		list = append(list, 0)
	}
	msg = binary.LittleEndian.AppendUint16(msg, uint16(len(list)))
	msg = append(msg, list...)

	frame := make([]byte, 4, 4+len(msg))
	frame[1] = byte(len(msg) >> 16)
	frame[2] = byte(len(msg) >> 8)
	frame[3] = byte(len(msg))
	return append(frame, msg...)
}

func newTestServer(t *testing.T) *SMBServer {
	t.Helper()
	mgr := shares.NewShareManager(t.TempDir())
	srv, err := NewSMBServer(&Config{
		EnableSMB2: true, EnableSMB3: true,
		Users:        map[string]AuthConfig{"u": {Password: "p"}},
		ShareManager: mgr,
	})
	if err != nil {
		t.Fatalf("NewSMBServer: %v", err)
	}
	return srv
}

// A client that only speaks SMB1 must get an answer, not silence: Windows
// otherwise waits out its own timeout and reports ERROR_BAD_NETPATH.
func TestSMB1OnlyClientIsRefused(t *testing.T) {
	srv := newTestServer(t)

	server, client := net.Pipe()
	defer client.Close()
	errs := make(chan error, 1)
	go func() { errs <- srv.ServeConn(server) }()

	if _, err := client.Write(smb1Frame(protocol.SMB1_COM_NEGOTIATE, []string{"NT LM 0.12", "LANMAN2.1"})); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(client, hdr); err != nil {
		t.Fatalf("no answer to the SMB1 negotiate: %v", err)
	}
	body := make([]byte, int(hdr[1])<<16|int(hdr[2])<<8|int(hdr[3]))
	if _, err := io.ReadFull(client, body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !bytes.HasPrefix(body, []byte(protocol.SMB1_PROTOCOL_ID)) {
		t.Fatalf("answer is not SMB1: %x", body[:4])
	}
	if got := binary.LittleEndian.Uint32(body[5:9]); got != protocol.STATUS_NOT_SUPPORTED {
		t.Fatalf("status = %#08x, want %#08x", got, protocol.STATUS_NOT_SUPPORTED)
	}
	if body[9]&0x80 == 0 {
		t.Errorf("SMB_FLAGS_SERVER_TO_REDIR not set: flags = %#02x", body[9])
	}

	select {
	case err := <-errs:
		if !errors.Is(err, ErrSMB1Disabled) {
			t.Fatalf("ServeConn returned %v, want ErrSMB1Disabled", err)
		}
		var refusal *SMB1DisabledError
		if !errors.As(err, &refusal) {
			t.Fatalf("error %v is not *SMB1DisabledError", err)
		}
		if len(refusal.Dialects) != 2 || refusal.Dialects[0] != "NT LM 0.12" {
			t.Fatalf("dialects = %v", refusal.Dialects)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ServeConn did not return")
	}
}
