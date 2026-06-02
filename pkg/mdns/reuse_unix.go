//go:build unix

package mdns

import "golang.org/x/sys/unix"

// setReuseAddr enables address/port reuse so the mDNS group port (5353) can be
// bound alongside a system mDNS responder. SO_REUSEPORT is required for that
// sharing on macOS/BSD and also works on Linux; both are applied best-effort.
func setReuseAddr(fd uintptr) error {
	if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		return err
	}
	// Not every kernel exposes SO_REUSEPORT; ignore failures.
	_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	return nil
}
