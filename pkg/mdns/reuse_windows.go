//go:build windows

package mdns

import "syscall"

// setReuseAddr enables address reuse on Windows. SO_REUSEADDR there permits
// binding a port already in use, which lets the responder share UDP 5353 with
// any other mDNS listener.
func setReuseAddr(fd uintptr) error {
	return syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
}
