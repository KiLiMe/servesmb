//go:build !unix && !windows

package mdns

// setReuseAddr is a no-op on platforms that do not expose the reuse socket
// options through a supported API. Binding simply proceeds without them.
func setReuseAddr(fd uintptr) error {
	return nil
}
