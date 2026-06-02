//go:build !windows

package shares

import "syscall"

// diskFreeTotal returns the bytes available to an unprivileged caller and the
// total bytes of the filesystem containing path, via statfs(2).
func diskFreeTotal(path string) (free, total uint64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	bsize := uint64(st.Bsize)
	return uint64(st.Bavail) * bsize, uint64(st.Blocks) * bsize, nil
}
