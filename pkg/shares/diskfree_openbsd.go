//go:build openbsd

package shares

import "syscall"

// diskFreeTotal returns the bytes available to an unprivileged caller and the
// total bytes of the filesystem containing path, via statfs(2).
func diskFreeTotal(path string) (free, total uint64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	bsize := uint64(st.F_bsize)
	return uint64(st.F_bavail) * bsize, uint64(st.F_blocks) * bsize, nil
}
