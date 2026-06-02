//go:build netbsd

package shares

import "golang.org/x/sys/unix"

// diskFreeTotal returns the bytes available to an unprivileged caller and the
// total bytes of the filesystem containing path, via statvfs(2).
func diskFreeTotal(path string) (free, total uint64, err error) {
	var st unix.Statvfs_t
	if err := unix.Statvfs(path, &st); err != nil {
		return 0, 0, err
	}
	bsize := uint64(st.Frsize)
	if bsize == 0 {
		bsize = uint64(st.Bsize)
	}
	return uint64(st.Bavail) * bsize, uint64(st.Blocks) * bsize, nil
}
