package shares

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/3xport/servesmb/pkg/protocol"
	"github.com/spf13/afero"
)

type ShareManager struct {
	shares      map[string]*protocol.Share
	filesystems map[string]afero.Fs
	basePath    string
}

func NewShareManager(basePath string) *ShareManager {
	return &ShareManager{
		shares:      make(map[string]*protocol.Share),
		filesystems: make(map[string]afero.Fs),
		basePath:    basePath,
	}
}

func (sm *ShareManager) AddShare(share *protocol.Share) error {
	// Default to OS filesystem grounded at basePath
	// For OS shares, the share.Path is relative to sm.basePath
	fullPath := filepath.Join(sm.basePath, share.Path)
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		return fmt.Errorf("share path does not exist: %s", fullPath)
	}

	// Create a BasePathFs to restrict access to the share directory
	fs := afero.NewBasePathFs(afero.NewOsFs(), fullPath)
	return sm.AddShareWithFs(share, fs)
}

func (sm *ShareManager) AddShareWithFs(share *protocol.Share, fs afero.Fs) error {
	name := strings.ToUpper(share.Name)
	sm.shares[name] = share
	sm.filesystems[name] = fs
	return nil
}

func (sm *ShareManager) GetShare(name string) (*protocol.Share, error) {
	share, exists := sm.shares[strings.ToUpper(name)]
	if !exists {
		return nil, fmt.Errorf("share not found: %s", name)
	}
	return share, nil
}

func (sm *ShareManager) ListShares() []*protocol.Share {
	shares := make([]*protocol.Share, 0, len(sm.shares))
	for _, share := range sm.shares {
		shares = append(shares, share)
	}
	return shares
}

// DiskFree reports the real free (available to the caller) and total bytes of
// the volume backing the named share, computed from the same path AddShare
// grounds the share's filesystem on. ok is false when it can't be determined
// (e.g. the IPC$ in-memory share), so callers can fall back to a default.
func (sm *ShareManager) DiskFree(shareName string) (free, total uint64, ok bool) {
	share, err := sm.GetShare(shareName)
	if err != nil || share == nil {
		return 0, 0, false
	}
	fullPath := filepath.Join(sm.basePath, share.Path)
	free, total, err = diskFreeTotal(fullPath)
	if err != nil || total == 0 {
		return 0, 0, false
	}
	return free, total, true
}

// getFsAndPath retrieves the filesystem and the relative path for a given share and path.
// The path is cleaned and ensured to be valid for the filesystem.
func (sm *ShareManager) getFsAndPath(shareName, path string) (afero.Fs, string, error) {
	name := strings.ToUpper(shareName)
	fs, ok := sm.filesystems[name]
	if !ok {
		return nil, "", fmt.Errorf("share not found: %s", shareName)
	}

	// Clean the path
	// In the protocol, paths are often backslashes. Replace with forward slash for afero?
	// afero (and Go) usually handles forward slashes well. Windows might need care.
	// But since we are using BasePathFs, we should treat paths as relative to the root of that Fs.
	cleanPath := filepath.Clean(path)

	// Remove leading volume or slash if present to make it relative
	// e.g. \folder\file -> folder/file
	cleanPath = strings.TrimPrefix(cleanPath, "\\")
	cleanPath = strings.TrimPrefix(cleanPath, "/")
	cleanPath = strings.ReplaceAll(cleanPath, "\\", "/")

	if cleanPath == "" || cleanPath == "." {
		cleanPath = "."
	}

	return fs, cleanPath, nil
}

func (sm *ShareManager) GetFileInfo(shareName, path string) (*protocol.FileInfo, error) {
	fs, cleanPath, err := sm.getFsAndPath(shareName, path)
	if err != nil {
		return nil, err
	}

	stat, err := fs.Stat(cleanPath)
	if err != nil {
		return nil, err
	}

	fileInfo := &protocol.FileInfo{
		Name:         stat.Name(),
		Size:         stat.Size(),
		ModifiedTime: stat.ModTime(),
		AccessedTime: stat.ModTime(), // Use modtime as fallback
		CreatedTime:  stat.ModTime(), // Use modtime as fallback
		IsDirectory:  stat.IsDir(),
	}

	// Set basic attributes
	if stat.IsDir() {
		fileInfo.Attributes = protocol.FILE_ATTRIBUTE_DIRECTORY
	} else {
		fileInfo.Attributes = protocol.FILE_ATTRIBUTE_NORMAL
	}

	// Add read-only attribute if file is not writable
	// afero.FileInfo Mode() returns os.FileMode
	if stat.Mode()&0200 == 0 {
		fileInfo.Attributes |= protocol.FILE_ATTRIBUTE_READONLY
	}

	return fileInfo, nil
}

func (sm *ShareManager) ListDirectory(shareName, path string) ([]*protocol.FileInfo, error) {
	fs, cleanPath, err := sm.getFsAndPath(shareName, path)
	if err != nil {
		return nil, err
	}

	// afero.Fs doesn't have ReadDir directly (except Afero struct).
	// We need to Open and then Readdir or use afero.ReadDir
	entries, err := afero.ReadDir(fs, cleanPath)
	if err != nil {
		return nil, err
	}

	var files []*protocol.FileInfo
	for _, info := range entries {
		fileInfo := &protocol.FileInfo{
			Name:         info.Name(),
			Size:         info.Size(),
			ModifiedTime: info.ModTime(),
			AccessedTime: info.ModTime(),
			CreatedTime:  info.ModTime(),
			IsDirectory:  info.IsDir(),
		}

		if info.IsDir() {
			fileInfo.Attributes = protocol.FILE_ATTRIBUTE_DIRECTORY
		} else {
			fileInfo.Attributes = protocol.FILE_ATTRIBUTE_NORMAL
		}

		if info.Mode()&0200 == 0 {
			fileInfo.Attributes |= protocol.FILE_ATTRIBUTE_READONLY
		}

		files = append(files, fileInfo)
	}

	return files, nil
}

func (sm *ShareManager) ReadFile(shareName, path string, offset int64, length int) ([]byte, error) {
	fs, cleanPath, err := sm.getFsAndPath(shareName, path)
	if err != nil {
		return nil, err
	}

	file, err := fs.Open(cleanPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	if offset > 0 {
		_, err = file.Seek(offset, 0)
		if err != nil {
			return nil, err
		}
	}

	buffer := make([]byte, length)
	n, err := file.Read(buffer)
	// io.EOF is expected if we read past end, but formatted error might differ
	if err != nil && err.Error() != "EOF" {
		return nil, err
	}

	return buffer[:n], nil
}

func (sm *ShareManager) WriteFile(shareName, path string, offset int64, data []byte) (int, error) {
	share, err := sm.GetShare(shareName)
	if err != nil {
		return 0, err
	}

	if share.ReadOnly {
		return 0, fmt.Errorf("share is read-only")
	}

	fs, cleanPath, err := sm.getFsAndPath(shareName, path)
	if err != nil {
		return 0, err
	}

	file, err := fs.OpenFile(cleanPath, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	if offset > 0 {
		_, err = file.Seek(offset, 0)
		if err != nil {
			return 0, err
		}
	}

	return file.Write(data)
}

func (sm *ShareManager) CreateDirectory(shareName, path string) error {
	share, err := sm.GetShare(shareName)
	if err != nil {
		return err
	}

	if share.ReadOnly {
		return fmt.Errorf("share is read-only")
	}

	fs, cleanPath, err := sm.getFsAndPath(shareName, path)
	if err != nil {
		return err
	}

	return fs.MkdirAll(cleanPath, 0755)
}

func (sm *ShareManager) DeleteFile(shareName, path string) error {
	share, err := sm.GetShare(shareName)
	if err != nil {
		return err
	}

	if share.ReadOnly {
		return fmt.Errorf("share is read-only")
	}

	fs, cleanPath, err := sm.getFsAndPath(shareName, path)
	if err != nil {
		return err
	}

	return fs.Remove(cleanPath)
}

func (sm *ShareManager) TruncateFile(shareName, path string, size int64) error {
	share, err := sm.GetShare(shareName)
	if err != nil {
		return err
	}

	if share.ReadOnly {
		return fmt.Errorf("share is read-only")
	}

	fs, cleanPath, err := sm.getFsAndPath(shareName, path)
	if err != nil {
		return err
	}

	// afero.Fs does not always have Truncate?
	// afero.Fs interface doesn't have Truncate. We have to Open and Truncate if supported, or use Fs-specific?
	// Wait, afero.Fs interface has: Create, Mkdir, MkdirAll, Open, OpenFile, Remove, RemoveAll, Rename, Stat, Name, Chmod, Chtimes
	// It does NOT have Truncate.
	// But `os.File` has Truncate. So we OpenFile and call Truncate on the file object?
	// Or we use `afero.Fs` cast to something that supports it?
	// Usually Truncate is on the file handle.
	file, err := fs.OpenFile(cleanPath, os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	return file.Truncate(size)
}

func (sm *ShareManager) DeleteDirectory(shareName, path string) error {
	share, err := sm.GetShare(shareName)
	if err != nil {
		return err
	}

	if share.ReadOnly {
		return fmt.Errorf("share is read-only")
	}

	fs, cleanPath, err := sm.getFsAndPath(shareName, path)
	if err != nil {
		return err
	}

	return fs.Remove(cleanPath)
}

func (sm *ShareManager) Rename(shareName, oldPath, newPath string) error {
	share, err := sm.GetShare(shareName)
	if err != nil {
		return err
	}

	if share.ReadOnly {
		return fmt.Errorf("share is read-only")
	}

	fs, cleanOldPath, err := sm.getFsAndPath(shareName, oldPath)
	if err != nil {
		return err
	}

	_, cleanNewPath, err := sm.getFsAndPath(shareName, newPath)
	if err != nil {
		return err
	}

	return fs.Rename(cleanOldPath, cleanNewPath)
}

func (sm *ShareManager) FileExists(shareName, path string) bool {
	fs, cleanPath, err := sm.getFsAndPath(shareName, path)
	if err != nil {
		return false
	}

	_, err = fs.Stat(cleanPath)
	return err == nil
}

// Default shares for testing
func (sm *ShareManager) AddDefaultShares() error {
	// Add IPC$ share for administrative functions
	ipcShare := &protocol.Share{
		Name:        "IPC$",
		Path:        "",
		Comment:     "Remote IPC",
		ReadOnly:    true,
		GuestAccess: true,
		Hidden:      true,
	}

	// Add IPC$ share without path validation (special case)
	// We also register a MemMapFs for it, though it likely won't be used for file access
	sm.shares[strings.ToUpper(ipcShare.Name)] = ipcShare
	sm.filesystems[strings.ToUpper(ipcShare.Name)] = afero.NewMemMapFs()

	return nil
}
