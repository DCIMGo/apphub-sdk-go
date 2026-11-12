package apphubsdk

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/gogf/gf/v2/errors/gerror"
)

// maxLocalArtifactSize 限制本地授权文件和租约的读取大小。
const maxLocalArtifactSize = 4 << 20

func readBoundedFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, maxLocalArtifactSize+1))
	if err != nil {
		return nil, gerror.Wrap(err, "read local authorization")
	}
	if len(content) > maxLocalArtifactSize {
		return nil, gerror.New("local authorization exceeds size limit")
	}
	return content, nil
}

func atomicWrite(path string, content []byte, mode os.FileMode) error {
	return atomicWriteValidated(path, content, mode, nil)
}

// atomicWriteValidated 将内容写到同一目录的临时文件，按需复验后再替换目标。
func atomicWriteValidated(path string, content []byte, mode os.FileMode, validate func([]byte) error) error {
	if path == "" {
		return gerror.New("destination path is required")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return gerror.Wrap(err, "create authorization directory")
	}
	temporary, err := os.CreateTemp(directory, ".apphub-*")
	if err != nil {
		return gerror.Wrap(err, "create temporary authorization")
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return gerror.Wrap(err, "protect temporary authorization")
	}
	if _, err := temporary.Write(content); err != nil {
		_ = temporary.Close()
		return gerror.Wrap(err, "write temporary authorization")
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return gerror.Wrap(err, "sync temporary authorization")
	}
	if err := temporary.Close(); err != nil {
		return gerror.Wrap(err, "close temporary authorization")
	}
	if validate != nil {
		staged, err := readBoundedFile(temporaryPath)
		if err != nil {
			return gerror.Wrap(err, "re-read temporary authorization")
		}
		if err := validate(staged); err != nil {
			return gerror.Wrap(err, "verify temporary authorization")
		}
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return gerror.Wrap(err, "replace local authorization")
	}
	if runtime.GOOS != "windows" {
		if directoryHandle, err := os.Open(directory); err == nil {
			if syncErr := directoryHandle.Sync(); syncErr != nil && !errors.Is(syncErr, os.ErrInvalid) {
				_ = directoryHandle.Close()
				return gerror.Wrap(syncErr, "sync authorization directory")
			}
			_ = directoryHandle.Close()
		}
	}
	return nil
}
