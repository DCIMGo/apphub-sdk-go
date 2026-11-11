package apphubsdk

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

const maxLocalArtifactSize = 4 << 20

func readBoundedFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, maxLocalArtifactSize+1))
	if err != nil {
		return nil, fmt.Errorf("read local authorization: %w", err)
	}
	if len(content) > maxLocalArtifactSize {
		return nil, fmt.Errorf("local authorization exceeds size limit")
	}
	return content, nil
}

func atomicWrite(path string, content []byte, mode os.FileMode) error {
	return atomicWriteValidated(path, content, mode, nil)
}

func atomicWriteValidated(path string, content []byte, mode os.FileMode, validate func([]byte) error) error {
	if path == "" {
		return fmt.Errorf("destination path is required")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create authorization directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".apphub-*")
	if err != nil {
		return fmt.Errorf("create temporary authorization: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("protect temporary authorization: %w", err)
	}
	if _, err := temporary.Write(content); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write temporary authorization: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync temporary authorization: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary authorization: %w", err)
	}
	if validate != nil {
		staged, err := readBoundedFile(temporaryPath)
		if err != nil {
			return fmt.Errorf("re-read temporary authorization: %w", err)
		}
		if err := validate(staged); err != nil {
			return fmt.Errorf("verify temporary authorization: %w", err)
		}
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace local authorization: %w", err)
	}
	if runtime.GOOS != "windows" {
		if directoryHandle, err := os.Open(directory); err == nil {
			if syncErr := directoryHandle.Sync(); syncErr != nil && !errors.Is(syncErr, os.ErrInvalid) {
				_ = directoryHandle.Close()
				return fmt.Errorf("sync authorization directory: %w", syncErr)
			}
			_ = directoryHandle.Close()
		}
	}
	return nil
}
