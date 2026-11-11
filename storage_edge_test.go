package apphubsdk

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAtomicWriteValidatedReplacesOnlyAfterValidation(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "authorization.dat")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("validation rejected")
	err := atomicWriteValidated(path, []byte("new"), 0o600, func(staged []byte) error {
		if string(staged) != "new" {
			t.Fatalf("validator received %q", staged)
		}
		return wantErr
	})
	if err == nil || !strings.Contains(err.Error(), "verify temporary authorization") {
		t.Fatalf("validation error not returned: %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "old" {
		t.Fatalf("failed validation replaced destination: %q", content)
	}
	temporary, err := filepath.Glob(filepath.Join(directory, ".apphub-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(temporary) != 0 {
		t.Fatalf("temporary files leaked: %v", temporary)
	}

	if err := atomicWriteValidated(path, []byte("new"), 0o600, func([]byte) error { return nil }); err != nil {
		t.Fatal(err)
	}
	content, err = os.ReadFile(path)
	if err != nil || string(content) != "new" {
		t.Fatalf("atomic replacement failed: %q %v", content, err)
	}
}

func TestStorageRejectsInvalidDestinationsAndOversizeFiles(t *testing.T) {
	if err := atomicWriteValidated("", []byte("x"), 0o600, nil); err == nil {
		t.Fatal("empty destination accepted")
	}
	directory := t.TempDir()
	parentFile := filepath.Join(directory, "not-a-directory")
	if err := os.WriteFile(parentFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(filepath.Join(parentFile, "authorization"), []byte("x"), 0o600); err == nil {
		t.Fatal("file parent accepted as directory")
	}

	largePath := filepath.Join(directory, "large")
	if err := os.WriteFile(largePath, bytes.Repeat([]byte{'x'}, maxLocalArtifactSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedFile(largePath); err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("oversize file accepted: %v", err)
	}
}

func TestEnvelopeDecodingBounds(t *testing.T) {
	jsonEnvelope := ` {"schemaVersion":"1.0"} `
	decoded, err := decodeEnvelope(jsonEnvelope)
	if err != nil || string(decoded) != strings.TrimSpace(jsonEnvelope) {
		t.Fatalf("JSON envelope not accepted: %q %v", decoded, err)
	}
	for _, value := range []string{"%%%", "", base64.RawURLEncoding.EncodeToString(make([]byte, maxLocalArtifactSize+1))} {
		if _, err := decodeEnvelope(value); err == nil {
			t.Fatalf("invalid envelope accepted (length %d)", len(value))
		}
	}
}
