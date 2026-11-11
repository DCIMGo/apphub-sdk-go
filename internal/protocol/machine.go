package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"unicode"
)

const machineDigestDomain = "dcimgo-apphub/machine/v1"

func NormalizeMachineComponents(components ...string) (string, error) {
	values := make([]string, 0, len(components))
	seen := make(map[string]struct{}, len(components))
	for _, value := range components {
		value = strings.ToLower(strings.TrimSpace(value))
		value = strings.Map(func(r rune) rune {
			if unicode.IsSpace(r) {
				return ' '
			}
			return r
		}, value)
		value = strings.Join(strings.Fields(value), " ")
		if value == "" {
			continue
		}
		if len(value) > 1024 {
			return "", NewValidationError(ErrInvalidPayload, "machine component", nil)
		}
		if _, exists := seen[value]; !exists {
			seen[value] = struct{}{}
			values = append(values, value)
		}
	}
	if len(values) == 0 {
		return "", NewValidationError(ErrInvalidPayload, "machine components", nil)
	}
	sort.Strings(values)
	h := sha256.New()
	_, _ = h.Write([]byte(machineDigestDomain))
	for _, value := range values {
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(value))
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func IsMachineID(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}
