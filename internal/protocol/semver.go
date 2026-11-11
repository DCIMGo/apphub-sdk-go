package protocol

import (
	"fmt"
	"strconv"
	"strings"
)

type semanticVersion struct {
	major, minor, patch uint64
	pre                 []string
}

func parseSemanticVersion(value string) (semanticVersion, error) {
	var result semanticVersion
	value = strings.TrimSpace(value)
	if value == "" || strings.HasPrefix(value, "v") {
		return result, fmt.Errorf("invalid semantic version")
	}
	coreAndPre := strings.SplitN(strings.SplitN(value, "+", 2)[0], "-", 2)
	parts := strings.Split(coreAndPre[0], ".")
	if len(parts) != 3 {
		return result, fmt.Errorf("semantic version must have major.minor.patch")
	}
	parsed := make([]uint64, 3)
	for i, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return result, fmt.Errorf("invalid numeric identifier")
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return result, fmt.Errorf("invalid numeric identifier")
			}
		}
		var err error
		parsed[i], err = strconv.ParseUint(part, 10, 64)
		if err != nil {
			return result, fmt.Errorf("numeric identifier out of range: %w", err)
		}
	}
	result.major, result.minor, result.patch = parsed[0], parsed[1], parsed[2]
	if len(coreAndPre) == 2 {
		if coreAndPre[1] == "" {
			return result, fmt.Errorf("empty prerelease")
		}
		result.pre = strings.Split(coreAndPre[1], ".")
		for _, identifier := range result.pre {
			if identifier == "" {
				return result, fmt.Errorf("empty prerelease identifier")
			}
			numeric := true
			for _, r := range identifier {
				if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '-') {
					return result, fmt.Errorf("invalid prerelease identifier")
				}
				if r < '0' || r > '9' {
					numeric = false
				}
			}
			if numeric && len(identifier) > 1 && identifier[0] == '0' {
				return result, fmt.Errorf("numeric prerelease has leading zero")
			}
		}
	}
	return result, nil
}
func compareSemanticVersion(left, right semanticVersion) int {
	if result := compareUint(left.major, right.major); result != 0 {
		return result
	}
	if result := compareUint(left.minor, right.minor); result != 0 {
		return result
	}
	if result := compareUint(left.patch, right.patch); result != 0 {
		return result
	}
	if len(left.pre) == 0 && len(right.pre) == 0 {
		return 0
	}
	if len(left.pre) == 0 {
		return 1
	}
	if len(right.pre) == 0 {
		return -1
	}
	for i := 0; i < len(left.pre) && i < len(right.pre); i++ {
		leftNumber, leftErr := strconv.ParseUint(left.pre[i], 10, 64)
		rightNumber, rightErr := strconv.ParseUint(right.pre[i], 10, 64)
		switch {
		case leftErr == nil && rightErr == nil:
			if result := compareUint(leftNumber, rightNumber); result != 0 {
				return result
			}
		case leftErr == nil:
			return -1
		case rightErr == nil:
			return 1
		default:
			if left.pre[i] < right.pre[i] {
				return -1
			}
			if left.pre[i] > right.pre[i] {
				return 1
			}
		}
	}
	return compareUint(uint64(len(left.pre)), uint64(len(right.pre)))
}
func compareUint(left, right uint64) int {
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}
func ValidateVersionRange(version string, versionRange VersionRange) error {
	current, err := parseSemanticVersion(version)
	if err != nil {
		return NewValidationError(ErrVersionMismatch, "appVersion", err)
	}
	var minimum, maximum semanticVersion
	if versionRange.Minimum != "" {
		minimum, err = parseSemanticVersion(versionRange.Minimum)
		if err != nil {
			return NewValidationError(ErrInvalidPayload, "versionRange.minimum", err)
		}
	}
	if versionRange.MaximumExclusive != "" {
		maximum, err = parseSemanticVersion(versionRange.MaximumExclusive)
		if err != nil {
			return NewValidationError(ErrInvalidPayload, "versionRange.maximumExclusive", err)
		}
	}
	if versionRange.Minimum != "" && versionRange.MaximumExclusive != "" && compareSemanticVersion(minimum, maximum) >= 0 {
		return NewValidationError(ErrInvalidPayload, "versionRange", nil)
	}
	if versionRange.Minimum != "" && compareSemanticVersion(current, minimum) < 0 {
		return NewValidationError(ErrVersionMismatch, "appVersion", nil)
	}
	if versionRange.MaximumExclusive != "" && compareSemanticVersion(current, maximum) >= 0 {
		return NewValidationError(ErrVersionMismatch, "appVersion", nil)
	}
	return nil
}
