//go:build !windows && (!linux || android)

package machineidentity

import "errors"

// readInstallationID 在尚未接入统一采集的平台返回不支持错误。
func readInstallationID() (string, Binding, error) {
	return "", Binding{}, errors.New("unified system installation identity is unsupported on this platform")
}
