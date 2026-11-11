//go:build !windows && (!linux || android)

package machineidentity

import "errors"

func readInstallationID() (string, Binding, error) {
	return "", Binding{}, errors.New("unified system installation identity is unsupported on this platform")
}
