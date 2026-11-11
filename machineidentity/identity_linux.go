//go:build linux && !android

package machineidentity

import (
	"fmt"
	"io"
	"os"
)

// readInstallationID 读取 Linux 的 /etc/machine-id，并限制输入长度。
func readInstallationID() (string, Binding, error) {
	const path = "/etc/machine-id"
	file, err := os.Open(path)
	if err != nil {
		return "", Binding{}, fmt.Errorf("read Linux installation identity: %w", err)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 257))
	if err != nil {
		return "", Binding{}, fmt.Errorf("read Linux installation identity: %w", err)
	}
	if len(raw) > 256 {
		return "", Binding{}, fmt.Errorf("Linux installation identity is too long")
	}
	return string(raw), Binding{Scheme, "os-installation", "linux", "linux.machine-id"}, nil
}
