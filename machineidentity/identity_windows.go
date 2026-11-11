package machineidentity

import (
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"
)

// readInstallationID 从 Windows 注册表读取当前系统的 MachineGuid。
func readInstallationID() (string, Binding, error) {
	path, _ := syscall.UTF16PtrFromString(`SOFTWARE\Microsoft\Cryptography`)
	name, _ := syscall.UTF16PtrFromString("MachineGuid")
	var key syscall.Handle
	// 64 位系统统一读原生注册表视图，32 位系统忽略此标志。
	if err := syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, path, 0, syscall.KEY_QUERY_VALUE|syscall.KEY_WOW64_64KEY, &key); err != nil {
		return "", Binding{}, fmt.Errorf("open Windows installation identity: %w", err)
	}
	defer syscall.RegCloseKey(key)
	var buf [256]byte
	var kind uint32
	size := uint32(len(buf))
	if err := syscall.RegQueryValueEx(key, name, nil, &kind, &buf[0], &size); err != nil {
		return "", Binding{}, fmt.Errorf("read Windows installation identity: %w", err)
	}
	if kind != syscall.REG_SZ || size < 2 || size > uint32(len(buf)) || size%2 != 0 {
		return "", Binding{}, errors.New("invalid Windows installation identity")
	}
	value := make([]uint16, size/2)
	for i := range value {
		value[i] = binary.LittleEndian.Uint16(buf[i*2:])
	}
	if value[len(value)-1] != 0 {
		return "", Binding{}, errors.New("invalid Windows installation identity")
	}
	for _, unit := range value[:len(value)-1] {
		if unit == 0 {
			return "", Binding{}, errors.New("invalid Windows installation identity")
		}
	}
	return syscall.UTF16ToString(value), Binding{Scheme, "os-installation", "windows", "windows.machine-guid"}, nil
}
