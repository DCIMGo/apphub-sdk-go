package protocol

import (
	"strings"

	"github.com/DCIMGo/apphub-sdk-go/machineidentity"
)

const SchemaVersionV2 = "2.0"

// ValidMachineBinding 校验机器摘要和协议版本要求的绑定字段。
func ValidMachineBinding(version, machineID string, binding *machineidentity.Binding) bool {
	if !IsMachineID(machineID) {
		return false
	}
	switch version {
	case SchemaVersionV1:
		return binding == nil
	case SchemaVersionV2:
		return binding != nil && binding.Valid() && machineID == strings.ToLower(machineID)
	default:
		return false
	}
}
