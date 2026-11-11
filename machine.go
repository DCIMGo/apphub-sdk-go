package apphubsdk

import (
	"context"
	"fmt"
	"os"
	"runtime"

	license "github.com/DCIMGo/apphub-sdk-go/internal/protocol"
	"github.com/DCIMGo/apphub-sdk-go/machineidentity"
)

// hostMachineSource 使用主机名、操作系统和运行架构生成旧版机器摘要。
type hostMachineSource struct{}

func (hostMachineSource) Components(_ context.Context) ([]string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("read hostname: %w", err)
	}
	return []string{"hostname=" + hostname, "os=" + runtime.GOOS, "arch=" + runtime.GOARCH}, nil
}

func machineID(ctx context.Context, source MachineSource) (string, error) {
	components, err := source.Components(ctx)
	if err != nil {
		return "", fmt.Errorf("read machine identity: %w", err)
	}
	return license.NormalizeMachineComponents(components...)
}

// requestMachineIdentity 按客户端配置选择新请求所用的机器绑定方案。
func (c *client) requestMachineIdentity(ctx context.Context) (string, *machineidentity.Binding, error) {
	if !c.config.UseUnifiedMachineIdentity {
		id, err := machineID(ctx, c.config.MachineSource)
		return id, nil, err
	}
	identity, err := machineidentity.Collect(ctx)
	if err != nil {
		return "", nil, err
	}
	return identity.MachineID, &identity.Binding, nil
}

// machineForBinding 以已签名的绑定字段为准。字段缺失时使用旧版 MachineSource。
func (c *client) machineForBinding(ctx context.Context, binding *machineidentity.Binding) (string, error) {
	if binding == nil {
		return machineID(ctx, c.config.MachineSource)
	}
	identity, err := machineidentity.Collect(ctx)
	if err != nil {
		return "", license.NewValidationError(license.ErrMachineIdentityUnavailable, "machineBinding", err)
	}
	if identity.Binding != *binding {
		return "", license.NewValidationError(license.ErrMachineMismatch, "machineBinding", nil)
	}
	return identity.MachineID, nil
}
