# DCIMGo AppHub Go SDK

Go 应用可以用这个 SDK 生成机器码、验证授权文件、在线激活、管理联网租约，以及读取功能和额度。Windows 和 Linux 应用可使用统一机器身份。AppHub 接收授权申请并签发，目标应用在本机采集和验签。

## 安装

在调用方的 Go 项目中安装已发布版本。仓库要求 Go 1.23 或更高版本。

```sh
go get github.com/DCIMGo/apphub-sdk-go@v0.1.0
```

应用仓库提交 `go.mod` 和 `go.sum`，后续构建使用已锁定的版本。也可以直接下载采集工具和 `SHA256SUMS`。 [v0.1.0 下载](https://github.com/DCIMGo/apphub-sdk-go/releases/tag/v0.1.0)

## 获取机器码

在**需要授权的目标机器**上运行采集工具。把 `go-sample`、`1.0.0` 和 `default` 换成 AppHub 中登记的应用标识、实际应用版本和实例标识。

```sh
go run github.com/DCIMGo/apphub-sdk-go/cmd/apphub-machine-request@v0.1.0 -app-id go-sample -app-version 1.0.0 -instance-id default
```

程序输出一行 `AHM1.` 申请码。把它粘贴到 AppHub「机器码离线授权」的「机器码」输入框，核对平台、运行架构、应用和实例，再按批准的来源签发。已有脚本可追加 `-format json` 获取原有申请 JSON。

非 Go 程序可以调用 Release 中的对应平台二进制。用进程参数传入应用、版本和实例。退出码为 0 时从标准输出读取申请码，失败时从标准错误读取提示。

### 在 Go 程序中调用

应用的「获取机器码」按钮可以调用 `machineidentity.Collect`，再把 `MarshalRequestCode` 的返回值显示出来。

```go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/DCIMGo/apphub-sdk-go/machineidentity"
)

func main() {
	identity, err := machineidentity.Collect(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	code, err := identity.MarshalRequestCode("go-sample", "1.0.0", "default", time.Now())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(code)
}
```

Windows 读取系统 `MachineGuid`，Linux 读取 `/etc/machine-id`。申请只包含派生摘要和申请字段。生成时间变化会改变整行申请码，同一系统安装的绑定摘要保持稳定。

## 在应用中初始化 SDK

将 [配置模板](config/apphub-sdk.example.json) 复制为 `config/apphub-sdk.json`。指定应用版本、实例、授权文件路径和 AppHub 导出的可信验签公钥文件。下面是本地离线验签配置示例。

```json
{
  "appId": "go-sample",
  "appVersion": "1.0.0",
  "instanceId": "default",
  "licensePath": "./data/go-sample.license",
  "publicKeyPath": "./data/license-public-keys.json"
}
```

把已签发的授权文件放到 `licensePath`，再在应用启动时调用 `VerifyLocal`。状态为 `active` 或 `expiring` 时，本地授权可用。

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/DCIMGo/apphub-sdk-go/bootstrap"
)

func main() {
	client, err := bootstrap.NewFromConfig("./config/apphub-sdk.json")
	if err != nil {
		log.Fatal(err)
	}
	status, err := client.VerifyLocal(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("授权状态 %s\n", status.LocalState)
	fmt.Printf("数据导出权限 %t\n", client.HasFeature("asset.export"))
}
```

如果程序已经负责加载配置和公钥，可以直接将这些值传给 `apphubsdk.New(apphubsdk.Config{...})`。带 `context.Context` 的 SDK 方法都要求传入非空上下文。

## 组合接口和嵌入客户端

用接口组合把授权检查接到业务服务中。业务服务只依赖所需方法，测试时可以注入实现相同接口的替身。需要保留完整 SDK 接口并加上业务方法时，可以在结构体里嵌入 `apphubsdk.Client`。 [Go 嵌入说明](https://go.dev/doc/effective_go#embedding)

```go
package licensing

import "github.com/DCIMGo/apphub-sdk-go"

type FeatureReader interface {
	HasFeature(code string) bool
}

type ExportService struct {
	features FeatureReader
}

func NewExportService(features FeatureReader) ExportService {
	return ExportService{features: features}
}

func (s ExportService) CanExport() bool {
	return s.features.HasFeature("asset.export")
}

type LicenseClient struct {
	apphubsdk.Client
}

func (c LicenseClient) ExportLimit() (int64, bool) {
	return c.GetIntLimit("asset.export.max")
}

var _ apphubsdk.Client = LicenseClient{}
```

初始化并验证授权后，使用 `NewExportService(client)` 注入 SDK。需要调用扩展方法时，构造 `LicenseClient{Client: client}`。嵌入类型仍可调用 SDK 的原有方法。

`HasFeature`、`GetIntLimit` 和 `GetConfig` 读取最近一次校验保存的权益。应用应在启动时先校验，并按业务需要刷新授权状态。在真正执行导出、添加设备等操作时检查功能与额度。读取额度和配置时，用第二个返回值判断该项是否存在。将示例权益键换成 AppHub 授权项中的实际键。

## 选择授权模式

| 模式 | 调用流程 |
| --- | --- |
| 完全离线 | 启动调用 `VerifyLocal`。收到新文件时读取字节并调用 `ImportLicense(ctx, content)`，SDK 验证成功后安装文件。 |
| 一次激活 | 调用 `ActivateOnce(ctx, apphubsdk.ActivateRequest{ActivationCode: code})` 获取并安装签名文件。之后启动调用 `VerifyLocal`。同一激活意图重试时复用同一个 `IdempotencyKey`。 |
| 联网租约 | 启动调用 `VerifyOnlineLease` 检查缓存，首次申请使用 `AuthorizeOnline`。可用状态为 `authorized`、`renewing`、`grace`。到达签名的续签窗口后调用 `RenewOnline`，也可用 `StartAutoRenew` 启动后台续签，退出时调用 `StopAutoRenew`。 |

同时支持本地文件和联网租约的应用可使用 `bootstrap.VerifyStartup`，它先检查本地文件，再检查缓存租约。只允许单一授权模式的应用可直接调用对应的校验方法。

## 配置与运行约定

- 在线激活、租约和更新检查需要设置 `serverUrl`，远程服务使用 HTTPS。本机联调可使用回环 HTTP。
- `bootstrap.LoadConfig` 会读取 `APPHUB_SDK_APP_ID`、`APPHUB_SDK_APP_VERSION`、`APPHUB_SDK_INSTANCE_ID`、`APPHUB_SDK_SERVER_URL`、`APPHUB_SDK_LICENSE_PATH` 和 `APPHUB_SDK_PUBLIC_KEY_PATH`。对应的非空环境变量覆盖 JSON 字符串字段。
- 在支持 2.0 请求的 AppHub 环境中，将 JSON 的 `useUnifiedMachineIdentity` 或 Go 配置的 `UseUnifiedMachineIdentity` 设为 `true`，可让新请求使用统一机器身份。SDK 根据已签名文件或租约的协议选择验签方案。沿用旧授权时，保留原来的 `MachineSource` 和仍在使用的历史公钥。
- 使用服务账号可写的持久化目录保存授权、`.clock` 和缓存租约。应用只部署验签公钥，激活码和短期实例凭证按敏感配置处理。
- `CheckUpdate` 返回实例有权访问的更新信息及清单摘要。包下载、签名验证、安装和回滚由更新器执行。
