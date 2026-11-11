# DCIMGo AppHub Go SDK

Module path: `github.com/DCIMGo/apphub-sdk-go`. Consumers must use an immutable
published version such as `v0.1.0`; application repositories must not use a
relative `replace` or copy this source tree. The AppHub workspace uses `go.work`
only to run server-to-SDK protocol compatibility tests before publication.

The SDK verifies signed licenses locally for `offline` and `activate_once`, and
caches short-lived signed leases for `online_lease`. It sends no business usage,
application logs, or raw hardware attributes to AppHub.

```go
package main

import (
	"context"
	"crypto/ed25519"
	"log"

	apphubsdk "github.com/DCIMGo/apphub-sdk-go"
)

func main() {
	publicKeys := map[string]ed25519.PublicKey{
		"license-2026-01": loadPublicKey(),
	}
	sdk, err := apphubsdk.New(apphubsdk.Config{
		AppID:       "go-dcim",
		AppVersion:  "2.1.0",
		InstanceID:  "dcim-primary",
		ServerURL:   "https://apphub.example.com",
		LicensePath: "/var/lib/go-dcim/app.license",
		PublicKeys:  publicKeys,
	})
	if err != nil {
		log.Fatal(err)
	}

	status, err := sdk.VerifyLocal(context.Background())
	if err != nil {
		log.Printf("license unavailable: %v", err)
		return
	}
	if status.LocalState == "active" && sdk.HasFeature("asset.export") {
		// Enable the feature at the business entry point.
	}
}

func loadPublicKey() ed25519.PublicKey { return nil }
```

One-time activation downloads a long-lived license and verifies its digest,
signature, App ID, machine binding, version, and time window before replacing
the local file:

```go
status, err := sdk.ActivateOnce(ctx, apphubsdk.ActivateRequest{
	ActivationCode: code, // Never log this value.
	IdempotencyKey: requestID,
})
```

Online leases use `AuthorizeOnline`, `RenewOnline`, and optionally
`StartAutoRenew`. A network failure does not become a revocation: the SDK derives
`authorized`, `renewing`, `grace`, then `restricted` from the last verified signed
lease. Applications must enforce returned feature and limit values themselves.

## 本地联调流程

SDK 的本地流程可以按“启动校验 → 激活/授权 → 权益读取 → 更新检查”组织。所有公开
方法都要求传入非空 `context.Context`；传入 `nil` 会返回 `context is required`，不会
触发机器信息读取或网络请求。

一次性激活只在线请求一次授权文件，文件通过签名、摘要、应用号、机器码、版本和时间窗
校验后才原子写入 `LicensePath`：

```go
status, err := client.ActivateOnce(ctx, apphubsdk.ActivateRequest{
	ActivationCode: code,
	IdempotencyKey: "go-sample-activate-20260826-0001",
})
if err != nil {
	return err // 原有本地授权文件不会被替换
}
log.Printf("activated: %s", status.LicenseID)
```

联网租约应用建议在启动时先验证缓存，网络可用时再申请或续租；短暂断网期间可继续使用
签名租约声明的 `grace` 策略：

```go
status, err := client.VerifyOnlineLease(ctx)
if err != nil || (status.LeaseState != "authorized" && status.LeaseState != "renewing" && status.LeaseState != "grace") {
	status, err = client.AuthorizeOnline(ctx, apphubsdk.AuthorizeRequest{
		ActivationCode: code,
		IdempotencyKey: "go-sample-online-20260826-0001",
	})
	if err != nil {
		return err
	}
}
if err := client.StartAutoRenew(ctx); err != nil {
	return err
}
defer client.StopAutoRenew()
```

更新检查只返回权益范围内的发布元数据，不会自动下载或安装：

```go
decision, err := client.CheckUpdate(ctx, apphubsdk.UpdateCheckRequest{
	CurrentVersion: "1.0.0",
	Channel:        "stable",
})
if err != nil {
	return err
}
if decision.UpdateAvailable && decision.Release != nil {
	log.Printf("update %s available (task=%s)", decision.Release.Version, decision.UpdateTaskID)
}
```

更新包仍需交给独立 updater 完成清单、摘要、签名和健康检查；SDK 不在业务进程内执行
安装或回滚。

The default machine source uses a normalized hostname/OS/architecture digest.
Production deployments should provide a stable, platform-specific
`MachineSource` (for example, a TPM or OS installation identifier). Only the
purpose-separated `sha256:...` digest is placed in machine requests.

### 统一机器码（Windows / Linux）

Go 应用可用 `go get github.com/DCIMGo/apphub-sdk-go@main` 获取主分支当前提交，
Go 会将该提交的版本写入 `go.mod`。接入项目应提交 `go.mod` 和 `go.sum`，
后续构建使用项目已锁定的版本。目标程序调用 `machineidentity.Collect(ctx)`，
再用返回对象的 `MarshalRequestCode(appID, appVersion, instanceID, time.Now())`
生成供用户复制的 `AHM1.` 授权申请码。

也可以用 `go install github.com/DCIMGo/apphub-sdk-go/cmd/apphub-machine-request@main`
安装命令。生产构建按 AppHub SDK 发布流程使用批准的版本。


在目标系统进入 SDK 仓库根目录，运行下面的命令，替换应用标识、版本和实例。

```sh
go run ./cmd/apphub-machine-request -app-id my-app -app-version 1.0.0 -instance-id default
```

把输出的一行 `AHM1.` 机器码粘贴到 AppHub「机器码离线授权」的「机器码」输入框。
页面会显示平台、运行架构、采集来源、应用和实例，再按批准来源签发。
脚本如需原来的 JSON 输出，可追加 `-format json`。应用也可调用
`machineidentity.Identity.MarshalRequestCode` 生成可粘贴的文本。
同一系统安装上的应用使用同一绑定摘要，签发文件仍绑定各自应用和实例。
Windows 使用系统 `MachineGuid`，Linux 使用 `/etc/machine-id`，输出仅包含派生摘要及申请字段。

SDK 使用 `Config.UseUnifiedMachineIdentity: true`（bootstrap JSON 中为
`"useUnifiedMachineIdentity": true`）发送新申请、一次激活和联网租约请求。
开关默认关闭；新旧签名文件始终按各自的协议版本选择验签身份，无需为读取
既有授权更改配置。升级时保留原 `MachineSource` 和历史受信公钥。

Security notes:

- Embed only verification public keys in applications; signing private keys do
  not belong in the SDK.
- Use HTTPS. Plain HTTP is accepted only for loopback local development.
- Preserve historical public keys while still-valid artifacts reference them.
- Treat local clock rollback detection as tamper resistance, not as protection
  from a machine administrator.

## 本地配置文件兜底

首批应用可以使用 `bootstrap.LoadConfig` 读取一个 JSON 配置文件，默认路径
为 `./config/apphub-sdk.json`；`APPHUB_SDK_APP_ID`、`APPHUB_SDK_APP_VERSION`、
`APPHUB_SDK_INSTANCE_ID`、`APPHUB_SDK_SERVER_URL`、`APPHUB_SDK_LICENSE_PATH`
和 `APPHUB_SDK_PUBLIC_KEY_PATH` 等非空环境变量会覆盖文件值。这样本机测试
不需要重复拼接长命令，部署时也可以只注入差异配置。

仓库提供可直接复制的模板：`config/apphub-sdk.example.json`。模板只包含
本机联调地址和相对路径，不包含授权码、私钥或真实公钥；复制到应用自己的
`config/apphub-sdk.json` 后，再按应用号和数据目录调整值即可。

```json
{
  "appId": "go-sample",
  "appVersion": "1.0.0",
  "instanceId": "go-sample-local",
  "serverUrl": "http://127.0.0.1:50000",
  "licensePath": "./data/go-sample.license",
  "publicKeyPath": "./data/license-public-keys.json"
}
```

```go
config, err := bootstrap.LoadConfig("./config/apphub-sdk.json")
if err != nil { log.Fatal(err) }
client, err := bootstrap.New(config)
```

仓库根目录的 `scripts/sdk-local-demo.ps1` 提供可重复的本地联调入口。默认会先以
开发配置运行 SQLite 种子命令，再运行 SDK 的 `httptest` 契约测试，覆盖本地授权、
一次性激活、联网租约续期/断网宽限和更新检查；使用 `-SkipSeed` 可跳过数据库种子。
该脚本只验证 SDK 行为，不连接生产授权服务，也不负责下载、安装或回滚更新包。

Release inputs are prepared by `apphub-sdk-release` in the AppHub repository.
The generated file-proxy archive is tested from an empty module cache before it
may be promoted to the approved Git/Go proxy and tagged. A local proxy test does
not constitute production publication.
