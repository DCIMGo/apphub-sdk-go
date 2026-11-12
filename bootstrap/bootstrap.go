// Package bootstrap 提供配置加载、公钥解析和应用启动校验的通用入口。
package bootstrap

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	apphubsdk "github.com/DCIMGo/apphub-sdk-go"
	"github.com/gogf/gf/v2/encoding/gbase64"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/os/genv"
)

// Config 保存解析后的 SDK 启动配置，供 New 创建客户端。
type Config struct {
	AppID                     string
	AppVersion                string
	InstanceID                string
	ServerURL                 string
	LicensePath               string
	PublicKeyPath             string
	UseUnifiedMachineIdentity bool
}

// FileConfig 描述 JSON 配置结构。对应的非空 APPHUB_SDK_ 环境变量可覆盖字符串字段。
type FileConfig struct {
	AppID                     string `json:"appId"`
	AppVersion                string `json:"appVersion"`
	InstanceID                string `json:"instanceId"`
	ServerURL                 string `json:"serverUrl"`
	LicensePath               string `json:"licensePath"`
	PublicKeyPath             string `json:"publicKeyPath"`
	UseUnifiedMachineIdentity bool   `json:"useUnifiedMachineIdentity,omitempty"`
}

// LoadConfig 读取 JSON 配置并应用环境变量覆盖。
// 配置加载可在应用框架初始化之前执行。
// 路径为空时读取 ./config/apphub-sdk.json。
func LoadConfig(path string) (Config, error) {
	if strings.TrimSpace(path) == "" {
		path = filepath.Join("config", "apphub-sdk.json")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return Config{}, gerror.Wrapf(err, "read SDK config %q", path)
	}
	var file FileConfig
	if err := json.Unmarshal(content, &file); err != nil {
		return Config{}, gerror.Wrapf(err, "decode SDK config %q", path)
	}
	value := func(fileValue, envName string) string {
		if envValue := strings.TrimSpace(genv.Get(envName, "").String()); envValue != "" {
			return envValue
		}
		return strings.TrimSpace(fileValue)
	}
	return Config{
		UseUnifiedMachineIdentity: file.UseUnifiedMachineIdentity,
		AppID:                     value(file.AppID, "APPHUB_SDK_APP_ID"), AppVersion: value(file.AppVersion, "APPHUB_SDK_APP_VERSION"),
		InstanceID: value(file.InstanceID, "APPHUB_SDK_INSTANCE_ID"), ServerURL: value(file.ServerURL, "APPHUB_SDK_SERVER_URL"),
		LicensePath: value(file.LicensePath, "APPHUB_SDK_LICENSE_PATH"), PublicKeyPath: value(file.PublicKeyPath, "APPHUB_SDK_PUBLIC_KEY_PATH"),
	}, nil
}

// NewFromConfig 加载本地 JSON 配置及验签公钥，构造客户端。
func NewFromConfig(path string) (apphubsdk.Client, error) {
	config, err := LoadConfig(path)
	if err != nil {
		return nil, err
	}
	return New(config)
}

type keyFile struct {
	Keys []keyEntry `json:"keys"`
}

type keyEntry struct {
	KeyID     string `json:"keyId"`
	PublicKey string `json:"publicKeyBase64"`
}

// LoadPublicKeys 从受信任来源的 JSON 文件加载 Ed25519 验签公钥，并按 keyId 建立索引。
func LoadPublicKeys(path string) (map[string]ed25519.PublicKey, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, gerror.Wrap(err, "read public key file")
	}
	var envelope keyFile
	if err := json.Unmarshal(content, &envelope); err != nil {
		return nil, gerror.Wrap(err, "decode public key file")
	}
	if len(envelope.Keys) == 0 {
		return nil, gerror.New("public key file contains no keys")
	}
	keys := make(map[string]ed25519.PublicKey, len(envelope.Keys))
	for _, entry := range envelope.Keys {
		if strings.TrimSpace(entry.KeyID) == "" {
			return nil, gerror.New("public key id is required")
		}
		if _, exists := keys[entry.KeyID]; exists {
			return nil, gerror.Newf("public key id %q is duplicated", entry.KeyID)
		}
		decoded, err := gbase64.DecodeString(strings.TrimSpace(entry.PublicKey))
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			return nil, gerror.Newf("public key %q is not a base64 Ed25519 key", entry.KeyID)
		}
		keys[entry.KeyID] = ed25519.PublicKey(decoded)
	}
	return keys, nil
}

// New 按解析后的配置加载验签公钥并创建 SDK 客户端。
func New(config Config) (apphubsdk.Client, error) {
	keys, err := LoadPublicKeys(config.PublicKeyPath)
	if err != nil {
		return nil, err
	}
	return apphubsdk.New(apphubsdk.Config{
		AppID: config.AppID, AppVersion: config.AppVersion, InstanceID: config.InstanceID,
		UseUnifiedMachineIdentity: config.UseUnifiedMachineIdentity,
		ServerURL:                 config.ServerURL, LicensePath: config.LicensePath, PublicKeys: keys,
	})
}

// VerifyStartup 先检查本地授权，再检查缓存租约。
// 有效、即将到期的本地文件以及允许继续使用的租约状态均可通过启动检查。
func VerifyStartup(ctx context.Context, client apphubsdk.Client) (*apphubsdk.Status, error) {
	localStatus, localErr := client.VerifyLocal(ctx)
	if localErr == nil && (localStatus.LocalState == "active" || localStatus.LocalState == "expiring") {
		return localStatus, nil
	}
	leaseStatus, leaseErr := client.VerifyOnlineLease(ctx)
	if leaseErr == nil && (leaseStatus.LeaseState == "authorized" || leaseStatus.LeaseState == "renewing" || leaseStatus.LeaseState == "grace") {
		return leaseStatus, nil
	}
	if localErr != nil && leaseErr != nil {
		return localStatus, gerror.Newf("local license unavailable (%v) and cached online lease unavailable (%v)", localErr, leaseErr)
	}
	return localStatus, gerror.Newf("authorization is not usable: local=%s lease=%s", localStatus.LocalState, leaseStatus.LeaseState)
}
