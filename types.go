// Package apphubsdk 提供 AppHub 本地授权验签、在线激活与租约管理。
package apphubsdk

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"time"
)

// Version 是 SDK 版本，也是在线请求中的客户端版本。
const Version = "0.1.0"

// Client 定义应用可调用的 SDK 接口。接受上下文的方法要求传入非空 context.Context。
type Client interface {
	// MachineID 根据客户端配置计算用于新请求的机器摘要。
	MachineID(context.Context) (string, error)
	// MachineRequest 导出 JSON 申请，供业务代码与现有接口交换。
	MachineRequest(context.Context) ([]byte, error)
	// ImportLicense 验签并安装已签发的授权文件。
	ImportLicense(context.Context, []byte) (*Status, error)
	// ActivateOnce 使用激活码取得授权文件，验签后安装。
	ActivateOnce(context.Context, ActivateRequest) (*Status, error)
	// AuthorizeOnline 使用激活码申请签名租约并缓存。
	AuthorizeOnline(context.Context, AuthorizeRequest) (*Status, error)
	// RenewOnline 使用已有租约请求续签。
	RenewOnline(context.Context) (*Status, error)
	// CheckUpdate 查询当前实例的更新权益和发布信息。
	CheckUpdate(context.Context, UpdateCheckRequest) (*UpdateCheckResult, error)
	// StartAutoRenew 在签名租约进入续租窗口后尝试续签。
	StartAutoRenew(context.Context) error
	// StopAutoRenew 取消后台续签并等待协程退出。
	StopAutoRenew()
	// VerifyLocal 从本地磁盘读取并验证授权文件。
	VerifyLocal(context.Context) (*Status, error)
	// VerifyOnlineLease 离线验证本地缓存的签名租约。
	VerifyOnlineLease(context.Context) (*Status, error)
	// Status 返回最近一次保存的授权状态快照。
	Status() Status
	// HasFeature 查询当前可用授权是否开通指定功能。
	HasFeature(string) bool
	// GetIntLimit 查询指定额度，第二个返回值表示该额度是否存在。
	GetIntLimit(string) (int64, bool)
	// GetConfig 查询指定授权配置，第二个返回值表示是否读到了可用值。
	GetConfig(string) (any, bool)
}

// MachineSource 为旧版机器绑定提供组成项，既有授权应沿用原采集规则。
type MachineSource interface {
	Components(context.Context) ([]string, error)
}

// Config 配置客户端的应用、实例、可信公钥及授权文件位置。
type Config struct {
	AppID         string
	AppVersion    string
	InstanceID    string
	ServerURL     string
	LicensePath   string
	PublicKeys    map[string]ed25519.PublicKey
	MachineSource MachineSource
	// UseUnifiedMachineIdentity 使新请求使用统一机器身份和 2.0 协议。
	// 验证已签发的文件或租约时，SDK 按签名内容选择身份方案。
	UseUnifiedMachineIdentity bool
	HTTPClient                *http.Client
	Clock                     func() time.Time
	ExpiringBefore            time.Duration
	ClockRollbackSkew         time.Duration
	AutoRenewInterval         time.Duration
	// InstanceCredential 是更新检查使用的短期实例凭证。
	InstanceCredential string
}

// ActivateRequest 提供一次性激活所需的激活码和请求参数。
type ActivateRequest struct {
	ActivationCode string
	ServerURL      string
	InstanceID     string
	InstanceName   string
	IdempotencyKey string
}

// AuthorizeRequest 提供申请联网租约所需的激活码和请求参数。
type AuthorizeRequest struct {
	ActivationCode string
	ServerURL      string
	InstanceID     string
	InstanceName   string
	IdempotencyKey string
}

// UpdateCheckRequest 描述要检查更新的实例、版本与平台。
// 未填渠道时使用 stable，未填操作系统或架构时使用当前运行平台。
type UpdateCheckRequest struct {
	ServerURL          string
	CurrentVersion     string
	Channel            string
	OS                 string
	Arch               string
	InstanceID         string
	InstanceCredential string
	IdempotencyKey     string
}

// UpdateCheckResult 表示 AppHub 按实例权益给出的更新结果。
// 没有可用更新或请求被拒时，Release 为空。
type UpdateCheckResult struct {
	UpdateAvailable        bool
	Reason                 string
	UpdateTaskID           string
	Release                *UpdateRelease
	DownloadToken          string
	DownloadTokenExpiresAt *time.Time
}

// UpdateRelease 提供更新器获取和核对清单所需的发布信息。
type UpdateRelease struct {
	ID               string
	Version          string
	Channel          string
	Mandatory        bool
	SecurityUpdate   bool
	SupportsRollback bool
	ReleaseNotes     string
	KnownIssues      string
	MaintenanceUntil *time.Time
	ManifestURL      string
	ManifestSHA256   string
}

// Status 保存校验后的授权状态、时间窗口及功能和额度。
type Status struct {
	Mode            string
	LocalState      string
	LeaseState      string
	AppID           string
	InstanceID      string
	LicenseID       string
	LicenseRevision int64
	LeaseID         string
	LeaseRevision   int64
	NotBefore       *time.Time
	ExpiresAt       *time.Time
	RenewAfter      *time.Time
	GraceUntil      *time.Time
	GraceEndPolicy  string
	Features        map[string]bool
	Limits          map[string]int64
	Configs         map[string]json.RawMessage
	UpdatePolicy    UpdatePolicy
	Reason          string
	VerifiedAt      time.Time
}

// UpdatePolicy 表示当前授权允许的更新渠道、维护期限和更新操作。
type UpdatePolicy struct {
	Enabled             bool
	AutoUpdateEnabled   bool
	Channels            []string
	MaintenanceUntil    *time.Time
	MaximumVersion      string
	AllowRollback       bool
	ForcedUpdateAllowed bool
}

// APIError 保留 AppHub 请求的 HTTP 状态、业务错误码和追踪标识。
type APIError struct {
	HTTPStatus int
	Code       int
	Reason     string
	Message    string
	TraceID    string
}

func (e *APIError) Error() string {
	if e.Reason != "" {
		return "AppHub request failed: " + e.Reason
	}
	return "AppHub request failed"
}
