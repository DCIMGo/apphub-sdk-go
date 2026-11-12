package apphubsdk

import (
	"context"
	"time"

	license "github.com/DCIMGo/apphub-sdk-go/internal/protocol"
	"github.com/gogf/gf/v2/errors/gerror"
)

// StartAutoRenew 确认缓存租约可验后启动定期检查，进入续租或宽限状态时尝试续签。
func (c *client) StartAutoRenew(ctx context.Context) error {
	if ctx == nil {
		return gerror.New("context is required")
	}
	if _, err := c.verifyCachedLease(ctx); err != nil {
		return gerror.Wrap(err, "verify cached lease before auto-renew")
	}
	c.mu.Lock()
	if c.autoCancel != nil {
		c.mu.Unlock()
		return gerror.New("automatic renewal is already running")
	}
	runContext, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	c.autoCancel = cancel
	c.autoDone = done
	c.mu.Unlock()
	go c.autoRenew(runContext, done)
	return nil
}

// StopAutoRenew 通知后台协程退出，并等待当前续签流程结束。
func (c *client) StopAutoRenew() {
	c.mu.Lock()
	cancel := c.autoCancel
	done := c.autoDone
	c.autoCancel = nil
	c.autoDone = nil
	c.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	<-done
}

func (c *client) autoRenew(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(c.config.AutoRenewInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			status, err := c.verifyCachedLease(ctx)
			if err != nil {
				continue
			}
			if status.LeaseState == string(license.LeaseRenewing) || status.LeaseState == string(license.LeaseGrace) {
				_, _ = c.RenewOnline(ctx)
			}
		}
	}
}
