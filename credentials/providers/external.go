package providers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// ExternalCredentialUpdateCallback 定义External凭证更新回调函数类型
type ExternalCredentialUpdateCallback func(accessKeyId, accessKeySecret, securityToken string, expiration int64) error

type externalCredentialResponse struct {
	Mode            string `json:"mode"`
	AccessKeyId     string `json:"access_key_id"`
	AccessKeySecret string `json:"access_key_secret"`
	SecurityToken   string `json:"sts_token"`
	Expiration      string `json:"expiration,omitempty"`
}

type ExternalCredentialsProvider struct {
	processCommand string

	lastUpdateTimestamp int64
	expirationTimestamp int64
	sessionCredentials  *sessionCredentials
	// External credential call back
	credentialUpdateCallback ExternalCredentialUpdateCallback
	// 互斥锁，用于并发安全
	mu sync.RWMutex
}

type ExternalCredentialsProviderBuilder struct {
	provider *ExternalCredentialsProvider
}

func NewExternalCredentialsProviderBuilder() *ExternalCredentialsProviderBuilder {
	return &ExternalCredentialsProviderBuilder{
		provider: &ExternalCredentialsProvider{},
	}
}

func (b *ExternalCredentialsProviderBuilder) WithProcessCommand(processCommand string) *ExternalCredentialsProviderBuilder {
	b.provider.processCommand = processCommand
	return b
}

func (b *ExternalCredentialsProviderBuilder) WithCredentialUpdateCallback(callback ExternalCredentialUpdateCallback) *ExternalCredentialsProviderBuilder {
	b.provider.credentialUpdateCallback = callback
	return b
}

func (b *ExternalCredentialsProviderBuilder) Build() (provider *ExternalCredentialsProvider, err error) {
	if b.provider.processCommand == "" {
		err = errors.New("process_command is empty")
		return
	}

	provider = b.provider
	return
}

func (provider *ExternalCredentialsProvider) getCredentials() (session *sessionCredentials, err error) {
	args := strings.Fields(provider.processCommand)
	if len(args) == 0 {
		err = errors.New("process_command is empty")
		return
	}

	cmd := exec.Command(args[0], args[1:]...)

	// 创建一个buffer来捕获标准输出
	var stdoutBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf

	// 创建一个buffer来捕获标准错误输出
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	// 执行命令
	err = cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("failed to execute external command: %w\nstderr: %s", err, stderrBuf.String())
	}

	// 只解析标准输出
	buf := stdoutBuf.Bytes()

	// 解析得到凭证响应
	var resp externalCredentialResponse
	err = json.Unmarshal(buf, &resp)
	if err != nil {
		fmt.Println(provider.processCommand)
		fmt.Println(string(buf))
		return nil, fmt.Errorf("failed to parse external command output: %w", err)
	}

	// 验证返回的凭证数据
	if resp.AccessKeyId == "" || resp.AccessKeySecret == "" {
		return nil, fmt.Errorf("invalid credential response: access_key_id or access_key_secret is empty")
	}

	// 根据 mode 验证 SecurityToken
	if resp.Mode == "StsToken" && resp.SecurityToken == "" {
		return nil, fmt.Errorf("invalid StsToken credential response: sts_token is empty")
	}

	session = &sessionCredentials{
		AccessKeyId:     resp.AccessKeyId,
		AccessKeySecret: resp.AccessKeySecret,
		SecurityToken:   resp.SecurityToken,
		Expiration:      resp.Expiration,
	}

	return
}

func (provider *ExternalCredentialsProvider) needUpdateCredential() (result bool) {
	provider.mu.RLock()
	defer provider.mu.RUnlock()

	// 如果没有缓存凭证，需要更新
	if provider.sessionCredentials == nil {
		return true
	}

	// 如果没有过期时间，每次都更新（因为外部命令可能返回动态凭证）
	if provider.expirationTimestamp == 0 {
		return true
	}

	// 如果凭证即将过期（提前180秒），需要更新
	return provider.expirationTimestamp-time.Now().Unix() <= 180
}

func (provider *ExternalCredentialsProvider) GetCredentials() (cc *Credentials, err error) {
	// 先检查是否需要更新（使用读锁）
	provider.mu.RLock()
	needUpdate := provider.sessionCredentials == nil ||
		provider.expirationTimestamp == 0 ||
		provider.expirationTimestamp-time.Now().Unix() <= 180
	provider.mu.RUnlock()

	if needUpdate {
		// 获取新凭证（在锁外执行，避免阻塞其他 goroutine）
		sessionCredentials, err1 := provider.getCredentials()
		if err1 != nil {
			return nil, err1
		}

		// 使用写锁更新共享状态
		provider.mu.Lock()
		// 双重检查，避免多个 goroutine 同时更新
		if provider.sessionCredentials == nil ||
			provider.expirationTimestamp == 0 ||
			provider.expirationTimestamp-time.Now().Unix() <= 180 {
			provider.sessionCredentials = sessionCredentials

			// 如果返回了过期时间，解析并缓存
			if sessionCredentials.Expiration != "" {
				expirationTime, err2 := time.Parse("2006-01-02T15:04:05Z", sessionCredentials.Expiration)
				if err2 != nil {
					// 如果解析失败，不设置过期时间，下次调用时重新获取
					provider.expirationTimestamp = 0
				} else {
					provider.lastUpdateTimestamp = time.Now().Unix()
					provider.expirationTimestamp = expirationTime.Unix()
				}
			} else {
				// 没有过期时间，下次调用时重新获取
				provider.expirationTimestamp = 0
			}
		}
		expirationTimestamp := provider.expirationTimestamp
		sessionCredentials = provider.sessionCredentials
		provider.mu.Unlock()

		// 如果设置了回调函数，则调用回调函数写回配置文件（在锁外执行）
		if provider.credentialUpdateCallback != nil {
			err1 := provider.credentialUpdateCallback(
				sessionCredentials.AccessKeyId,
				sessionCredentials.AccessKeySecret,
				sessionCredentials.SecurityToken,
				expirationTimestamp,
			)
			if err1 != nil {
				fmt.Printf("Warning: failed to update external credentials in config file: %v\n", err1)
			}
		}
	}

	// 使用读锁读取凭证
	provider.mu.RLock()
	cc = &Credentials{
		AccessKeyId:     provider.sessionCredentials.AccessKeyId,
		AccessKeySecret: provider.sessionCredentials.AccessKeySecret,
		SecurityToken:   provider.sessionCredentials.SecurityToken,
		ProviderName:    provider.GetProviderName(),
	}
	provider.mu.RUnlock()
	return
}

func (provider *ExternalCredentialsProvider) GetProviderName() string {
	return "external"
}
