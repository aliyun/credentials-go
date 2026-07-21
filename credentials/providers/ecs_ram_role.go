package providers

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	httputil "github.com/aliyun/credentials-go/credentials/internal/http"
)

type ECSRAMRoleCredentialsProvider struct {
	roleName                     string
	disableIMDSv1                bool
	asyncCredentialUpdateEnabled bool
	asyncCheckInterval           time.Duration
	// for sts
	session             *sessionCredentials
	expirationTimestamp int64
	prefetchTimestamp   int64
	shouldRefresh       bool
	// for http options
	httpOptions *HttpOptions
	// async refresh
	mu     sync.Mutex
	stopCh chan struct{}
	once   sync.Once
}

type ECSRAMRoleCredentialsProviderBuilder struct {
	provider *ECSRAMRoleCredentialsProvider
}

func NewECSRAMRoleCredentialsProviderBuilder() *ECSRAMRoleCredentialsProviderBuilder {
	return &ECSRAMRoleCredentialsProviderBuilder{
		provider: &ECSRAMRoleCredentialsProvider{
			asyncCredentialUpdateEnabled: true,
		},
	}
}

func (builder *ECSRAMRoleCredentialsProviderBuilder) WithRoleName(roleName string) *ECSRAMRoleCredentialsProviderBuilder {
	builder.provider.roleName = roleName
	return builder
}

func (builder *ECSRAMRoleCredentialsProviderBuilder) WithDisableIMDSv1(disableIMDSv1 bool) *ECSRAMRoleCredentialsProviderBuilder {
	builder.provider.disableIMDSv1 = disableIMDSv1
	return builder
}

func (builder *ECSRAMRoleCredentialsProviderBuilder) WithHttpOptions(httpOptions *HttpOptions) *ECSRAMRoleCredentialsProviderBuilder {
	builder.provider.httpOptions = httpOptions
	return builder
}

// WithAsyncCredentialUpdateEnabled controls the 1-minute background IMDS check
// and 1-hour async prefetch, matching Python/Java/Node ECS providers.
func (builder *ECSRAMRoleCredentialsProviderBuilder) WithAsyncCredentialUpdateEnabled(enabled bool) *ECSRAMRoleCredentialsProviderBuilder {
	builder.provider.asyncCredentialUpdateEnabled = enabled
	return builder
}

// withAsyncCheckInterval sets the background checker interval (tests only).
func (builder *ECSRAMRoleCredentialsProviderBuilder) withAsyncCheckInterval(d time.Duration) *ECSRAMRoleCredentialsProviderBuilder {
	builder.provider.asyncCheckInterval = d
	return builder
}

const defaultMetadataTokenDuration = 21600 // 6 hours

func (builder *ECSRAMRoleCredentialsProviderBuilder) Build() (provider *ECSRAMRoleCredentialsProvider, err error) {

	if strings.ToLower(os.Getenv("ALIBABA_CLOUD_ECS_METADATA_DISABLED")) == "true" {
		err = errors.New("IMDS credentials is disabled")
		return
	}

	// 设置 roleName 默认值
	if builder.provider.roleName == "" {
		builder.provider.roleName = os.Getenv("ALIBABA_CLOUD_ECS_METADATA")
	}

	if !builder.provider.disableIMDSv1 {
		builder.provider.disableIMDSv1 = strings.ToLower(os.Getenv("ALIBABA_CLOUD_IMDSV1_DISABLED")) == "true"
	}

	provider = builder.provider
	if provider.asyncCredentialUpdateEnabled {
		if provider.asyncCheckInterval <= 0 {
			provider.asyncCheckInterval = defaultEcsAsyncCheckInterval
		}
		provider.stopCh = make(chan struct{})
		provider.startAsyncRefreshChecker()
	}
	return
}

type ecsRAMRoleResponse struct {
	Code            *string `json:"Code"`
	AccessKeyId     *string `json:"AccessKeyId"`
	AccessKeySecret *string `json:"AccessKeySecret"`
	SecurityToken   *string `json:"SecurityToken"`
	LastUpdated     *string `json:"LastUpdated"`
	Expiration      *string `json:"Expiration"`
}

func (provider *ECSRAMRoleCredentialsProvider) needUpdateCredential() bool {
	return isSessionCredentialStale(provider.expirationTimestamp)
}

func (provider *ECSRAMRoleCredentialsProvider) shouldPrefetchCredential() bool {
	if provider.prefetchTimestamp == 0 {
		return false
	}
	return time.Now().Unix() >= provider.prefetchTimestamp
}

func (provider *ECSRAMRoleCredentialsProvider) startAsyncRefreshChecker() {
	interval := provider.asyncCheckInterval
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-provider.stopCh:
				return
			case <-ticker.C:
				provider.mu.Lock()
				shouldRefresh := provider.shouldRefresh
				provider.mu.Unlock()
				if !shouldRefresh {
					continue
				}
				_, _ = provider.GetCredentials()
			}
		}
	}()
}

// Close stops the background IMDS check goroutine.
func (provider *ECSRAMRoleCredentialsProvider) Close() {
	if provider.stopCh == nil {
		return
	}
	provider.once.Do(func() {
		close(provider.stopCh)
	})
}

func (provider *ECSRAMRoleCredentialsProvider) getRoleName() (roleName string, err error) {
	req := &httputil.Request{
		Method:   "GET",
		Protocol: "http",
		Host:     "100.100.100.200",
		Path:     "/latest/meta-data/ram/security-credentials/",
		Headers:  map[string]string{},
	}

	connectTimeout := 1 * time.Second
	readTimeout := 1 * time.Second

	if provider.httpOptions != nil && provider.httpOptions.ConnectTimeout > 0 {
		connectTimeout = time.Duration(provider.httpOptions.ConnectTimeout) * time.Millisecond
	}
	if provider.httpOptions != nil && provider.httpOptions.ReadTimeout > 0 {
		readTimeout = time.Duration(provider.httpOptions.ReadTimeout) * time.Millisecond
	}
	if provider.httpOptions != nil && provider.httpOptions.Proxy != "" {
		req.Proxy = provider.httpOptions.Proxy
	}
	req.ConnectTimeout = connectTimeout
	req.ReadTimeout = readTimeout

	metadataToken, err := provider.getMetadataToken()
	if err != nil {
		return "", err
	}
	if metadataToken != "" {
		req.Headers["x-aliyun-ecs-metadata-token"] = metadataToken
	}

	res, err := httpDo(req)
	if err != nil {
		err = fmt.Errorf("get role name failed: %s", err.Error())
		return
	}

	if res.StatusCode != 200 {
		err = fmt.Errorf("get role name failed: %s %d", req.BuildRequestURL(), res.StatusCode)
		return
	}

	roleName = strings.TrimSpace(string(res.Body))
	return
}

func (provider *ECSRAMRoleCredentialsProvider) getCredentials() (session *sessionCredentials, err error) {
	roleName := provider.roleName
	if roleName == "" {
		roleName, err = provider.getRoleName()
		if err != nil {
			return
		}
	}

	req := &httputil.Request{
		Method:   "GET",
		Protocol: "http",
		Host:     "100.100.100.200",
		Path:     "/latest/meta-data/ram/security-credentials/" + roleName,
		Headers:  map[string]string{},
	}

	connectTimeout := 1 * time.Second
	readTimeout := 1 * time.Second

	if provider.httpOptions != nil && provider.httpOptions.ConnectTimeout > 0 {
		connectTimeout = time.Duration(provider.httpOptions.ConnectTimeout) * time.Millisecond
	}
	if provider.httpOptions != nil && provider.httpOptions.ReadTimeout > 0 {
		readTimeout = time.Duration(provider.httpOptions.ReadTimeout) * time.Millisecond
	}
	if provider.httpOptions != nil && provider.httpOptions.Proxy != "" {
		req.Proxy = provider.httpOptions.Proxy
	}
	req.ConnectTimeout = connectTimeout
	req.ReadTimeout = readTimeout

	metadataToken, err := provider.getMetadataToken()
	if err != nil {
		return nil, err
	}
	if metadataToken != "" {
		req.Headers["x-aliyun-ecs-metadata-token"] = metadataToken
	}

	res, err := httpDo(req)
	if err != nil {
		err = fmt.Errorf("refresh Ecs sts token err: %s", err.Error())
		return
	}

	if res.StatusCode != 200 {
		err = fmt.Errorf("refresh Ecs sts token err, httpStatus: %d, message = %s", res.StatusCode, string(res.Body))
		return
	}

	var data ecsRAMRoleResponse
	err = json.Unmarshal(res.Body, &data)
	if err != nil {
		err = fmt.Errorf("refresh Ecs sts token err, json.Unmarshal fail: %s", err.Error())
		return
	}

	if data.AccessKeyId == nil || data.AccessKeySecret == nil || data.SecurityToken == nil {
		err = fmt.Errorf("refresh Ecs sts token err, fail to get credentials")
		return
	}

	if *data.Code != "Success" {
		err = fmt.Errorf("refresh Ecs sts token err, Code is not Success")
		return
	}

	session = &sessionCredentials{
		AccessKeyId:     *data.AccessKeyId,
		AccessKeySecret: *data.AccessKeySecret,
		SecurityToken:   *data.SecurityToken,
		Expiration:      *data.Expiration,
	}
	return
}

func (provider *ECSRAMRoleCredentialsProvider) refreshCredentials() error {
	session, err := provider.getCredentials()
	if err != nil {
		return err
	}

	expirationTime, err := time.Parse("2006-01-02T15:04:05Z", session.Expiration)
	if err != nil {
		return err
	}

	provider.mu.Lock()
	provider.session = session
	provider.expirationTimestamp = expirationTime.Unix()
	provider.prefetchTimestamp = time.Now().Unix() + EcsPrefetchTimeSeconds
	provider.shouldRefresh = true
	provider.mu.Unlock()
	return nil
}

func (provider *ECSRAMRoleCredentialsProvider) GetCredentials() (cc *Credentials, err error) {
	provider.mu.Lock()
	needSync := provider.session == nil || provider.needUpdateCredential()
	needPrefetch := !needSync && provider.shouldPrefetchCredential()
	session := provider.session
	provider.mu.Unlock()

	if needSync {
		if err1 := provider.refreshCredentials(); err1 != nil {
			return nil, err1
		}
		provider.mu.Lock()
		session = provider.session
		provider.mu.Unlock()
	} else if needPrefetch {
		// Async prefetch: refresh in background, return current still-valid credentials.
		go func() {
			_ = provider.refreshCredentials()
		}()
	}

	cc = &Credentials{
		AccessKeyId:     session.AccessKeyId,
		AccessKeySecret: session.AccessKeySecret,
		SecurityToken:   session.SecurityToken,
		ProviderName:    provider.GetProviderName(),
	}
	return
}

func (provider *ECSRAMRoleCredentialsProvider) GetProviderName() string {
	return "ecs_ram_role"
}

func (provider *ECSRAMRoleCredentialsProvider) getMetadataToken() (metadataToken string, err error) {
	// PUT http://100.100.100.200/latest/api/token
	req := &httputil.Request{
		Method:   "PUT",
		Protocol: "http",
		Host:     "100.100.100.200",
		Path:     "/latest/api/token",
		Headers: map[string]string{
			"X-aliyun-ecs-metadata-token-ttl-seconds": strconv.Itoa(defaultMetadataTokenDuration),
		},
	}

	connectTimeout := 1 * time.Second
	readTimeout := 1 * time.Second

	if provider.httpOptions != nil && provider.httpOptions.ConnectTimeout > 0 {
		connectTimeout = time.Duration(provider.httpOptions.ConnectTimeout) * time.Millisecond
	}
	if provider.httpOptions != nil && provider.httpOptions.ReadTimeout > 0 {
		readTimeout = time.Duration(provider.httpOptions.ReadTimeout) * time.Millisecond
	}
	if provider.httpOptions != nil && provider.httpOptions.Proxy != "" {
		req.Proxy = provider.httpOptions.Proxy
	}
	req.ConnectTimeout = connectTimeout
	req.ReadTimeout = readTimeout

	res, _err := httpDo(req)
	if _err != nil {
		if provider.disableIMDSv1 {
			err = fmt.Errorf("get metadata token failed: %s", _err.Error())
		}
		return
	}
	if res.StatusCode != 200 {
		if provider.disableIMDSv1 {
			err = fmt.Errorf("refresh Ecs sts token err, httpStatus: %d, message = %s", res.StatusCode, string(res.Body))
		}
		return
	}
	metadataToken = string(res.Body)
	return
}
