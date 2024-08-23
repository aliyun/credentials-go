package providers

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	httputil "github.com/aliyun/credentials-go/credentials/internal/http"
	"github.com/aliyun/credentials-go/credentials/internal/utils"
)

type ECSRAMRoleCredentialsProvider struct {
	roleName                     string
	metadataTokenDurationSeconds int
	enableIMDSv2                 bool
	runtime                      *utils.Runtime
	// for sts
	session             *sessionCredentials
	expirationTimestamp int64
}

type ECSRAMRoleCredentialsProviderBuilder struct {
	provider *ECSRAMRoleCredentialsProvider
}

func NewECSRAMRoleCredentialsProviderBuilder() *ECSRAMRoleCredentialsProviderBuilder {
	return &ECSRAMRoleCredentialsProviderBuilder{
		provider: &ECSRAMRoleCredentialsProvider{
			// TBD: 默认启用 IMDS v2
			// enableIMDSv2: os.Getenv("ALIBABA_CLOUD_IMDSV2_DISABLED") != "true", // 默认启用 v2
		},
	}
}

func (builder *ECSRAMRoleCredentialsProviderBuilder) WithMetadataTokenDurationSeconds(metadataTokenDurationSeconds int) *ECSRAMRoleCredentialsProviderBuilder {
	builder.provider.metadataTokenDurationSeconds = metadataTokenDurationSeconds
	return builder
}

func (builder *ECSRAMRoleCredentialsProviderBuilder) WithRoleName(roleName string) *ECSRAMRoleCredentialsProviderBuilder {
	builder.provider.roleName = roleName
	return builder
}

func (builder *ECSRAMRoleCredentialsProviderBuilder) WithEnableIMDSv2(enableIMDSv2 bool) *ECSRAMRoleCredentialsProviderBuilder {
	builder.provider.enableIMDSv2 = enableIMDSv2
	return builder
}

const defaultMetadataTokenDuration = 21600 // 6 hours

func (builder *ECSRAMRoleCredentialsProviderBuilder) Build() (provider *ECSRAMRoleCredentialsProvider, err error) {
	// 设置 roleName 默认值
	if builder.provider.roleName == "" {
		builder.provider.roleName = os.Getenv("ALIBABA_CLOUD_ECS_METADATA")
	}

	if builder.provider.metadataTokenDurationSeconds == 0 {
		builder.provider.metadataTokenDurationSeconds = defaultMetadataTokenDuration
	}

	if builder.provider.metadataTokenDurationSeconds < 1 || builder.provider.metadataTokenDurationSeconds > 21600 {
		err = errors.New("the metadata token duration seconds must be 1-21600")
		return
	}

	builder.provider.runtime = &utils.Runtime{
		ConnectTimeout: 5,
		ReadTimeout:    5,
	}

	provider = builder.provider
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
	if provider.expirationTimestamp == 0 {
		return true
	}

	return provider.expirationTimestamp-time.Now().Unix() <= 180
}

func (provider *ECSRAMRoleCredentialsProvider) getRoleName() (roleName string, err error) {
	req := &httputil.Request{
		Method:         "GET",
		Protocol:       "http",
		Host:           "100.100.100.200",
		Path:           "/latest/meta-data/ram/security-credentials/",
		ConnectTimeout: 5 * time.Second,
		ReadTimeout:    5 * time.Second,
		Headers:        map[string]string{},
	}

	if provider.enableIMDSv2 {
		metadataToken, err := provider.getMetadataToken()
		if err != nil {
			return "", err
		}
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
		Method:         "GET",
		Protocol:       "http",
		Host:           "100.100.100.200",
		Path:           "/latest/meta-data/ram/security-credentials/" + roleName,
		ConnectTimeout: 5 * time.Second,
		ReadTimeout:    5 * time.Second,
		Headers:        map[string]string{},
	}

	if provider.enableIMDSv2 {
		metadataToken, err := provider.getMetadataToken()
		if err != nil {
			return nil, err
		}
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

func (provider *ECSRAMRoleCredentialsProvider) GetCredentials() (cc *Credentials, err error) {
	if provider.session == nil || provider.needUpdateCredential() {
		session, err1 := provider.getCredentials()
		if err1 != nil {
			return nil, err1
		}

		provider.session = session
		expirationTime, err2 := time.Parse("2006-01-02T15:04:05Z", session.Expiration)
		if err2 != nil {
			return nil, err2
		}
		provider.expirationTimestamp = expirationTime.Unix()
	}

	cc = &Credentials{
		AccessKeyId:     provider.session.AccessKeyId,
		AccessKeySecret: provider.session.AccessKeySecret,
		SecurityToken:   provider.session.SecurityToken,
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
			"X-aliyun-ecs-metadata-token-ttl-seconds": strconv.Itoa(provider.metadataTokenDurationSeconds),
		},
		ConnectTimeout: 5 * time.Second,
		ReadTimeout:    5 * time.Second,
	}
	res, err := httpDo(req)
	if err != nil {
		err = fmt.Errorf("get metadata token failed: %s", err.Error())
		return
	}
	metadataToken = string(res.Body)
	return
}
