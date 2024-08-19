package providers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aliyun/credentials-go/credentials/internal/utils"
	"github.com/aliyun/credentials-go/credentials/request"
)

const securityCredURL = "http://100.100.100.200/latest/meta-data/ram/security-credentials/"
const apiTokenURL = "http://100.100.100.200/latest/api/token"

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
	httpRequest, err := hookNewRequest(http.NewRequest)("GET", securityCredURL, strings.NewReader(""))
	if err != nil {
		err = fmt.Errorf("get role name failed: %s", err.Error())
		return
	}

	if provider.enableIMDSv2 {
		metadataToken, err := provider.getMetadataToken()
		if err != nil {
			return "", err
		}
		httpRequest.Header.Set("x-aliyun-ecs-metadata-token", metadataToken)
	}

	httpClient := &http.Client{
		Timeout: 5 * time.Second,
	}
	httpResponse, err := hookDo(httpClient.Do)(httpRequest)
	if err != nil {
		err = fmt.Errorf("get role name failed: %s", err.Error())
		return
	}

	if httpResponse.StatusCode != http.StatusOK {
		err = fmt.Errorf("get role name failed: request %s %d", securityCredURL, httpResponse.StatusCode)
		return
	}

	defer httpResponse.Body.Close()

	responseBody, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return
	}

	roleName = strings.TrimSpace(string(responseBody))
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

	requestUrl := securityCredURL + roleName
	httpRequest, err := hookNewRequest(http.NewRequest)("GET", requestUrl, strings.NewReader(""))
	if err != nil {
		err = fmt.Errorf("refresh Ecs sts token err: %s", err.Error())
		return
	}

	if provider.enableIMDSv2 {
		metadataToken, err := provider.getMetadataToken()
		if err != nil {
			return nil, err
		}
		httpRequest.Header.Set("x-aliyun-ecs-metadata-token", metadataToken)
	}

	httpClient := &http.Client{
		Timeout: 5 * time.Second,
	}
	httpResponse, err := hookDo(httpClient.Do)(httpRequest)
	if err != nil {
		err = fmt.Errorf("refresh Ecs sts token err: %s", err.Error())
		return
	}

	defer httpResponse.Body.Close()

	responseBody, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return
	}

	if httpResponse.StatusCode != http.StatusOK {
		err = fmt.Errorf("refresh Ecs sts token err, httpStatus: %d, message = %s", httpResponse.StatusCode, string(responseBody))
		return
	}

	var data ecsRAMRoleResponse
	err = json.Unmarshal(responseBody, &data)
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
	request := request.NewCommonRequest()
	request.URL = apiTokenURL
	request.Method = "PUT"
	request.Headers["X-aliyun-ecs-metadata-token-ttl-seconds"] = strconv.Itoa(provider.metadataTokenDurationSeconds)
	content, err := doAction(request, provider.runtime)
	if err != nil {
		err = fmt.Errorf("get metadata token failed: %s", err.Error())
		return
	}
	metadataToken = string(content)
	return
}
