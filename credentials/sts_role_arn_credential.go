package credentials

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/alibabacloud-go/tea/tea"
	"github.com/aliyun/credentials-go/credentials/request"
	"github.com/aliyun/credentials-go/credentials/utils"
)

const defaultDurationSeconds = 3600

func getDurationSeconds(roleSessionExpiration int) (string, error) {
	if roleSessionExpiration > 0 {
		if roleSessionExpiration >= 900 && roleSessionExpiration <= 3600 {
			return strconv.Itoa(roleSessionExpiration), nil
		} else {
			return "", errors.New("[InvalidParam]:Assume Role session duration should be in the range of 15min - 1hr")
		}
	}

	return strconv.Itoa(defaultDurationSeconds), nil
}

type RAMRoleArnCredentialsProvider struct {
	*credentialUpdater
	sessionCredential *sessionCredential
	options           *RAMRoleArnCredentialsProviderOptions
}

// Deprecated: GetAccessKeyId is deprecated, use GetCredential instead of.
func (p *RAMRoleArnCredentialsProvider) GetAccessKeyId() (accessKeyId *string, err error) {
	c, err := p.GetCredential()
	if err != nil {
		return
	}

	accessKeyId = c.AccessKeyId
	return
}

// Deprecated: GetAccessKeySecret is deprecated, use GetCredential instead of.
func (p *RAMRoleArnCredentialsProvider) GetAccessKeySecret() (accessKeySecret *string, err error) {
	c, err := p.GetCredential()
	if err != nil {
		return
	}

	accessKeySecret = c.AccessKeySecret
	return
}

// Deprecated: GetSecurityToken is deprecated, use GetCredential instead of.
func (p *RAMRoleArnCredentialsProvider) GetSecurityToken() (securityToken *string, err error) {
	c, err := p.GetCredential()
	if err != nil {
		return
	}

	securityToken = c.SecurityToken
	return
}

// GetBearerToken is useless for RamRoleArnCredential
func (p *RAMRoleArnCredentialsProvider) GetBearerToken() *string {
	return tea.String("")
}

// GetType reutrns provider type
func (p *RAMRoleArnCredentialsProvider) GetType() *string {
	return tea.String("ram_role_arn")
}

func (p *RAMRoleArnCredentialsProvider) GetCredential() (*CredentialModel, error) {
	if p.sessionCredential == nil || p.needUpdateCredential() {
		err := p.updateCredential()
		if err != nil {
			return nil, err
		}
	}
	credential := &CredentialModel{
		AccessKeyId:     tea.String(p.sessionCredential.AccessKeyId),
		AccessKeySecret: tea.String(p.sessionCredential.AccessKeySecret),
		SecurityToken:   tea.String(p.sessionCredential.SecurityToken),
		Type:            tea.String("ram_role_arn"),
	}
	return credential, nil
}

func NewRAMRoleArnCredentialsProvider(options *RAMRoleArnCredentialsProviderOptions) *RAMRoleArnCredentialsProvider {
	return &RAMRoleArnCredentialsProvider{
		credentialUpdater: new(credentialUpdater),
		options:           options,
	}
}

type RAMRoleArnCredentialsProviderOptions struct {
	AccessKeyId           string
	AccessKeySecret       string
	SecurityToken         string
	RoleArn               string
	RoleSessionName       string
	RoleSessionExpiration int
	Policy                string
	ExternalId            string
	runtime               *utils.Runtime
}

func NewRAMRoleArnCredentialsProviderOptions() *RAMRoleArnCredentialsProviderOptions {
	return &RAMRoleArnCredentialsProviderOptions{}
}

func (o *RAMRoleArnCredentialsProviderOptions) SetAccessKeyId(accessKeyId string) *RAMRoleArnCredentialsProviderOptions {
	o.AccessKeyId = accessKeyId
	return o
}

func (c *RAMRoleArnCredentialsProviderOptions) SetAccessKeySecret(accessKeyId string) *RAMRoleArnCredentialsProviderOptions {
	c.AccessKeySecret = accessKeyId
	return c
}

func (c *RAMRoleArnCredentialsProviderOptions) SetSecurityToken(securityToken string) *RAMRoleArnCredentialsProviderOptions {
	c.SecurityToken = securityToken
	return c
}

func (c *RAMRoleArnCredentialsProviderOptions) SetRoleArn(roleArn string) *RAMRoleArnCredentialsProviderOptions {
	c.RoleArn = roleArn
	return c
}

func (c *RAMRoleArnCredentialsProviderOptions) SetRoleSessionName(roleSessionName string) *RAMRoleArnCredentialsProviderOptions {
	c.RoleSessionName = roleSessionName
	return c
}

func (c *RAMRoleArnCredentialsProviderOptions) SetPolicy(policy string) *RAMRoleArnCredentialsProviderOptions {
	c.Policy = policy
	return c
}

func (c *RAMRoleArnCredentialsProviderOptions) SetRoleSessionExpiration(roleSessionExpiration int) *RAMRoleArnCredentialsProviderOptions {
	c.RoleSessionExpiration = roleSessionExpiration
	return c
}

func (c *RAMRoleArnCredentialsProviderOptions) SetRuntime(runtime *utils.Runtime) *RAMRoleArnCredentialsProviderOptions {
	c.runtime = runtime
	return c
}

func (c *RAMRoleArnCredentialsProviderOptions) SetExternalId(externalId string) *RAMRoleArnCredentialsProviderOptions {
	c.ExternalId = externalId
	return c
}

func (p *RAMRoleArnCredentialsProvider) updateCredential() (err error) {
	options := p.options
	if options.runtime == nil {
		options.runtime = new(utils.Runtime)
	}
	request := request.NewCommonRequest()
	request.Domain = "sts.aliyuncs.com"
	if options.runtime.STSEndpoint != "" {
		request.Domain = options.runtime.STSEndpoint
	}
	request.Scheme = "HTTPS"
	request.Method = "GET"
	request.QueryParams["AccessKeyId"] = options.AccessKeyId
	if options.SecurityToken != "" {
		request.QueryParams["SecurityToken"] = options.SecurityToken
	}
	request.QueryParams["Action"] = "AssumeRole"
	request.QueryParams["Format"] = "JSON"
	durationSeconds, err := getDurationSeconds(options.RoleSessionExpiration)
	if err != nil {
		return
	}

	request.QueryParams["DurationSeconds"] = durationSeconds
	request.QueryParams["RoleArn"] = options.RoleArn
	if options.Policy != "" {
		request.QueryParams["Policy"] = options.Policy
	}
	if options.ExternalId != "" {
		request.QueryParams["ExternalId"] = options.ExternalId
	}
	request.QueryParams["RoleSessionName"] = options.RoleSessionName
	request.QueryParams["SignatureMethod"] = "HMAC-SHA1"
	request.QueryParams["SignatureVersion"] = "1.0"
	request.QueryParams["Version"] = "2015-04-01"
	request.QueryParams["Timestamp"] = utils.GetTimeInFormatISO8601()
	request.QueryParams["SignatureNonce"] = utils.GetUUID()
	signature := utils.ShaHmac1(request.BuildStringToSign(), options.AccessKeySecret+"&")
	request.QueryParams["Signature"] = signature
	request.Headers["Host"] = request.Domain
	request.Headers["Accept-Encoding"] = "identity"
	request.URL = request.BuildURL()
	content, err := doAction(request, options.runtime)
	if err != nil {
		return fmt.Errorf("refresh RoleArn sts token err: %s", err.Error())
	}
	var resp *ramRoleArnResponse
	err = json.Unmarshal(content, &resp)
	if err != nil {
		return fmt.Errorf("refresh RoleArn sts token err: Json.Unmarshal fail: %s", err.Error())
	}
	if resp == nil || resp.Credentials == nil {
		return fmt.Errorf("refresh RoleArn sts token err: Credentials is empty")
	}
	respCredentials := resp.Credentials
	if respCredentials.AccessKeyId == "" || respCredentials.AccessKeySecret == "" || respCredentials.SecurityToken == "" || respCredentials.Expiration == "" {
		return fmt.Errorf("refresh RoleArn sts token err: AccessKeyId: %s, AccessKeySecret: %s, SecurityToken: %s, Expiration: %s", respCredentials.AccessKeyId, respCredentials.AccessKeySecret, respCredentials.SecurityToken, respCredentials.Expiration)
	}

	expirationTime, err := time.Parse("2006-01-02T15:04:05Z", respCredentials.Expiration)
	p.lastUpdateTimestamp = time.Now().Unix()
	p.credentialExpiration = int(expirationTime.Unix() - time.Now().Unix())
	p.sessionCredential = &sessionCredential{
		AccessKeyId:     respCredentials.AccessKeyId,
		AccessKeySecret: respCredentials.AccessKeySecret,
		SecurityToken:   respCredentials.SecurityToken,
	}

	return
}

type ramRoleArnResponse struct {
	Credentials *credentialsInResponse `json:"Credentials" xml:"Credentials"`
}

type credentialsInResponse struct {
	AccessKeyId     string `json:"AccessKeyId" xml:"AccessKeyId"`
	AccessKeySecret string `json:"AccessKeySecret" xml:"AccessKeySecret"`
	SecurityToken   string `json:"SecurityToken" xml:"SecurityToken"`
	Expiration      string `json:"Expiration" xml:"Expiration"`
}
