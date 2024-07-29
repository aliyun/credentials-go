package credentials

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"time"

	"github.com/alibabacloud-go/tea/tea"
	"github.com/aliyun/credentials-go/credentials/request"
	"github.com/aliyun/credentials-go/credentials/utils"
)

// OIDCCredential is a kind of credentials
type OIDCCredentialsProvider struct {
	*credentialUpdater
	AccessKeyId           string
	AccessKeySecret       string
	RoleArn               string
	OIDCProviderArn       string
	OIDCTokenFilePath     string
	Policy                string
	RoleSessionName       string
	RoleSessionExpiration int
	sessionCredential     *sessionCredential
	runtime               *utils.Runtime
}

type OIDCResponse struct {
	Credentials *credentialsInResponse `json:"Credentials" xml:"Credentials"`
}

type OIDCcredentialsInResponse struct {
	AccessKeyId     string `json:"AccessKeyId" xml:"AccessKeyId"`
	AccessKeySecret string `json:"AccessKeySecret" xml:"AccessKeySecret"`
	SecurityToken   string `json:"SecurityToken" xml:"SecurityToken"`
	Expiration      string `json:"Expiration" xml:"Expiration"`
}

func newOIDCRoleArnCredential(accessKeyId, accessKeySecret, roleArn, OIDCProviderArn, OIDCTokenFilePath, RoleSessionName, policy string, RoleSessionExpiration int, runtime *utils.Runtime) (provider *OIDCCredentialsProvider, err error) {
	if OIDCTokenFilePath == "" {
		OIDCTokenFilePath = os.Getenv("ALIBABA_CLOUD_OIDC_TOKEN_FILE")
	}

	if OIDCTokenFilePath == "" {
		err = errors.New("the OIDC token file path is empty")
		return
	}

	provider = &OIDCCredentialsProvider{
		AccessKeyId:           accessKeyId,
		AccessKeySecret:       accessKeySecret,
		RoleArn:               roleArn,
		OIDCProviderArn:       OIDCProviderArn,
		OIDCTokenFilePath:     OIDCTokenFilePath,
		RoleSessionName:       RoleSessionName,
		Policy:                policy,
		RoleSessionExpiration: RoleSessionExpiration,
		credentialUpdater:     new(credentialUpdater),
		runtime:               runtime,
	}
	return
}

func (e *OIDCCredentialsProvider) GetCredential() (*CredentialModel, error) {
	if e.sessionCredential == nil || e.needUpdateCredential() {
		err := e.updateCredential()
		if err != nil {
			return nil, err
		}
	}
	credential := &CredentialModel{
		AccessKeyId:     tea.String(e.sessionCredential.AccessKeyId),
		AccessKeySecret: tea.String(e.sessionCredential.AccessKeySecret),
		SecurityToken:   tea.String(e.sessionCredential.SecurityToken),
		Type:            tea.String("oidc_role_arn"),
	}
	return credential, nil
}

// GetAccessKeyId reutrns OIDCCredential's AccessKeyId
// if AccessKeyId is not exist or out of date, the function will update it.
func (r *OIDCCredentialsProvider) GetAccessKeyId() (accessKeyId *string, err error) {
	c, err := r.GetCredential()
	if err != nil {
		return
	}

	accessKeyId = c.AccessKeyId
	return
}

// GetAccessSecret reutrns OIDCCredential's AccessKeySecret
// if AccessKeySecret is not exist or out of date, the function will update it.
func (r *OIDCCredentialsProvider) GetAccessKeySecret() (accessKeySecret *string, err error) {
	c, err := r.GetCredential()
	if err != nil {
		return
	}

	accessKeySecret = c.AccessKeySecret
	return
}

// GetSecurityToken reutrns OIDCCredential's SecurityToken
// if SecurityToken is not exist or out of date, the function will update it.
func (r *OIDCCredentialsProvider) GetSecurityToken() (securityToken *string, err error) {
	c, err := r.GetCredential()
	if err != nil {
		return
	}

	securityToken = c.SecurityToken
	return
}

// GetBearerToken is useless OIDCCredential
func (r *OIDCCredentialsProvider) GetBearerToken() *string {
	return tea.String("")
}

// GetType reutrns OIDCCredential's type
func (r *OIDCCredentialsProvider) GetType() *string {
	return tea.String("oidc_role_arn")
}

var getFileContent = func(filePath string) (content string, err error) {
	bytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return
	}

	if len(bytes) == 0 {
		err = fmt.Errorf("the content of %s is empty", filePath)
	}

	content = string(bytes)
	return
}

func (r *OIDCCredentialsProvider) updateCredential() (err error) {
	if r.runtime == nil {
		r.runtime = new(utils.Runtime)
	}
	request := request.NewCommonRequest()
	request.Domain = "sts.aliyuncs.com"
	if r.runtime.STSEndpoint != "" {
		request.Domain = r.runtime.STSEndpoint
	}
	request.Scheme = "HTTPS"
	request.Method = "POST"
	request.QueryParams["Timestamp"] = utils.GetTimeInFormatISO8601()
	request.QueryParams["Action"] = "AssumeRoleWithOIDC"
	request.QueryParams["Format"] = "JSON"
	request.BodyParams["RoleArn"] = r.RoleArn
	request.BodyParams["OIDCProviderArn"] = r.OIDCProviderArn
	token, err := getFileContent(r.OIDCTokenFilePath)
	if err != nil {
		return fmt.Errorf("read oidc token file failed: %s", err.Error())
	}

	request.BodyParams["OIDCToken"] = token
	if r.Policy != "" {
		request.QueryParams["Policy"] = r.Policy
	}
	if r.RoleSessionExpiration > 0 {
		request.QueryParams["DurationSeconds"] = strconv.Itoa(r.RoleSessionExpiration)
	}
	request.QueryParams["RoleSessionName"] = r.RoleSessionName
	request.QueryParams["Version"] = "2015-04-01"
	request.QueryParams["SignatureNonce"] = utils.GetUUID()
	request.Headers["Host"] = request.Domain
	request.Headers["Accept-Encoding"] = "identity"
	request.Headers["content-type"] = "application/x-www-form-urlencoded"
	request.URL = request.BuildURL()
	content, err := doAction(request, r.runtime)
	if err != nil {
		return fmt.Errorf("get sts token failed with: %s", err.Error())
	}
	var resp *OIDCResponse
	err = json.Unmarshal(content, &resp)
	if err != nil {
		return fmt.Errorf("get sts token failed with: Json.Unmarshal fail: %s", err.Error())
	}
	if resp == nil || resp.Credentials == nil {
		return fmt.Errorf("get sts token failed with: credentials is empty")
	}
	respCredentials := resp.Credentials
	if respCredentials.AccessKeyId == "" || respCredentials.AccessKeySecret == "" || respCredentials.SecurityToken == "" || respCredentials.Expiration == "" {
		return fmt.Errorf("get sts token failed with: AccessKeyId: %s, AccessKeySecret: %s, SecurityToken: %s, Expiration: %s", respCredentials.AccessKeyId, respCredentials.AccessKeySecret, respCredentials.SecurityToken, respCredentials.Expiration)
	}

	expirationTime, err := time.Parse("2006-01-02T15:04:05Z", respCredentials.Expiration)
	r.lastUpdateTimestamp = time.Now().Unix()
	r.credentialExpiration = int(expirationTime.Unix() - time.Now().Unix())
	r.sessionCredential = &sessionCredential{
		AccessKeyId:     respCredentials.AccessKeyId,
		AccessKeySecret: respCredentials.AccessKeySecret,
		SecurityToken:   respCredentials.SecurityToken,
	}

	return
}
