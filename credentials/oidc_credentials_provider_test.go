package credentials

import (
	"errors"
	"net/http"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aliyun/credentials-go/credentials/internal/utils"
)

func TestNewOidcCredentialsProvider(t *testing.T) {
	_, err := newOIDCRoleArnCredential("accessKeyId", "accessKeySecret", "RoleArn", "OIDCProviderArn", "", "roleSessionName", "Policy", 3600, nil)
	assert.NotNil(t, err)
	assert.Equal(t, "the OIDC token file path is empty", err.Error())

	// get oidc token path from env
	os.Setenv("ALIBABA_CLOUD_OIDC_TOKEN_FILE", "/path/to/oidc_token")
	provider, err := newOIDCRoleArnCredential("accessKeyId", "accessKeySecret", "RoleArn", "OIDCProviderArn", "", "roleSessionName", "Policy", 3600, nil)
	assert.Nil(t, err)
	assert.Equal(t, "/path/to/oidc_token", provider.OIDCTokenFilePath)

	os.Unsetenv("ALIBABA_CLOUD_OIDC_TOKEN_FILE")
	provider, err = newOIDCRoleArnCredential("accessKeyId", "accessKeySecret", "RoleArn", "OIDCProviderArn", "/path/to/oidc_token_args", "roleSessionName", "Policy", 3600, nil)
	assert.Nil(t, err)
	assert.Equal(t, "/path/to/oidc_token_args", provider.OIDCTokenFilePath)
}

func Test_oidcCredential_updateCredential(t *testing.T) {
	oidcCredential, err := newOIDCRoleArnCredential("accessKeyId", "accessKeySecret", "RoleArn", "OIDCProviderArn", "/path/to/tokenFilePath", "roleSessionName", "Policy", 3600, nil)
	assert.Nil(t, err)

	c, err := oidcCredential.GetCredential()
	assert.NotNil(t, err)
	assert.Equal(t, "read oidc token file failed: open /path/to/tokenFilePath: no such file or directory", err.Error())
	assert.Nil(t, c)

	accessKeyId, err := oidcCredential.GetAccessKeyId()
	assert.NotNil(t, err)
	assert.Equal(t, "read oidc token file failed: open /path/to/tokenFilePath: no such file or directory", err.Error())
	assert.Nil(t, accessKeyId)

	accessKeySecret, err := oidcCredential.GetAccessKeySecret()
	assert.NotNil(t, err)
	assert.Equal(t, "read oidc token file failed: open /path/to/tokenFilePath: no such file or directory", err.Error())
	assert.Nil(t, accessKeySecret)

	securityToken, err := oidcCredential.GetSecurityToken()
	assert.NotNil(t, err)
	assert.Equal(t, "read oidc token file failed: open /path/to/tokenFilePath: no such file or directory", err.Error())
	assert.Nil(t, securityToken)

	originGetFileContent := getFileContent
	defer func() {
		getFileContent = originGetFileContent
	}()
	getFileContent = func(filePath string) (content string, err error) {
		return "token", nil
	}
	// mock server error
	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(500, ``, errors.New("mock server error"))
		}
	}
	c, err = oidcCredential.GetCredential()
	assert.NotNil(t, err)
	assert.Equal(t, "get sts token failed with: mock server error", err.Error())
	assert.Nil(t, c)
	// mock unmarshal error
	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(200, `invalid json`, nil)
		}
	}
	c, err = oidcCredential.GetCredential()
	assert.NotNil(t, err)
	assert.Equal(t, "get sts token failed with: Json.Unmarshal fail: invalid character 'i' looking for beginning of value", err.Error())
	assert.Nil(t, c)

	// mock null response
	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(200, `null`, nil)
		}
	}
	c, err = oidcCredential.GetCredential()
	assert.NotNil(t, err)
	assert.Equal(t, "get sts token failed with: credentials is empty", err.Error())
	assert.Nil(t, c)

	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(200, `{}`, nil)
		}
	}
	c, err = oidcCredential.GetCredential()
	assert.NotNil(t, err)
	assert.Equal(t, "get sts token failed with: credentials is empty", err.Error())
	assert.Nil(t, c)

	// mock empty ak
	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(200, `{"Credentials": {}}`, nil)
		}
	}
	c, err = oidcCredential.GetCredential()
	assert.NotNil(t, err)
	assert.Equal(t, "get sts token failed with: AccessKeyId: , AccessKeySecret: , SecurityToken: , Expiration: ", err.Error())
	assert.Nil(t, c)

	// mock normal credentials
	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(200, `{"Credentials": {"AccessKeyId":"akid","AccessKeySecret":"aksecret","SecurityToken":"ststoken","Expiration":"2006-01-02T15:04:05Z"}}`, nil)
		}
	}
	c, err = oidcCredential.GetCredential()
	assert.Nil(t, err)
	assert.NotNil(t, c)
	assert.Equal(t, "akid", *c.AccessKeyId)
	assert.Equal(t, "aksecret", *c.AccessKeySecret)
	assert.Equal(t, "ststoken", *c.SecurityToken)

	akid, err := oidcCredential.GetAccessKeyId()
	assert.Nil(t, err)
	assert.Equal(t, "akid", *akid)

	secret, err := oidcCredential.GetAccessKeySecret()
	assert.Nil(t, err)
	assert.Equal(t, "aksecret", *secret)

	ststoken, err := oidcCredential.GetSecurityToken()
	assert.Nil(t, err)
	assert.Equal(t, "ststoken", *ststoken)
}

func TestOIDCCredentialsProviderGetBearerToken(t *testing.T) {
	provider, err := newOIDCRoleArnCredential("accessKeyId", "accessKeySecret", "RoleArn", "OIDCProviderArn", "tokenFilePath", "roleSessionName", "Policy", 3600, nil)
	assert.Nil(t, err)
	assert.Equal(t, "", *provider.GetBearerToken())
}

func TestOIDCCredentialsProviderGetType(t *testing.T) {
	provider, err := newOIDCRoleArnCredential("accessKeyId", "accessKeySecret", "RoleArn", "OIDCProviderArn", "tokenFilePath", "roleSessionName", "Policy", 3600, nil)
	assert.Nil(t, err)
	assert.Equal(t, "oidc_role_arn", *provider.GetType())
}

func Test_getFileContent(t *testing.T) {
	wd, _ := os.Getwd()
	// read a normal token
	token, err := getFileContent(path.Join(wd, "../test_fixtures/oidc_token"))
	assert.Nil(t, err)
	assert.Equal(t, "test_long_oidc_token_eyJhbGciOiJSUzI1NiIsImtpZCI6ImFQaXlpNEVGSU8wWnlGcFh1V0psQUNWbklZVlJsUkNmM2tlSzNMUlhWT1UifQ.eyJhdWQiOlsic3RzLmFsaXl1bmNzLmNvbSJdLCJleHAiOjE2NDUxMTk3ODAsImlhdCI6MTY0NTA4Mzc4MCwiaXNzIjoiaHR0cHM6Ly9vaWRjLWFjay1jbi1oYW5nemhvdS5vc3MtY24taGFuZ3pob3UtaW50ZXJuYWwuYWxpeXVuY3MuY29tL2NmMWQ4ZGIwMjM0ZDk0YzEyOGFiZDM3MTc4NWJjOWQxNSIsImt1YmVybmV0ZXMuaW8iOnsibmFtZXNwYWNlIjoidGVzdC1ycnNhIiwicG9kIjp7Im5hbWUiOiJydW4tYXMtcm9vdCIsInVpZCI6ImIzMGI0MGY2LWNiZTAtNGY0Yy1hZGYyLWM1OGQ4ZmExZTAxMCJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoidXNlcjEiLCJ1aWQiOiJiZTEyMzdjYS01MTY4LTQyMzYtYWUyMC00NDM1YjhmMGI4YzAifX0sIm5iZiI6MTY0NTA4Mzc4MCwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OnRlc3QtcnJzYTp1c2VyMSJ9.XGP-wgLj-iMiAHjLe0lZLh7y48Qsj9HzsEbNh706WwerBoxnssdsyGFb9lzd2FyM8CssbAOCstr7OuAMWNdJmDZgpiOGGSbQ-KXXmbfnIS4ix-V3pQF6LVBFr7xJlj20J6YY89um3rv_04t0iCGxKWs2ZMUyU1FbZpIPRep24LVKbUz1saiiVGgDBTIZdHA13Z-jUvYAnsxK_Kj5tc1K-IuQQU0IwSKJh5OShMcdPugMV5LwTL3ogCikfB7yljq5vclBhCeF2lXLIibvwF711TOhuJ5lMlh-a2KkIgwBHhANg_U9k4Mt_VadctfUGc4hxlSbBD0w9o9mDGKwgGmW5Q", token)

	// read a empty token
	_, err = getFileContent(path.Join(wd, "../test_fixtures/empty_oidc_token"))
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "the content of ")
	assert.Contains(t, err.Error(), "/test_fixtures/empty_oidc_token is empty")

	// read a inexist token
	_, err = getFileContent(path.Join(wd, "../test_fixtures/inexist_oidc_token"))
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "no such file or directory")
}

func TestSTSEndpoint(t *testing.T) {
	originGetFileContent := getFileContent
	defer func() {
		getFileContent = originGetFileContent
	}()
	getFileContent = func(filePath string) (content string, err error) {
		return "token", nil
	}
	// mock server error
	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			assert.Equal(t, "sts.cn-beijing.aliyuncs.com", req.Host)
			return mockResponse(500, ``, errors.New("mock server error"))
		}
	}

	runtime := &utils.Runtime{
		STSEndpoint: "sts.cn-beijing.aliyuncs.com",
	}
	provider, err := newOIDCRoleArnCredential("accessKeyId", "accessKeySecret", "RoleArn", "OIDCProviderArn", "tokenFilePath", "roleSessionName", "Policy", 3600, runtime)
	assert.Nil(t, err)
	c, err := provider.GetCredential()
	assert.NotNil(t, err)
	assert.Equal(t, "get sts token failed with: mock server error", err.Error())
	assert.Nil(t, c)
}
