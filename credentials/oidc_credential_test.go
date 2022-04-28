package credentials

import (
	"errors"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_oidcCredential_updateCredential(t *testing.T) {
	oidcCredential := newOIDCRoleArnCredential("accessKeyId", "accessKeySecret", "RoleArn", "OIDCProviderArn", "tokenFilePath", "roleSessionName", "Policy", 3600, nil)
	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(300, ``, errors.New("sdk test"))
		}
	}
	accesskeyId, err := oidcCredential.GetAccessKeyId()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh RoleArn sts token err: sdk test", err.Error())
	assert.Equal(t, "", *accesskeyId)

	assert.Equal(t, "oidc_role_arn", *oidcCredential.GetType())

	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(200, `{"Credentials":{"AccessKeyId":"accessKeyId","AccessKeySecret":"accessKeySecret","SecurityToken":"securitytoken","Expiration":"2020-01-02T15:04:05Z"}}`, nil)
		}
	}
	accesskeyId, err = oidcCredential.GetAccessKeyId()
	assert.Nil(t, err)
	assert.Equal(t, "accessKeyId", *accesskeyId)

	accesskeySecret, err := oidcCredential.GetAccessKeySecret()
	assert.Nil(t, err)
	assert.Equal(t, "accessKeySecret", *accesskeySecret)

	ststoken, err := oidcCredential.GetSecurityToken()
	assert.Nil(t, err)
	assert.Equal(t, "securitytoken", *ststoken)

	os.Setenv("ALIBABA_CLOUD_OIDC_TOKEN_FILE", "")
	token := oidcCredential.GetOIDCToken("/test")
	assert.Nil(t, token)
	path, _ := os.Getwd()
	os.Setenv("ALIBABA_CLOUD_OIDC_TOKEN_FILE", path+"/oidc_token")
	token = oidcCredential.GetOIDCToken("/test")
	assert.Equal(t, "test_long_oidc_token_eyJhbGciOiJSUzI1NiIsImtpZCI6ImFQaXlpNEVGSU8wWnlGcFh1V0psQUNWbklZVlJsUkNmM2tlSzNMUlhWT1UifQ.eyJhdWQiOlsic3RzLmFsaXl1bmNzLmNvbSJdLCJleHAiOjE2NDUxMTk3ODAsImlhdCI6MTY0NTA4Mzc4MCwiaXNzIjoiaHR0cHM6Ly9vaWRjLWFjay1jbi1oYW5nemhvdS5vc3MtY24taGFuZ3pob3UtaW50ZXJuYWwuYWxpeXVuY3MuY29tL2NmMWQ4ZGIwMjM0ZDk0YzEyOGFiZDM3MTc4NWJjOWQxNSIsImt1YmVybmV0ZXMuaW8iOnsibmFtZXNwYWNlIjoidGVzdC1ycnNhIiwicG9kIjp7Im5hbWUiOiJydW4tYXMtcm9vdCIsInVpZCI6ImIzMGI0MGY2LWNiZTAtNGY0Yy1hZGYyLWM1OGQ4ZmExZTAxMCJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoidXNlcjEiLCJ1aWQiOiJiZTEyMzdjYS01MTY4LTQyMzYtYWUyMC00NDM1YjhmMGI4YzAifX0sIm5iZiI6MTY0NTA4Mzc4MCwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OnRlc3QtcnJzYTp1c2VyMSJ9.XGP-wgLj-iMiAHjLe0lZLh7y48Qsj9HzsEbNh706WwerBoxnssdsyGFb9lzd2FyM8CssbAOCstr7OuAMWNdJmDZgpiOGGSbQ-KXXmbfnIS4ix-V3pQF6LVBFr7xJlj20J6YY89um3rv_04t0iCGxKWs2ZMUyU1FbZpIPRep24LVKbUz1saiiVGgDBTIZdHA13Z-jUvYAnsxK_Kj5tc1K-IuQQU0IwSKJh5OShMcdPugMV5LwTL3ogCikfB7yljq5vclBhCeF2lXLIibvwF711TOhuJ5lMlh-a2KkIgwBHhANg_U9k4Mt_VadctfUGc4hxlSbBD0w9o9mDGKwgGmW5Q", *token)
	os.Setenv("ALIBABA_CLOUD_OIDC_TOKEN_FILE", "")
	token = oidcCredential.GetOIDCToken(path + "/oidc_token")
	assert.Equal(t, 1027, len(*token))
	assert.Equal(t, "test_long_oidc_token_eyJhbGciOiJSUzI1NiIsImtpZCI6ImFQaXlpNEVGSU8wWnlGcFh1V0psQUNWbklZVlJsUkNmM2tlSzNMUlhWT1UifQ.eyJhdWQiOlsic3RzLmFsaXl1bmNzLmNvbSJdLCJleHAiOjE2NDUxMTk3ODAsImlhdCI6MTY0NTA4Mzc4MCwiaXNzIjoiaHR0cHM6Ly9vaWRjLWFjay1jbi1oYW5nemhvdS5vc3MtY24taGFuZ3pob3UtaW50ZXJuYWwuYWxpeXVuY3MuY29tL2NmMWQ4ZGIwMjM0ZDk0YzEyOGFiZDM3MTc4NWJjOWQxNSIsImt1YmVybmV0ZXMuaW8iOnsibmFtZXNwYWNlIjoidGVzdC1ycnNhIiwicG9kIjp7Im5hbWUiOiJydW4tYXMtcm9vdCIsInVpZCI6ImIzMGI0MGY2LWNiZTAtNGY0Yy1hZGYyLWM1OGQ4ZmExZTAxMCJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoidXNlcjEiLCJ1aWQiOiJiZTEyMzdjYS01MTY4LTQyMzYtYWUyMC00NDM1YjhmMGI4YzAifX0sIm5iZiI6MTY0NTA4Mzc4MCwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OnRlc3QtcnJzYTp1c2VyMSJ9.XGP-wgLj-iMiAHjLe0lZLh7y48Qsj9HzsEbNh706WwerBoxnssdsyGFb9lzd2FyM8CssbAOCstr7OuAMWNdJmDZgpiOGGSbQ-KXXmbfnIS4ix-V3pQF6LVBFr7xJlj20J6YY89um3rv_04t0iCGxKWs2ZMUyU1FbZpIPRep24LVKbUz1saiiVGgDBTIZdHA13Z-jUvYAnsxK_Kj5tc1K-IuQQU0IwSKJh5OShMcdPugMV5LwTL3ogCikfB7yljq5vclBhCeF2lXLIibvwF711TOhuJ5lMlh-a2KkIgwBHhANg_U9k4Mt_VadctfUGc4hxlSbBD0w9o9mDGKwgGmW5Q", *token)
}
