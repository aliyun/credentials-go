package credentials

import (
	"bytes"
	"errors"
	"io/ioutil"
	"net/http"
	"strconv"
	"testing"

	"github.com/aliyun/credentials-go/credentials/utils"
	"github.com/stretchr/testify/assert"
)

func mockResponse(statusCode int, content string, mockerr error) (res *http.Response, err error) {
	status := strconv.Itoa(statusCode)
	res = &http.Response{
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		Header:     map[string][]string{"sdk": {"test"}},
		StatusCode: statusCode,
		Status:     status + " " + http.StatusText(statusCode),
	}
	res.Body = ioutil.NopCloser(bytes.NewReader([]byte(content)))
	err = mockerr
	return
}

func Test_RoleArnCredential(t *testing.T) {
	auth := newRAMRoleArnCredential("accessKeyId", "accessKeySecret", "roleArn", "roleSessionName", "policy", 300, nil)
	origTestHookDo := hookDo
	defer func() { hookDo = origTestHookDo }()
	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(200, `{"Credentials":{"AccessKeyId":"accessKeyId","AccessKeySecret":"accessKeySecret","SecurityToken":"securitytoken","Expiration":"expiration"}}`, errors.New("Internal error"))
		}
	}
	accesskeyId, err := auth.GetAccessKeyId()
	assert.NotNil(t, err)
	assert.Equal(t, "[InvalidParam]:Assume Role session duration should be in the range of 15min - 1Hr", err.Error())
	assert.Nil(t, accesskeyId)

	accesskeySecret, err := auth.GetAccessKeySecret()
	assert.NotNil(t, err)
	assert.Equal(t, "[InvalidParam]:Assume Role session duration should be in the range of 15min - 1Hr", err.Error())
	assert.Nil(t, accesskeySecret)

	ststoken, err := auth.GetSecurityToken()
	assert.NotNil(t, err)
	assert.Equal(t, "[InvalidParam]:Assume Role session duration should be in the range of 15min - 1Hr", err.Error())
	assert.Nil(t, ststoken)

	assert.Equal(t, "", *auth.GetBearerToken())
	assert.Equal(t, "ram_role_arn", *auth.GetType())

	auth.RoleSessionExpiration = 1000
	accesskeyId, err = auth.GetAccessKeyId()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh RoleArn sts token err: Internal error", err.Error())
	assert.Nil(t, accesskeyId)

	auth.RoleSessionExpiration = 0
	accesskeyId, err = auth.GetAccessKeyId()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh RoleArn sts token err: Internal error", err.Error())
	assert.Nil(t, accesskeyId)

	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(300, ``, nil)
		}
	}
	accesskeyId, err = auth.GetAccessKeyId()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh RoleArn sts token err: httpStatus: 300, message = ", err.Error())
	assert.Nil(t, accesskeyId)

	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(200, `"Credentials":{"AccessKeyId":"accessKeyId","AccessKeySecret":"accessKeySecret","SecurityToken":"securitytoken","Expiration":"expiration"}}`, nil)
		}
	}
	accesskeyId, err = auth.GetAccessKeyId()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh RoleArn sts token err: Json.Unmarshal fail: invalid character ':' after top-level value", err.Error())
	assert.Nil(t, accesskeyId)

	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(200, `{"Credentials":{"AccessKeySecret":"accessKeySecret","SecurityToken":"securitytoken","Expiration":"expiration"}}`, nil)
		}
	}
	accesskeyId, err = auth.GetAccessKeyId()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh RoleArn sts token err: AccessKeyId: , AccessKeySecret: accessKeySecret, SecurityToken: securitytoken, Expiration: expiration", err.Error())
	assert.Nil(t, accesskeyId)

	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(200, `{}`, nil)
		}
	}
	accesskeyId, err = auth.GetAccessKeyId()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh RoleArn sts token err: Credentials is empty", err.Error())
	assert.Nil(t, accesskeyId)

	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(200, `{"Credentials":{"AccessKeyId":"accessKeyId","AccessKeySecret":"accessKeySecret","SecurityToken":"securitytoken","Expiration":"2020-01-02T15:04:05Z"}}`, nil)
		}
	}
	accesskeyId, err = auth.GetAccessKeyId()
	assert.Nil(t, err)
	assert.Equal(t, "accessKeyId", *accesskeyId)

	accesskeySecret, err = auth.GetAccessKeySecret()
	assert.Nil(t, err)
	assert.Equal(t, "accessKeySecret", *accesskeySecret)

	ststoken, err = auth.GetSecurityToken()
	assert.Nil(t, err)
	assert.Equal(t, "securitytoken", *ststoken)

	cred, err := auth.GetCredential()
	assert.Nil(t, err)
	assert.Equal(t, "accessKeyId", *cred.AccessKeyId)
	assert.Equal(t, "accessKeySecret", *cred.AccessKeySecret)
	assert.Equal(t, "securitytoken", *cred.SecurityToken)
	assert.Nil(t, cred.BearerToken)
	assert.Equal(t, "ram_role_arn", *cred.Type)

	auth = newRAMRoleArnCredential("accessKeyId", "accessKeySecret", "roleArn", "roleSessionName", "policy", 3600, &utils.Runtime{STSEndpoint: "www.aliyun.com"})
	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			assert.Equal(t, "www.aliyun.com", req.Host)
			return mockResponse(200, `{}`, nil)
		}
	}
	accesskeyId, err = auth.GetAccessKeyId()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh RoleArn sts token err: Credentials is empty", err.Error())
	assert.Nil(t, accesskeyId)

	auth = newRAMRoleArnWithExternalIdCredential("accessKeyId", "accessKeySecret", "roleArn", "roleSessionName", "policy", 3600, "externalId", nil)
	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(200, `{"Credentials":{"AccessKeyId":"accessKeyId","AccessKeySecret":"accessKeySecret","SecurityToken":"securitytoken","Expiration":"2020-01-02T15:04:05Z"}}`, nil)
		}
	}
	accesskeyId, err = auth.GetAccessKeyId()
	assert.Nil(t, err)
	assert.Equal(t, "accessKeyId", *accesskeyId)

	accesskeySecret, err = auth.GetAccessKeySecret()
	assert.Nil(t, err)
	assert.Equal(t, "accessKeySecret", *accesskeySecret)

	ststoken, err = auth.GetSecurityToken()
	assert.Nil(t, err)
	assert.Equal(t, "securitytoken", *ststoken)
}

func TestStsRoleARNCredentialsProviderWithSecurityToken(t *testing.T) {
	auth := newRAMRoleArnl("accessKeyId", "accessKeySecret", "securityToken", "roleArn", "roleSessionName", "policy", 3600, "externalId", nil)
	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			assert.Equal(t, "securityToken", req.URL.Query().Get("SecurityToken"))
			return mockResponse(200, `{"Credentials":{"AccessKeyId":"accessKeyId","AccessKeySecret":"accessKeySecret","SecurityToken":"securitytoken","Expiration":"2020-01-02T15:04:05Z"}}`, nil)
		}
	}

	_, err := auth.GetCredential()
	assert.Nil(t, err)
}
