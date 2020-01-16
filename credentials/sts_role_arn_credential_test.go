package credentials

import (
	"bytes"
	"errors"
	"io/ioutil"
	"net/http"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func mockResponse(statusCode int, content string, mockerr error) (res *http.Response, err error) {
	status := strconv.Itoa(statusCode)
	res = &http.Response{
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		Header:     map[string][]string{"sdk": []string{"test"}},
		StatusCode: statusCode,
		Status:     status + " " + http.StatusText(statusCode),
	}
	res.Body = ioutil.NopCloser(bytes.NewReader([]byte(content)))
	err = mockerr
	return
}

func Test_RoleArnCredential(t *testing.T) {
	auth := newRAMRoleArnCredential("accessKeyID", "accessKeySecret", "roleArn", "roleSessionName", "policy", 300, nil)
	origTestHookDo := hookDo
	defer func() { hookDo = origTestHookDo }()
	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(200, `{"Credentials":{"AccessKeyID":"accessKeyID","AccessKeySecret":"accessKeySecret","SecurityToken":"securitytoken","Expiration":"expiration"}}`, errors.New("Internal error"))
		}
	}
	accesskeyID, err := auth.GetAccessKeyId()
	assert.NotNil(t, err)
	assert.Equal(t, "[InvalidParam]:Assume Role session duration should be in the range of 15min - 1Hr", err.Error())
	assert.Equal(t, "", accesskeyID)

	accesskeySecret, err := auth.GetAccessKeySecret()
	assert.NotNil(t, err)
	assert.Equal(t, "[InvalidParam]:Assume Role session duration should be in the range of 15min - 1Hr", err.Error())
	assert.Equal(t, "", accesskeySecret)

	ststoken, err := auth.GetSecurityToken()
	assert.NotNil(t, err)
	assert.Equal(t, "[InvalidParam]:Assume Role session duration should be in the range of 15min - 1Hr", err.Error())
	assert.Equal(t, "", ststoken)

	assert.Equal(t, "", auth.GetBearerToken())
	assert.Equal(t, "ram_role_arn", auth.GetType())

	auth.RoleSessionExpiration = 1000
	accesskeyID, err = auth.GetAccessKeyId()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh RoleArn sts token err: Internal error", err.Error())
	assert.Equal(t, "", accesskeyID)

	auth.RoleSessionExpiration = 0
	accesskeyID, err = auth.GetAccessKeyId()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh RoleArn sts token err: Internal error", err.Error())
	assert.Equal(t, "", accesskeyID)

	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(300, ``, nil)
		}
	}
	accesskeyID, err = auth.GetAccessKeyId()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh RoleArn sts token err: httpStatus: 300, message = ", err.Error())
	assert.Equal(t, "", accesskeyID)

	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(200, `"Credentials":{"AccessKeyID":"accessKeyID","AccessKeySecret":"accessKeySecret","SecurityToken":"securitytoken","Expiration":"expiration"}}`, nil)
		}
	}
	accesskeyID, err = auth.GetAccessKeyId()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh RoleArn sts token err: Json.Unmarshal fail: invalid character ':' after top-level value", err.Error())
	assert.Equal(t, "", accesskeyID)

	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(200, `{"Credentials":{"AccessKeySecret":"accessKeySecret","SecurityToken":"securitytoken","Expiration":"expiration"}}`, nil)
		}
	}
	accesskeyID, err = auth.GetAccessKeyId()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh RoleArn sts token err: AccessKeyID: , AccessKeySecret: accessKeySecret, SecurityToken: securitytoken, Expiration: expiration", err.Error())
	assert.Equal(t, "", accesskeyID)

	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(200, `{}`, nil)
		}
	}
	accesskeyID, err = auth.GetAccessKeyId()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh RoleArn sts token err: Credentials is empty", err.Error())
	assert.Equal(t, "", accesskeyID)

	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(200, `{"Credentials":{"AccessKeyID":"accessKeyID","AccessKeySecret":"accessKeySecret","SecurityToken":"securitytoken","Expiration":"2020-01-02T15:04:05Z"}}`, nil)
		}
	}
	accesskeyID, err = auth.GetAccessKeyId()
	assert.Nil(t, err)
	assert.Equal(t, "accessKeyID", accesskeyID)

	accesskeySecret, err = auth.GetAccessKeySecret()
	assert.Nil(t, err)
	assert.Equal(t, "accessKeySecret", accesskeySecret)

	ststoken, err = auth.GetSecurityToken()
	assert.Nil(t, err)
	assert.Equal(t, "securitytoken", ststoken)
}
