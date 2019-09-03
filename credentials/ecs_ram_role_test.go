package credentials

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_EcsRAmRoleCredential(t *testing.T) {
	auth := newEcsRamRoleCredential("go sdk", nil)
	origTestHookDo := hookDo
	defer func() { hookDo = origTestHookDo }()

	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(300, ``, errors.New("sdk test"))
		}
	}
	accesskeyId, err := auth.GetAccessKeyId()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh Ecs sts token err: sdk test", err.Error())
	assert.Equal(t, "", accesskeyId)

	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(300, ``, nil)
		}
	}
	accesskeyId, err = auth.GetAccessKeyId()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh Ecs sts token err: httpStatus: 300, message = ", err.Error())
	assert.Equal(t, "", accesskeyId)

	accesskeySecret, err := auth.GetAccessSecret()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh Ecs sts token err: httpStatus: 300, message = ", err.Error())
	assert.Equal(t, "", accesskeySecret)

	ststoken, err := auth.GetSecurityToken()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh Ecs sts token err: httpStatus: 300, message = ", err.Error())
	assert.Equal(t, "", ststoken)

	assert.Equal(t, "", auth.GetBearerToken())

	assert.Equal(t, "ecs_ram_role", auth.GetType())

	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(200, `"AccessKeyId":"accessKeyId","AccessKeySecret":"accessKeySecret","SecurityToken":"securitytoken","Expiration":"expiration"}`, nil)
		}
	}
	accesskeyId, err = auth.GetAccessKeyId()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh Ecs sts token err: Json.Unmarshal fail: invalid character ':' after top-level value", err.Error())
	assert.Equal(t, "", accesskeyId)

	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(200, `{"AccessKeySecret":"accessKeySecret","SecurityToken":"securitytoken","Expiration":"expiration","Code":"fail"}`, nil)
		}
	}
	accesskeyId, err = auth.GetAccessKeyId()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh Ecs sts token err: Code is not Success", err.Error())
	assert.Equal(t, "", accesskeyId)

	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(200, `{"AccessKeySecret":"accessKeySecret","SecurityToken":"securitytoken","Expiration":"expiration","Code":"Success"}`, nil)
		}
	}
	accesskeyId, err = auth.GetAccessKeyId()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh Ecs sts token err: AccessKeyId: <nil>, AccessKeySecret: accessKeySecret, SecurityToken: securitytoken, Expiration: expiration", err.Error())
	assert.Equal(t, "", accesskeyId)

	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(200, `{"AccessKeyId":"accessKeyId","AccessKeySecret":"accessKeySecret","SecurityToken":"securitytoken","Expiration":"2020-01-02T15:04:05Z","Code":"Success"}`, nil)
		}
	}
	accesskeyId, err = auth.GetAccessKeyId()
	assert.Nil(t, err)
	assert.Equal(t, "accessKeyId", accesskeyId)

	accesskeySecret, err = auth.GetAccessSecret()
	assert.Nil(t, err)
	assert.Equal(t, "accessKeySecret", accesskeySecret)

	ststoken, err = auth.GetSecurityToken()
	assert.Nil(t, err)
	assert.Equal(t, "securitytoken", ststoken)
}
