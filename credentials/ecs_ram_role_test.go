package credentials

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/alibabacloud-go/tea/tea"
	"github.com/stretchr/testify/assert"
)

func Test_EcsRAmRoleCredential(t *testing.T) {
	auth := newEcsRAMRoleCredential("go sdk", 0.5, nil)
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
	assert.Equal(t, "", *accesskeyId)

	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(300, ``, nil)
		}
	}
	accesskeyId, err = auth.GetAccessKeyId()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh Ecs sts token err: httpStatus: 300, message = ", err.Error())
	assert.Equal(t, "", *accesskeyId)

	accesskeySecret, err := auth.GetAccessKeySecret()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh Ecs sts token err: httpStatus: 300, message = ", err.Error())
	assert.Equal(t, "", *accesskeySecret)

	ststoken, err := auth.GetSecurityToken()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh Ecs sts token err: httpStatus: 300, message = ", err.Error())
	assert.Equal(t, "", *ststoken)

	assert.Equal(t, "", *auth.GetBearerToken())

	assert.Equal(t, "ecs_ram_role", *auth.GetType())

	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(400, `role`, nil)
		}
	}
	auth.RoleName = ""
	accesskeyId, err = auth.GetAccessKeyId()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh Ecs sts token err: httpStatus: 400, message = role", err.Error())

	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(200, `role`, nil)
		}
	}
	accesskeyId, err = auth.GetAccessKeyId()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh Ecs sts token err: Json Unmarshal fail: invalid character 'r' looking for beginning of value", err.Error())
	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(200, `"AccessKeyId":"accessKeyId","AccessKeySecret":"accessKeySecret","SecurityToken":"securitytoken","Expiration":"expiration"`, nil)
		}
	}
	auth.RoleName = "role"
	accesskeyId, err = auth.GetAccessKeyId()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh Ecs sts token err: Json Unmarshal fail: invalid character ':' after top-level value", err.Error())
	assert.Equal(t, "", *accesskeyId)

	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(200, `{"AccessKeySecret":"accessKeySecret","SecurityToken":"securitytoken","Expiration":"expiration","Code":"fail"}`, nil)
		}
	}
	accesskeyId, err = auth.GetAccessKeyId()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh Ecs sts token err: Code is not Success", err.Error())
	assert.Equal(t, "", *accesskeyId)

	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(200, `{"AccessKeySecret":"accessKeySecret","SecurityToken":"securitytoken","Expiration":"expiration","Code":"Success"}`, nil)
		}
	}
	accesskeyId, err = auth.GetAccessKeyId()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh Ecs sts token err: AccessKeyId: , AccessKeySecret: accessKeySecret, SecurityToken: securitytoken, Expiration: expiration", err.Error())
	assert.Equal(t, "", *accesskeyId)

	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(200, `{"AccessKeyId":"accessKeyId","AccessKeySecret":"accessKeySecret","SecurityToken":"securitytoken","Expiration":"2018-01-02T15:04:05Z","Code":"Success"}`, nil)
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

	err = errors.New("credentials")
	err = hookParse(err)
	assert.Equal(t, "credentials", err.Error())

	originHookParse := hookParse
	hookParse = func(err error) error {
		return errors.New("error parse")
	}
	defer func() {
		hookParse = originHookParse
	}()
	accesskeyId, err = auth.GetAccessKeyId()
	assert.Equal(t, "refresh Ecs sts token err: error parse", err.Error())
	assert.Equal(t, "", *accesskeyId)
}

func Test_inAdvance(t *testing.T) {
	origTestHookDo := hookDo
	defer func() { hookDo = origTestHookDo }()
	config := Config{
		Type:           tea.String("ecs_ram_role"),
		RoleName:       tea.String("test-role"),
		InAdvanceScale: tea.Float64(0.001),
	}
	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(200, `{"AccessKeyId":"accessKeyId","AccessKeySecret":"accessKeySecret","SecurityToken":"securitytoken","Expiration":"2018-01-02T15:04:05Z", "code":"Success"}`, nil)
		}
	}
	credential, err := NewCredential(&config)
	assert.Nil(t, err)
	accessKeyId, err := credential.GetAccessKeyId()
	assert.Nil(t, err)
	assert.Equal(t, "accessKeyId", *accessKeyId)

	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(300, `{"AccessKeyId":"test"}`, errors.New("hello"))
		}
	}
	// request err, old credential expired, return nil string
	accessKeyId, err = credential.GetAccessKeyId()
	assert.NotNil(t, err)
	assert.Equal(t, "", *accessKeyId)

	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			expirationTime := time.Now().Unix() + 60
			t := time.Unix(expirationTime, 0).UTC()
			expiration := t.Format("2006-01-02T15:04:05Z")
			return mockResponse(200, `{"AccessKeyId":"accessKeyId1","AccessKeySecret":"accessKeySecret1","SecurityToken":"securitytoken1",`+`"Expiration":`+`"`+expiration+`"`+","+`"code":"Success"}`, nil)
		}
	}
	accessKeyId1, err := credential.GetAccessKeyId()
	assert.Nil(t, err)
	assert.Equal(t, "accessKeyId1", *accessKeyId1)

	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(300, ``, errors.New("request fail"))
		}
	}
	// request fail,old credential not expired, return old credential
	accessKeyId1, err = credential.GetAccessKeyId()
	assert.Nil(t, err)
	assert.Equal(t, "accessKeyId1", *accessKeyId1)
}
