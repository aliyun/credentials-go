package credentials

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_getDurationSeconds(t *testing.T) {
	// valid seconds
	s, err := getDurationSeconds(1000)
	assert.Nil(t, err)
	assert.Equal(t, "1000", s)
	// default value
	s, err = getDurationSeconds(0)
	assert.Nil(t, err)
	assert.Equal(t, "3600", s)

	// invalid seconds
	_, err = getDurationSeconds(100)
	assert.NotNil(t, err)
	assert.Equal(t, "[InvalidParam]:Assume Role session duration should be in the range of 15min - 1hr", err.Error())
}

func TestNewRAMRoleArnCredentialsProviderOptions(t *testing.T) {
	o := NewRAMRoleArnCredentialsProviderOptions().
		SetAccessKeyId("akid").
		SetAccessKeySecret("aksecret").
		SetSecurityToken("st").
		SetRoleArn("ra").
		SetRoleSessionName("rsn").
		SetPolicy("policy").
		SetRoleSessionExpiration(600).
		SetRuntime(nil).
		SetExternalId("externalid")
	assert.Equal(t, "akid", o.AccessKeyId)
	assert.Equal(t, "aksecret", o.AccessKeySecret)
	assert.Equal(t, "st", o.SecurityToken)
	assert.Equal(t, "ra", o.RoleArn)
	assert.Equal(t, "rsn", o.RoleSessionName)
	assert.Equal(t, "policy", o.Policy)
	assert.Equal(t, 600, o.RoleSessionExpiration)
	assert.Nil(t, o.runtime)
	assert.Equal(t, "externalid", o.ExternalId)
}

func TestNewRAMRoleArnCredentialsProvider(t *testing.T) {
	p := NewRAMRoleArnCredentialsProvider(NewRAMRoleArnCredentialsProviderOptions())
	assert.NotNil(t, p)
}

func TestProviderGetType(t *testing.T) {
	p := NewRAMRoleArnCredentialsProvider(NewRAMRoleArnCredentialsProviderOptions())
	assert.Equal(t, "ram_role_arn", *p.GetType())
}

func TestProviderGetBearerToken(t *testing.T) {
	p := NewRAMRoleArnCredentialsProvider(NewRAMRoleArnCredentialsProviderOptions())
	assert.Equal(t, "", *p.GetBearerToken())
}

func mockResponse(statusCode int, content string, mockerr error) (res *http.Response, err error) {
	status := strconv.Itoa(statusCode)
	res = &http.Response{
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		Header:     map[string][]string{"sdk": {"test"}},
		StatusCode: statusCode,
		Status:     status + " " + http.StatusText(statusCode),
	}
	res.Body = io.NopCloser(bytes.NewReader([]byte(content)))
	err = mockerr
	return
}

func TestGetCredential(t *testing.T) {
	origTestHookDo := hookDo
	expirationTime := time.Now().Add(600).Format("2006-01-02T15:04:05Z")
	defer func() { hookDo = origTestHookDo }()
	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(200, fmt.Sprintf(`{"Credentials":{"AccessKeyId":"accessKeyId","AccessKeySecret":"accessKeySecret","SecurityToken":"securitytoken","Expiration":"%s"}}`, expirationTime), nil)
		}
	}
	p := NewRAMRoleArnCredentialsProvider(NewRAMRoleArnCredentialsProviderOptions())
	c, err := p.GetCredential()
	assert.Nil(t, err)
	assert.Equal(t, "accessKeyId", *c.AccessKeyId)
	assert.Equal(t, "accessKeySecret", *c.AccessKeySecret)
	assert.Equal(t, "securitytoken", *c.SecurityToken)
	assert.Equal(t, "ram_role_arn", *c.Type)

	akid, err := p.GetAccessKeyId()
	assert.Nil(t, err)
	assert.Equal(t, "accessKeyId", *akid)
	aksecret, err := p.GetAccessKeySecret()
	assert.Nil(t, err)
	assert.Equal(t, "accessKeySecret", *aksecret)
	securityToken, err := p.GetSecurityToken()
	assert.Nil(t, err)
	assert.Equal(t, "securitytoken", *securityToken)
}

func TestGetCredentialWithSTSEndpoint(t *testing.T) {
	origTestHookDo := hookDo
	expirationTime := time.Now().Add(600).Format("2006-01-02T15:04:05Z")
	defer func() { hookDo = origTestHookDo }()
	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(200, fmt.Sprintf(`{"Credentials":{"AccessKeyId":"accessKeyId","AccessKeySecret":"accessKeySecret","SecurityToken":"securitytoken","Expiration":"%s"}}`, expirationTime), nil)
		}
	}
	p := NewRAMRoleArnCredentialsProvider(
		NewRAMRoleArnCredentialsProviderOptions().
			SetSecurityToken("sts"))
	c, err := p.GetCredential()
	assert.Nil(t, err)
	assert.Equal(t, "accessKeyId", *c.AccessKeyId)
	assert.Equal(t, "accessKeySecret", *c.AccessKeySecret)
	assert.Equal(t, "securitytoken", *c.SecurityToken)
	assert.Equal(t, "ram_role_arn", *c.Type)

	akid, err := p.GetAccessKeyId()
	assert.Nil(t, err)
	assert.Equal(t, "accessKeyId", *akid)
	aksecret, err := p.GetAccessKeySecret()
	assert.Nil(t, err)
	assert.Equal(t, "accessKeySecret", *aksecret)
	securityToken, err := p.GetSecurityToken()
	assert.Nil(t, err)
	assert.Equal(t, "securitytoken", *securityToken)
}

// func TestGetCredential(t *testing.T) {
// 	origTestHookDo := hookDo
// 	expirationTime := time.Now().Add(600).Format("2006-01-02T15:04:05Z")
// 	defer func() { hookDo = origTestHookDo }()
// 	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
// 		return func(req *http.Request) (*http.Response, error) {
// 			return mockResponse(200, fmt.Sprintf(`{"Credentials":{"AccessKeyId":"accessKeyId","AccessKeySecret":"accessKeySecret","SecurityToken":"securitytoken","Expiration":"%s"}}`, expirationTime), nil)
// 		}
// 	}
// 	p := NewRAMRoleArnCredentialsProvider(NewRAMRoleArnCredentialsProviderOptions())
// 	c, err := p.GetCredential()
// 	assert.Nil(t, err)
// 	assert.Equal(t, "accessKeyId", *c.AccessKeyId)
// 	assert.Equal(t, "accessKeySecret", *c.AccessKeySecret)
// 	assert.Equal(t, "securitytoken", *c.SecurityToken)
// 	assert.Equal(t, "ram_role_arn", *c.Type)

// 	akid, err := p.GetAccessKeyId()
// 	assert.Nil(t, err)
// 	assert.Equal(t, "accessKeyId", *akid)
// 	aksecret, err := p.GetAccessKeySecret()
// 	assert.Nil(t, err)
// 	assert.Equal(t, "accessKeySecret", *aksecret)
// 	securityToken, err := p.GetSecurityToken()
// 	assert.Nil(t, err)
// 	assert.Equal(t, "securitytoken", *securityToken)
// }

func TestRAMRoleArnCredentialsProvider(t *testing.T) {
	// auth := newRAMRoleArnCredential("accessKeyId", "accessKeySecret", "roleArn", "roleSessionName", "policy", 300, nil)
	// origTestHookDo := hookDo
	// defer func() { hookDo = origTestHookDo }()
	// hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
	// 	return func(req *http.Request) (*http.Response, error) {
	// 		return mockResponse(200, `{"Credentials":{"AccessKeyId":"accessKeyId","AccessKeySecret":"accessKeySecret","SecurityToken":"securitytoken","Expiration":"expiration"}}`, errors.New("Internal error"))
	// 	}
	// }
	// accesskeyId, err := auth.GetAccessKeyId()
	// assert.NotNil(t, err)
	// assert.Equal(t, "[InvalidParam]:Assume Role session duration should be in the range of 15min - 1Hr", err.Error())
	// assert.Equal(t, "", *accesskeyId)

	// accesskeySecret, err := auth.GetAccessKeySecret()
	// assert.NotNil(t, err)
	// assert.Equal(t, "[InvalidParam]:Assume Role session duration should be in the range of 15min - 1Hr", err.Error())
	// assert.Equal(t, "", *accesskeySecret)

	// ststoken, err := auth.GetSecurityToken()
	// assert.NotNil(t, err)
	// assert.Equal(t, "[InvalidParam]:Assume Role session duration should be in the range of 15min - 1Hr", err.Error())
	// assert.Equal(t, "", *ststoken)

	// assert.Equal(t, "", *auth.GetBearerToken())
	// assert.Equal(t, "ram_role_arn", *auth.GetType())

	// auth.RoleSessionExpiration = 1000
	// accesskeyId, err = auth.GetAccessKeyId()
	// assert.NotNil(t, err)
	// assert.Equal(t, "refresh RoleArn sts token err: Internal error", err.Error())
	// assert.Equal(t, "", *accesskeyId)

	// auth.RoleSessionExpiration = 0
	// accesskeyId, err = auth.GetAccessKeyId()
	// assert.NotNil(t, err)
	// assert.Equal(t, "refresh RoleArn sts token err: Internal error", err.Error())
	// assert.Equal(t, "", *accesskeyId)

	// hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
	// 	return func(req *http.Request) (*http.Response, error) {
	// 		return mockResponse(300, ``, nil)
	// 	}
	// }
	// accesskeyId, err = auth.GetAccessKeyId()
	// assert.NotNil(t, err)
	// assert.Equal(t, "refresh RoleArn sts token err: httpStatus: 300, message = ", err.Error())
	// assert.Equal(t, "", *accesskeyId)

	// hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
	// 	return func(req *http.Request) (*http.Response, error) {
	// 		return mockResponse(200, `"Credentials":{"AccessKeyId":"accessKeyId","AccessKeySecret":"accessKeySecret","SecurityToken":"securitytoken","Expiration":"expiration"}}`, nil)
	// 	}
	// }
	// accesskeyId, err = auth.GetAccessKeyId()
	// assert.NotNil(t, err)
	// assert.Equal(t, "refresh RoleArn sts token err: Json.Unmarshal fail: invalid character ':' after top-level value", err.Error())
	// assert.Equal(t, "", *accesskeyId)

	// hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
	// 	return func(req *http.Request) (*http.Response, error) {
	// 		return mockResponse(200, `{"Credentials":{"AccessKeySecret":"accessKeySecret","SecurityToken":"securitytoken","Expiration":"expiration"}}`, nil)
	// 	}
	// }
	// accesskeyId, err = auth.GetAccessKeyId()
	// assert.NotNil(t, err)
	// assert.Equal(t, "refresh RoleArn sts token err: AccessKeyId: , AccessKeySecret: accessKeySecret, SecurityToken: securitytoken, Expiration: expiration", err.Error())
	// assert.Equal(t, "", *accesskeyId)

	// hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
	// 	return func(req *http.Request) (*http.Response, error) {
	// 		return mockResponse(200, `{}`, nil)
	// 	}
	// }
	// accesskeyId, err = auth.GetAccessKeyId()
	// assert.NotNil(t, err)
	// assert.Equal(t, "refresh RoleArn sts token err: Credentials is empty", err.Error())
	// assert.Equal(t, "", *accesskeyId)

	// hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
	// 	return func(req *http.Request) (*http.Response, error) {
	// 		return mockResponse(200, `{"Credentials":{"AccessKeyId":"accessKeyId","AccessKeySecret":"accessKeySecret","SecurityToken":"securitytoken","Expiration":"2020-01-02T15:04:05Z"}}`, nil)
	// 	}
	// }
	// accesskeyId, err = auth.GetAccessKeyId()
	// assert.Nil(t, err)
	// assert.Equal(t, "accessKeyId", *accesskeyId)

	// accesskeySecret, err = auth.GetAccessKeySecret()
	// assert.Nil(t, err)
	// assert.Equal(t, "accessKeySecret", *accesskeySecret)

	// ststoken, err = auth.GetSecurityToken()
	// assert.Nil(t, err)
	// assert.Equal(t, "securitytoken", *ststoken)

	// cred, err := auth.GetCredential()
	// assert.Nil(t, err)
	// assert.Equal(t, "accessKeyId", *cred.AccessKeyId)
	// assert.Equal(t, "accessKeySecret", *cred.AccessKeySecret)
	// assert.Equal(t, "securitytoken", *cred.SecurityToken)
	// assert.Nil(t, cred.BearerToken)
	// assert.Equal(t, "ram_role_arn", *cred.Type)

	// auth = newRAMRoleArnCredential("accessKeyId", "accessKeySecret", "roleArn", "roleSessionName", "policy", 3600, &utils.Runtime{STSEndpoint: "www.aliyun.com"})
	// hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
	// 	return func(req *http.Request) (*http.Response, error) {
	// 		assert.Equal(t, "www.aliyun.com", req.Host)
	// 		return mockResponse(200, `{}`, nil)
	// 	}
	// }
	// accesskeyId, err = auth.GetAccessKeyId()
	// assert.NotNil(t, err)
	// assert.Equal(t, "refresh RoleArn sts token err: Credentials is empty", err.Error())
	// assert.Equal(t, "", *accesskeyId)
}
