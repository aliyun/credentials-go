package credentials

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestURLCredentialsProvider_updateCredential(t *testing.T) {
	provider := newURLCredential("http://127.0.0.1")

	origTestHookDo := hookDo
	defer func() { hookDo = origTestHookDo }()
	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(300, ``, errors.New("sdk test"))
		}
	}

	cred, err := provider.GetCredential()
	assert.NotNil(t, err)
	assert.Equal(t, "get credentials from http://127.0.0.1 failed with error: sdk test", err.Error())
	assert.Nil(t, cred)

	_, err = provider.GetAccessKeyId()
	assert.NotNil(t, err)
	assert.Equal(t, "get credentials from http://127.0.0.1 failed with error: sdk test", err.Error())

	_, err = provider.GetAccessKeySecret()
	assert.NotNil(t, err)
	assert.Equal(t, "get credentials from http://127.0.0.1 failed with error: sdk test", err.Error())

	_, err = provider.GetSecurityToken()
	assert.NotNil(t, err)
	assert.Equal(t, "get credentials from http://127.0.0.1 failed with error: sdk test", err.Error())

	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(200, `invalid json`, nil)
		}
	}

	cred, err = provider.GetCredential()
	assert.NotNil(t, err)
	assert.Equal(t, "get credentials from http://127.0.0.1 failed with error, json unmarshal fail: invalid character 'i' looking for beginning of value", err.Error())
	assert.Nil(t, cred)

	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(200, `{}`, nil)
		}
	}

	cred, err = provider.GetCredential()
	assert.NotNil(t, err)
	assert.Equal(t, "get credentials failed: AccessKeyId: , AccessKeySecret: , SecurityToken: , Expiration: ", err.Error())
	assert.Nil(t, cred)

	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(200, `{"AccessKeyId":"akid", "AccessKeySecret":"aksecret","SecurityToken":"sts","Expiration":"2006-01-02T15:04:05Z"}`, nil)
		}
	}

	cred, err = provider.GetCredential()
	assert.Nil(t, err)
	assert.NotNil(t, cred)
	assert.Equal(t, "akid", *cred.AccessKeyId)
	assert.Equal(t, "aksecret", *cred.AccessKeySecret)
	assert.Equal(t, "sts", *cred.SecurityToken)

	akid, err := provider.GetAccessKeyId()
	assert.Nil(t, err)
	assert.Equal(t, "akid", *akid)

	aksecret, err := provider.GetAccessKeySecret()
	assert.Nil(t, err)
	assert.Equal(t, "aksecret", *aksecret)

	sts, err := provider.GetSecurityToken()
	assert.Nil(t, err)
	assert.Equal(t, "sts", *sts)
}

func TestURLCredentialsProviderGetBearerToken(t *testing.T) {
	provider := newURLCredential("http://127.0.0.1")
	assert.Equal(t, "", *provider.GetBearerToken())
}

func TestURLCredentialsProviderGetType(t *testing.T) {
	provider := newURLCredential("http://127.0.0.1")
	assert.Equal(t, "credential_uri", *provider.GetType())
}
