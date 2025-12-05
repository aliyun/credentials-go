package providers

import (
	"errors"
	"strings"
	"testing"
	"time"

	httputil "github.com/aliyun/credentials-go/credentials/internal/http"
	"github.com/stretchr/testify/assert"
)

// contains is a helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

func TestNewCloudSSOCredentialsProvider(t *testing.T) {

	_, err := NewCloudSSOCredentialsProviderBuilder().Build()
	assert.NotNil(t, err)
	assert.Equal(t, "CloudSSO access token is empty or expired, please re-login with cli", err.Error())

	_, err = NewCloudSSOCredentialsProviderBuilder().WithAccessToken("token").Build()
	assert.NotNil(t, err)
	assert.Equal(t, "CloudSSO access token is empty or expired, please re-login with cli", err.Error())

	_, err = NewCloudSSOCredentialsProviderBuilder().
		WithAccessToken("token").
		WithAccessTokenExpire(time.Now().Unix() + 1000).
		Build()
	assert.NotNil(t, err)
	assert.Equal(t, "CloudSSO sign in url or account id or access config is empty", err.Error())

	_, err = NewCloudSSOCredentialsProviderBuilder().
		WithAccessToken("token").
		WithAccessTokenExpire(time.Now().Unix() + 1000).
		WithSignInUrl("https://signin.aliyun.com").
		Build()
	assert.NotNil(t, err)
	assert.Equal(t, "CloudSSO sign in url or account id or access config is empty", err.Error())

	_, err = NewCloudSSOCredentialsProviderBuilder().
		WithAccessToken("token").
		WithAccessTokenExpire(time.Now().Unix() + 1000).
		WithSignInUrl("https://signin.aliyun.com").
		WithAccountId("123456").
		Build()
	assert.NotNil(t, err)
	assert.Equal(t, "CloudSSO sign in url or account id or access config is empty", err.Error())

	p, err := NewCloudSSOCredentialsProviderBuilder().
		WithAccessToken("token").
		WithAccessTokenExpire(time.Now().Unix() + 1000).
		WithSignInUrl("https://signin.aliyun.com").
		WithAccountId("123456").
		WithAccessConfig("config").
		Build()
	assert.Nil(t, err)

	assert.Equal(t, "https://signin.aliyun.com", p.signInUrl)

}

func TestCloudSSOCredentialsProvider_getCredentials(t *testing.T) {
	originHttpDo := httpDo
	defer func() { httpDo = originHttpDo }()

	p, err := NewCloudSSOCredentialsProviderBuilder().
		WithSignInUrl("https://signin-cn-shanghai.alibabacloudsso.com/a/login").
		WithAccountId("uid").
		WithAccessConfig("config").
		WithAccessToken("token").
		WithAccessTokenExpire(time.Now().Unix() + 1000).
		Build()
	assert.Nil(t, err)

	// case 1: mock new http request failed
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		err = errors.New("mock server error")
		return
	}
	_, err = p.getCredentials()
	assert.NotNil(t, err)
	assert.Equal(t, "mock server error", err.Error())

	// case 2: 4xx error
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		res = &httputil.Response{
			StatusCode: 400,
			Body:       []byte("4xx error"),
		}
		return
	}
	_, err = p.getCredentials()
	assert.NotNil(t, err)
	assert.Equal(t, "get session token from sso failed: 4xx error", err.Error())

	// case 3: invalid json
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		res = &httputil.Response{
			StatusCode: 200,
			Body:       []byte("invalid json"),
		}
		return
	}
	_, err = p.getCredentials()
	assert.NotNil(t, err)
	assert.Equal(t, "get session token from sso failed, json.Unmarshal fail: invalid character 'i' looking for beginning of value", err.Error())

	// case 4: empty response json
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		res = &httputil.Response{
			StatusCode: 200,
			Body:       []byte("null"),
		}
		return
	}
	_, err = p.getCredentials()
	assert.NotNil(t, err)
	assert.Equal(t, "get session token from sso failed, fail to get credentials", err.Error())

	// case 5: empty session ak response json
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		res = &httputil.Response{
			StatusCode: 200,
			Body:       []byte(`{"Credentials": {}}`),
		}
		return
	}
	_, err = p.getCredentials()
	assert.NotNil(t, err)
	assert.Equal(t, "get session token from sso failed, fail to get credentials", err.Error())

	// case 6: mock ok value
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		res = &httputil.Response{
			StatusCode: 200,
			Body:       []byte(`{"RequestId": "123", "CloudCredential": {"AccessKeyId":"ak","AccessKeySecret":"sk","Expiration":"2021-10-20T04:27:09Z","SecurityToken":"token"}}`),
		}
		return
	}
	creds, err := p.getCredentials()
	assert.Nil(t, err)
	assert.Equal(t, "ak", creds.AccessKeyId)
	assert.Equal(t, "sk", creds.AccessKeySecret)
	assert.Equal(t, "token", creds.SecurityToken)
	assert.Equal(t, "2021-10-20T04:27:09Z", creds.Expiration)

	// needUpdateCredential
	assert.True(t, p.needUpdateCredential())
	p.expirationTimestamp = time.Now().Unix()
	assert.True(t, p.needUpdateCredential())

	p.expirationTimestamp = time.Now().Unix() + 300
	assert.False(t, p.needUpdateCredential())
}

func TestCloudSSOCredentialsProviderGetCredentials(t *testing.T) {

	p, err := NewCloudSSOCredentialsProviderBuilder().
		WithSignInUrl("https://signin-cn-shanghai.alibabacloudsso.com/a/login").
		WithAccountId("uid").
		WithAccessConfig("config").
		WithAccessToken("token").
		WithAccessTokenExpire(time.Now().Unix() + 1000).
		WithHttpOptions(&HttpOptions{
			ConnectTimeout: 10000,
		}).
		Build()

	assert.Nil(t, err)
	assert.Equal(t, 10000, p.httpOptions.ConnectTimeout)
	_, err = p.GetCredentials()
	assert.NotNil(t, err)
	// Network-dependent test: accept expected error or any network-related error
	errMsg := err.Error()
	validError := contains(errMsg, "InvalidParameter.AccountId.InvalidChars") ||
		contains(errMsg, "timeout") ||
		contains(errMsg, "TLS handshake") ||
		contains(errMsg, "dial tcp") ||
		contains(errMsg, "lookup") ||
		contains(errMsg, "connection refused") ||
		contains(errMsg, "no such host")
	assert.True(t, validError, "Expected error about invalid account ID or network error, got: %s", errMsg)

	originHttpDo := httpDo
	defer func() { httpDo = originHttpDo }()

	// case 1: mock new http request failed
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		err = errors.New("mock server error")
		return
	}
	_, err = p.GetCredentials()
	assert.NotNil(t, err)
	assert.Equal(t, "mock server error", err.Error())

	// case 2: get invalid expiration
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		res = &httputil.Response{
			StatusCode: 200,
			Body:       []byte(`{"CloudCredential": {"AccessKeyId":"akid","AccessKeySecret":"aksecret","Expiration":"invalidexpiration","SecurityToken":"ststoken"}}`),
		}
		return
	}
	_, err = p.GetCredentials()
	assert.NotNil(t, err)
	assert.Equal(t, "parsing time \"invalidexpiration\" as \"2006-01-02T15:04:05Z\": cannot parse \"invalidexpiration\" as \"2006\"", err.Error())

	// case 3: happy result
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		res = &httputil.Response{
			StatusCode: 200,
			Body:       []byte(`{"CloudCredential": {"AccessKeyId":"akid","AccessKeySecret":"aksecret","Expiration":"2021-10-20T04:27:09Z","SecurityToken":"ststoken"}}`),
		}
		return
	}
	cc, err := p.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, "akid", cc.AccessKeyId)
	assert.Equal(t, "aksecret", cc.AccessKeySecret)
	assert.Equal(t, "ststoken", cc.SecurityToken)
	assert.Equal(t, "cloud_sso", cc.ProviderName)
	assert.True(t, p.needUpdateCredential())
}

func TestCloudSSOCredentialsProviderGetCredentialsWithHttpOptions(t *testing.T) {
	p, err := NewCloudSSOCredentialsProviderBuilder().
		WithSignInUrl("https://signin-cn-shanghai.alibabacloudsso.com/a/login").
		WithAccountId("uid").
		WithAccessConfig("config").
		WithAccessToken("token").
		WithAccessTokenExpire(time.Now().Unix() + 1000).
		WithHttpOptions(&HttpOptions{
			ConnectTimeout: 1000,
			ReadTimeout:    1000,
			Proxy:          "localhost:3999",
		}).
		Build()

	assert.Nil(t, err)
	_, err = p.GetCredentials()
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "proxyconnect tcp:")
}
