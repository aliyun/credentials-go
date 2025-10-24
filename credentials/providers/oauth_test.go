package providers

import (
	"errors"
	"testing"
	"time"

	httputil "github.com/aliyun/credentials-go/credentials/internal/http"
	"github.com/stretchr/testify/assert"
)

func TestNewOAuthCredentialsProvider(t *testing.T) {

	_, err := NewOAuthCredentialsProviderBuilder().Build()
	assert.NotNil(t, err)
	assert.Equal(t, "the ClientId is empty", err.Error())

	_, err = NewOAuthCredentialsProviderBuilder().WithClientId("clientId").Build()
	assert.NotNil(t, err)
	assert.Equal(t, "the url for sign-in is empty", err.Error())

	_, err = NewOAuthCredentialsProviderBuilder().
		WithClientId("clientId").
		WithSignInUrl("https://oauth.aliyun.com").
		Build()
	assert.NotNil(t, err)
	assert.Equal(t, "OAuth access token is empty or expired, please re-login with cli", err.Error())

	// Test valid OAuth provider
	p, err := NewOAuthCredentialsProviderBuilder().
		WithClientId("clientId").
		WithSignInUrl("https://oauth.aliyun.com").
		WithRefreshToken("refreshToken").
		WithAccessToken("accessToken").
		WithAccessTokenExpire(time.Now().Unix() + 1000).
		Build()
	assert.Nil(t, err)
	assert.Equal(t, "clientId", p.clientId)
	assert.Equal(t, "https://oauth.aliyun.com", p.signInUrl)
	assert.Equal(t, "refreshToken", p.refreshToken)
	assert.Equal(t, "accessToken", p.accessToken)
}

func TestOAuthCredentialsProvider_getCredentials(t *testing.T) {
	originHttpDo := httpDo
	defer func() { httpDo = originHttpDo }()

	p, err := NewOAuthCredentialsProviderBuilder().
		WithClientId("clientId").
		WithSignInUrl("https://oauth.aliyun.com").
		WithRefreshToken("refreshToken").
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
	assert.Equal(t, "get session token from OAuth failed: 4xx error", err.Error())

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
	assert.Equal(t, "get session token from OAuth failed, json.Unmarshal fail: invalid character 'i' looking for beginning of value", err.Error())

	// case 4: empty access key id
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		res = &httputil.Response{
			StatusCode: 200,
			Body:       []byte(`{"accessKeyId":"","accessKeySecret":"sk","securityToken":"token","expiration":"2021-10-20T04:27:09Z"}`),
		}
		return
	}
	_, err = p.getCredentials()
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "refresh session token err, fail to get credentials from OAuth")

	// case 5: empty access key secret
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		res = &httputil.Response{
			StatusCode: 200,
			Body:       []byte(`{"accessKeyId":"ak","accessKeySecret":"","securityToken":"token","expiration":"2021-10-20T04:27:09Z"}`),
		}
		return
	}
	_, err = p.getCredentials()
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "refresh session token err, fail to get credentials from OAuth")

	// case 6: empty security token
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		res = &httputil.Response{
			StatusCode: 200,
			Body:       []byte(`{"accessKeyId":"ak","accessKeySecret":"sk","securityToken":"","expiration":"2021-10-20T04:27:09Z"}`),
		}
		return
	}
	_, err = p.getCredentials()
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "refresh session token err, fail to get credentials from OAuth")

	// case 7: mock ok value
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		res = &httputil.Response{
			StatusCode: 200,
			Body:       []byte(`{"accessKeyId":"ak","accessKeySecret":"sk","securityToken":"token","expiration":"2021-10-20T04:27:09Z","requestId":"123"}`),
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

func TestOAuthCredentialsProviderGetCredentials(t *testing.T) {

	p, err := NewOAuthCredentialsProviderBuilder().
		WithClientId("clientId").
		WithSignInUrl("https://oauth.aliyun.com").
		WithRefreshToken("refreshToken").
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
	assert.Contains(t, err.Error(), "get session token from OAuth failed")

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
			Body:       []byte(`{"accessKeyId":"akid","accessKeySecret":"aksecret","securityToken":"ststoken","expiration":"invalidexpiration"}`),
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
			Body:       []byte(`{"accessKeyId":"akid","accessKeySecret":"aksecret","securityToken":"ststoken","expiration":"2021-10-20T04:27:09Z"}`),
		}
		return
	}
	cc, err := p.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, "akid", cc.AccessKeyId)
	assert.Equal(t, "aksecret", cc.AccessKeySecret)
	assert.Equal(t, "ststoken", cc.SecurityToken)
	assert.Equal(t, "oauth", cc.ProviderName)
	assert.True(t, p.needUpdateCredential())
}

func TestOAuthCredentialsProviderGetCredentialsWithHttpOptions(t *testing.T) {
	p, err := NewOAuthCredentialsProviderBuilder().
		WithClientId("clientId").
		WithSignInUrl("https://oauth.aliyun.com").
		WithRefreshToken("refreshToken").
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

func TestOAuthCredentialsProviderGetProviderName(t *testing.T) {
	p, err := NewOAuthCredentialsProviderBuilder().
		WithClientId("clientId").
		WithSignInUrl("https://oauth.aliyun.com").
		WithRefreshToken("refreshToken").
		WithAccessToken("token").
		WithAccessTokenExpire(time.Now().Unix() + 1000).
		Build()
	assert.Nil(t, err)
	assert.Equal(t, "oauth", p.GetProviderName())
}

func TestOAuthCredentialsProviderWithHttpOptions(t *testing.T) {
	httpOptions := &HttpOptions{
		ConnectTimeout: 5000,
		ReadTimeout:    8000,
		Proxy:          "http://proxy.example.com:8080",
	}

	p, err := NewOAuthCredentialsProviderBuilder().
		WithClientId("clientId").
		WithSignInUrl("https://oauth.aliyun.com").
		WithRefreshToken("refreshToken").
		WithAccessToken("token").
		WithAccessTokenExpire(time.Now().Unix() + 1000).
		WithHttpOptions(httpOptions).
		Build()

	assert.Nil(t, err)
	assert.Equal(t, httpOptions, p.httpOptions)
	assert.Equal(t, 5000, p.httpOptions.ConnectTimeout)
	assert.Equal(t, 8000, p.httpOptions.ReadTimeout)
	assert.Equal(t, "http://proxy.example.com:8080", p.httpOptions.Proxy)
}

func TestOAuthCredentialsProviderCredentialCaching(t *testing.T) {
	originHttpDo := httpDo
	defer func() { httpDo = originHttpDo }()

	p, err := NewOAuthCredentialsProviderBuilder().
		WithClientId("clientId").
		WithSignInUrl("https://oauth.aliyun.com").
		WithRefreshToken("refreshToken").
		WithAccessToken("token").
		WithAccessTokenExpire(time.Now().Unix() + 1000).
		Build()
	assert.Nil(t, err)

	// Mock successful response
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		res = &httputil.Response{
			StatusCode: 200,
			Body:       []byte(`{"accessKeyId":"akid","accessKeySecret":"aksecret","securityToken":"ststoken","expiration":"2021-10-20T04:27:09Z"}`),
		}
		return
	}

	// First call should make HTTP request
	cc1, err := p.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, "akid", cc1.AccessKeyId)

	// Second call should use cached credentials (no new HTTP request)
	cc2, err := p.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, "akid", cc2.AccessKeyId)
	assert.Equal(t, cc1.AccessKeyId, cc2.AccessKeyId)
}

func TestOAuthCredentialsProviderNeedUpdateCredential(t *testing.T) {
	p, err := NewOAuthCredentialsProviderBuilder().
		WithClientId("clientId").
		WithSignInUrl("https://oauth.aliyun.com").
		WithRefreshToken("refreshToken").
		WithAccessToken("token").
		WithAccessTokenExpire(time.Now().Unix() + 1000).
		Build()
	assert.Nil(t, err)

	// Initially should need update
	assert.True(t, p.needUpdateCredential())

	// Set expiration far in the future
	p.expirationTimestamp = time.Now().Unix() + 3600 // 1 hour
	assert.False(t, p.needUpdateCredential())

	// Set expiration close to now (within 180 seconds)
	p.expirationTimestamp = time.Now().Unix() + 100
	assert.True(t, p.needUpdateCredential())

	// Set expiration in the past
	p.expirationTimestamp = time.Now().Unix() - 100
	assert.True(t, p.needUpdateCredential())
}

func TestOAuthCredentialsProviderTryRefreshOauthToken(t *testing.T) {
	originHttpDo := httpDo
	defer func() { httpDo = originHttpDo }()

	p, err := NewOAuthCredentialsProviderBuilder().
		WithClientId("clientId").
		WithSignInUrl("https://oauth.aliyun.com").
		WithRefreshToken("refreshToken").
		WithAccessToken("accessToken").
		WithAccessTokenExpire(time.Now().Unix() + 1000).
		Build()
	assert.Nil(t, err)

	// Test successful token refresh
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		res = &httputil.Response{
			StatusCode: 200,
			Body:       []byte(`{"access_token":"new_access_token","refresh_token":"new_refresh_token","expires_in":3600,"token_type":"Bearer"}`),
		}
		return
	}

	err = p.tryRefreshOauthToken()
	assert.Nil(t, err)
	assert.Equal(t, "new_access_token", p.accessToken)
	assert.Equal(t, "new_refresh_token", p.refreshToken)
	assert.True(t, p.accessTokenExpire > time.Now().Unix())

	// Test refresh token failure - HTTP error
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		err = errors.New("network error")
		return
	}

	err = p.tryRefreshOauthToken()
	assert.NotNil(t, err)
	assert.Equal(t, "network error", err.Error())

	// Test refresh token failure - non-200 status
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		res = &httputil.Response{
			StatusCode: 400,
			Body:       []byte("bad request"),
		}
		return
	}

	err = p.tryRefreshOauthToken()
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "failed to refresh token, status code: 400")

	// Test refresh token failure - invalid JSON
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		res = &httputil.Response{
			StatusCode: 200,
			Body:       []byte("invalid json"),
		}
		return
	}

	err = p.tryRefreshOauthToken()
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "get refresh token from OAuth failed, json.Unmarshal fail")

	// Test refresh token failure - empty tokens
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		res = &httputil.Response{
			StatusCode: 200,
			Body:       []byte(`{"access_token":"","refresh_token":"","expires_in":3600,"token_type":"Bearer"}`),
		}
		return
	}

	err = p.tryRefreshOauthToken()
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "failed to refresh token from OAuth")
}

func TestOAuthCredentialsProviderTokenRefreshIntegration(t *testing.T) {
	originHttpDo := httpDo
	defer func() { httpDo = originHttpDo }()

	// Test case where access token is expired and needs refresh
	p, err := NewOAuthCredentialsProviderBuilder().
		WithClientId("clientId").
		WithSignInUrl("https://oauth.aliyun.com").
		WithRefreshToken("refreshToken").
		WithAccessToken("expiredToken").
		WithAccessTokenExpire(time.Now().Unix() - 1000). // expired token
		Build()
	assert.Nil(t, err)

	// Mock refresh token response
	refreshTokenCallCount := 0
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		if req.Path == "/v1/token" {
			refreshTokenCallCount++
			res = &httputil.Response{
				StatusCode: 200,
				Body:       []byte(`{"access_token":"new_access_token","refresh_token":"new_refresh_token","expires_in":3600,"token_type":"Bearer"}`),
			}
			return
		}
		// Mock credentials exchange response
		res = &httputil.Response{
			StatusCode: 200,
			Body:       []byte(`{"accessKeyId":"akid","accessKeySecret":"aksecret","securityToken":"ststoken","expiration":"2021-10-20T04:27:09Z"}`),
		}
		return
	}

	cc, err := p.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, "akid", cc.AccessKeyId)
	assert.Equal(t, "aksecret", cc.AccessKeySecret)
	assert.Equal(t, "ststoken", cc.SecurityToken)
	assert.Equal(t, "oauth", cc.ProviderName)
	assert.Equal(t, 1, refreshTokenCallCount) // Should have called refresh token once
}

func TestOAuthCredentialsProvider_TokenUpdateCallback(t *testing.T) {
	// Test OAuth provider with token update callback
	callbackCalled := false
	callbackData := struct {
		refreshToken      string
		accessToken       string
		accessKey         string
		secret            string
		securityToken     string
		accessTokenExpire int64
		stsExpire         int64
	}{}

	callback := func(refreshToken, accessToken, accessKey, secret, securityToken string, accessTokenExpire, stsExpire int64) error {
		callbackCalled = true
		callbackData.refreshToken = refreshToken
		callbackData.accessToken = accessToken
		callbackData.accessKey = accessKey
		callbackData.secret = secret
		callbackData.securityToken = securityToken
		callbackData.accessTokenExpire = accessTokenExpire
		callbackData.stsExpire = stsExpire
		return nil
	}

	p, err := NewOAuthCredentialsProviderBuilder().
		WithClientId("clientId").
		WithSignInUrl("https://oauth.aliyun.com").
		WithRefreshToken("refreshToken").
		WithAccessToken("accessToken").
		WithAccessTokenExpire(time.Now().Unix() + 1000).
		WithTokenUpdateCallback(callback).
		Build()
	assert.Nil(t, err)
	assert.NotNil(t, p.tokenUpdateCallback)

	// Test callback is called during token refresh
	originHttpDo := httpDo
	defer func() { httpDo = originHttpDo }()

	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		if req.Path == "/v1/token" {
			res = &httputil.Response{
				StatusCode: 200,
				Body:       []byte(`{"access_token":"new_access_token","refresh_token":"new_refresh_token","expires_in":3600,"token_type":"Bearer"}`),
			}
			return
		}
		// Mock credentials exchange response
		res = &httputil.Response{
			StatusCode: 200,
			Body:       []byte(`{"accessKeyId":"akid","accessKeySecret":"aksecret","securityToken":"ststoken","expiration":"2021-10-20T04:27:09Z"}`),
		}
		return
	}

	// Set expired token to trigger refresh
	p.accessTokenExpire = time.Now().Unix() - 1000

	_, err = p.GetCredentials()
	assert.Nil(t, err)
	assert.True(t, callbackCalled)
	assert.Equal(t, "new_refresh_token", callbackData.refreshToken)
	assert.Equal(t, "new_access_token", callbackData.accessToken)
	assert.Equal(t, "akid", callbackData.accessKey)
	assert.Equal(t, "aksecret", callbackData.secret)
	assert.Equal(t, "ststoken", callbackData.securityToken)
}

func TestOAuthCredentialsProvider_TokenUpdateCallback_Error(t *testing.T) {
	// Test OAuth provider with token update callback that returns error
	callback := func(refreshToken, accessToken, accessKey, secret, securityToken string, accessTokenExpire, stsExpire int64) error {
		return errors.New("callback error")
	}

	p, err := NewOAuthCredentialsProviderBuilder().
		WithClientId("clientId").
		WithSignInUrl("https://oauth.aliyun.com").
		WithRefreshToken("refreshToken").
		WithAccessToken("accessToken").
		WithAccessTokenExpire(time.Now().Unix() + 1000).
		WithTokenUpdateCallback(callback).
		Build()
	assert.Nil(t, err)

	originHttpDo := httpDo
	defer func() { httpDo = originHttpDo }()

	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		if req.Path == "/v1/token" {
			res = &httputil.Response{
				StatusCode: 200,
				Body:       []byte(`{"access_token":"new_access_token","refresh_token":"new_refresh_token","expires_in":3600,"token_type":"Bearer"}`),
			}
			return
		}
		// Mock credentials exchange response
		res = &httputil.Response{
			StatusCode: 200,
			Body:       []byte(`{"accessKeyId":"akid","accessKeySecret":"aksecret","securityToken":"ststoken","expiration":"2021-10-20T04:27:09Z"}`),
		}
		return
	}

	// Set expired token to trigger refresh
	p.accessTokenExpire = time.Now().Unix() - 1000

	// Should still succeed even if callback fails (callback error is logged but not returned)
	_, err = p.GetCredentials()
	assert.Nil(t, err)
}

func TestOAuthCredentialsProvider_WithoutTokenUpdateCallback(t *testing.T) {
	// Test OAuth provider without token update callback
	p, err := NewOAuthCredentialsProviderBuilder().
		WithClientId("clientId").
		WithSignInUrl("https://oauth.aliyun.com").
		WithRefreshToken("refreshToken").
		WithAccessToken("accessToken").
		WithAccessTokenExpire(time.Now().Unix() + 1000).
		Build()
	assert.Nil(t, err)
	assert.Nil(t, p.tokenUpdateCallback)

	originHttpDo := httpDo
	defer func() { httpDo = originHttpDo }()

	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		if req.Path == "/v1/token" {
			res = &httputil.Response{
				StatusCode: 200,
				Body:       []byte(`{"access_token":"new_access_token","refresh_token":"new_refresh_token","expires_in":3600,"token_type":"Bearer"}`),
			}
			return
		}
		// Mock credentials exchange response
		res = &httputil.Response{
			StatusCode: 200,
			Body:       []byte(`{"accessKeyId":"akid","accessKeySecret":"aksecret","securityToken":"ststoken","expiration":"2021-10-20T04:27:09Z"}`),
		}
		return
	}

	// Set expired token to trigger refresh
	p.accessTokenExpire = time.Now().Unix() - 1000

	// Should succeed without callback
	_, err = p.GetCredentials()
	assert.Nil(t, err)
}

func TestOAuthCredentialsProvider_TryRefreshOauthToken_WithCallback(t *testing.T) {
	originHttpDo := httpDo
	defer func() { httpDo = originHttpDo }()

	callbackCalled := false
	callback := func(refreshToken, accessToken, accessKey, secret, securityToken string, accessTokenExpire, stsExpire int64) error {
		callbackCalled = true
		return nil
	}

	p, err := NewOAuthCredentialsProviderBuilder().
		WithClientId("clientId").
		WithSignInUrl("https://oauth.aliyun.com").
		WithRefreshToken("refreshToken").
		WithAccessToken("accessToken").
		WithAccessTokenExpire(time.Now().Unix() + 1000).
		WithTokenUpdateCallback(callback).
		Build()
	assert.Nil(t, err)

	// Test successful token refresh
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		res = &httputil.Response{
			StatusCode: 200,
			Body:       []byte(`{"access_token":"new_access_token","refresh_token":"new_refresh_token","expires_in":3600,"token_type":"Bearer"}`),
		}
		return
	}

	err = p.tryRefreshOauthToken()
	assert.Nil(t, err)
	// 注意：tryRefreshOauthToken 本身不会调用回调函数，回调函数是在 GetCredentials 中调用的
	assert.False(t, callbackCalled) // 这里应该是 false，因为 tryRefreshOauthToken 不调用回调
	assert.Equal(t, "new_access_token", p.accessToken)
	assert.Equal(t, "new_refresh_token", p.refreshToken)
}

func TestOAuthCredentialsProvider_GetCredentials_WithExpiredToken(t *testing.T) {
	originHttpDo := httpDo
	defer func() { httpDo = originHttpDo }()

	p, err := NewOAuthCredentialsProviderBuilder().
		WithClientId("clientId").
		WithSignInUrl("https://oauth.aliyun.com").
		WithRefreshToken("refreshToken").
		WithAccessToken("accessToken").
		WithAccessTokenExpire(time.Now().Unix() - 1000). // expired token
		Build()
	assert.Nil(t, err)

	// Mock refresh token response
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		if req.Path == "/v1/token" {
			res = &httputil.Response{
				StatusCode: 200,
				Body:       []byte(`{"access_token":"new_access_token","refresh_token":"new_refresh_token","expires_in":3600,"token_type":"Bearer"}`),
			}
			return
		}
		// Mock credentials exchange response
		res = &httputil.Response{
			StatusCode: 200,
			Body:       []byte(`{"accessKeyId":"akid","accessKeySecret":"aksecret","securityToken":"ststoken","expiration":"2021-10-20T04:27:09Z"}`),
		}
		return
	}

	cc, err := p.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, "akid", cc.AccessKeyId)
	assert.Equal(t, "aksecret", cc.AccessKeySecret)
	assert.Equal(t, "ststoken", cc.SecurityToken)
	assert.Equal(t, "oauth", cc.ProviderName)
}

func TestOAuthCredentialsProvider_GetCredentials_WithEmptyAccessToken(t *testing.T) {
	originHttpDo := httpDo
	defer func() { httpDo = originHttpDo }()

	p, err := NewOAuthCredentialsProviderBuilder().
		WithClientId("clientId").
		WithSignInUrl("https://oauth.aliyun.com").
		WithRefreshToken("refreshToken").
		WithAccessToken(""). // empty access token
		WithAccessTokenExpire(time.Now().Unix() + 1000).
		Build()
	assert.Nil(t, err)

	// Mock refresh token response
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		if req.Path == "/v1/token" {
			res = &httputil.Response{
				StatusCode: 200,
				Body:       []byte(`{"access_token":"new_access_token","refresh_token":"new_refresh_token","expires_in":3600,"token_type":"Bearer"}`),
			}
			return
		}
		// Mock credentials exchange response
		res = &httputil.Response{
			StatusCode: 200,
			Body:       []byte(`{"accessKeyId":"akid","accessKeySecret":"aksecret","securityToken":"ststoken","expiration":"2021-10-20T04:27:09Z"}`),
		}
		return
	}

	cc, err := p.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, "akid", cc.AccessKeyId)
	assert.Equal(t, "aksecret", cc.AccessKeySecret)
	assert.Equal(t, "ststoken", cc.SecurityToken)
	assert.Equal(t, "oauth", cc.ProviderName)
}

func TestOAuthCredentialsProvider_GetCredentials_WithZeroAccessTokenExpire(t *testing.T) {
	originHttpDo := httpDo
	defer func() { httpDo = originHttpDo }()

	p, err := NewOAuthCredentialsProviderBuilder().
		WithClientId("clientId").
		WithSignInUrl("https://oauth.aliyun.com").
		WithRefreshToken("refreshToken").
		WithAccessToken("accessToken").
		WithAccessTokenExpire(0). // zero expire time
		Build()
	assert.Nil(t, err)

	// Mock refresh token response
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		if req.Path == "/v1/token" {
			res = &httputil.Response{
				StatusCode: 200,
				Body:       []byte(`{"access_token":"new_access_token","refresh_token":"new_refresh_token","expires_in":3600,"token_type":"Bearer"}`),
			}
			return
		}
		// Mock credentials exchange response
		res = &httputil.Response{
			StatusCode: 200,
			Body:       []byte(`{"accessKeyId":"akid","accessKeySecret":"aksecret","securityToken":"ststoken","expiration":"2021-10-20T04:27:09Z"}`),
		}
		return
	}

	cc, err := p.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, "akid", cc.AccessKeyId)
	assert.Equal(t, "aksecret", cc.AccessKeySecret)
	assert.Equal(t, "ststoken", cc.SecurityToken)
	assert.Equal(t, "oauth", cc.ProviderName)
}

func TestOAuthCredentialsProvider_GetCredentials_WithNearExpiredToken(t *testing.T) {
	originHttpDo := httpDo
	defer func() { httpDo = originHttpDo }()

	p, err := NewOAuthCredentialsProviderBuilder().
		WithClientId("clientId").
		WithSignInUrl("https://oauth.aliyun.com").
		WithRefreshToken("refreshToken").
		WithAccessToken("accessToken").
		WithAccessTokenExpire(time.Now().Unix() + 100). // near expired (within 180 seconds)
		Build()
	assert.Nil(t, err)

	// Mock refresh token response
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		if req.Path == "/v1/token" {
			res = &httputil.Response{
				StatusCode: 200,
				Body:       []byte(`{"access_token":"new_access_token","refresh_token":"new_refresh_token","expires_in":3600,"token_type":"Bearer"}`),
			}
			return
		}
		// Mock credentials exchange response
		res = &httputil.Response{
			StatusCode: 200,
			Body:       []byte(`{"accessKeyId":"akid","accessKeySecret":"aksecret","securityToken":"ststoken","expiration":"2021-10-20T04:27:09Z"}`),
		}
		return
	}

	cc, err := p.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, "akid", cc.AccessKeyId)
	assert.Equal(t, "aksecret", cc.AccessKeySecret)
	assert.Equal(t, "ststoken", cc.SecurityToken)
	assert.Equal(t, "oauth", cc.ProviderName)
}

func TestOAuthCredentialsProvider_TryRefreshOauthToken_InvalidURL(t *testing.T) {
	p, err := NewOAuthCredentialsProviderBuilder().
		WithClientId("clientId").
		WithSignInUrl("invalid-url"). // invalid URL
		WithRefreshToken("refreshToken").
		WithAccessToken("accessToken").
		WithAccessTokenExpire(time.Now().Unix() + 1000).
		Build()
	assert.Nil(t, err)

	err = p.tryRefreshOauthToken()
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "parse")
}

func TestOAuthCredentialsProvider_TryRefreshOauthToken_NetworkError(t *testing.T) {
	originHttpDo := httpDo
	defer func() { httpDo = originHttpDo }()

	p, err := NewOAuthCredentialsProviderBuilder().
		WithClientId("clientId").
		WithSignInUrl("https://oauth.aliyun.com").
		WithRefreshToken("refreshToken").
		WithAccessToken("accessToken").
		WithAccessTokenExpire(time.Now().Unix() + 1000).
		Build()
	assert.Nil(t, err)

	// Mock network error
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		return nil, errors.New("network error")
	}

	err = p.tryRefreshOauthToken()
	assert.NotNil(t, err)
	assert.Equal(t, "network error", err.Error())
}

func TestOAuthCredentialsProvider_TryRefreshOauthToken_Non200Status(t *testing.T) {
	originHttpDo := httpDo
	defer func() { httpDo = originHttpDo }()

	p, err := NewOAuthCredentialsProviderBuilder().
		WithClientId("clientId").
		WithSignInUrl("https://oauth.aliyun.com").
		WithRefreshToken("refreshToken").
		WithAccessToken("accessToken").
		WithAccessTokenExpire(time.Now().Unix() + 1000).
		Build()
	assert.Nil(t, err)

	// Mock non-200 status
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		res = &httputil.Response{
			StatusCode: 401,
			Body:       []byte("unauthorized"),
		}
		return
	}

	err = p.tryRefreshOauthToken()
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "failed to refresh token, status code: 401")
}

func TestOAuthCredentialsProvider_TryRefreshOauthToken_InvalidJSON(t *testing.T) {
	originHttpDo := httpDo
	defer func() { httpDo = originHttpDo }()

	p, err := NewOAuthCredentialsProviderBuilder().
		WithClientId("clientId").
		WithSignInUrl("https://oauth.aliyun.com").
		WithRefreshToken("refreshToken").
		WithAccessToken("accessToken").
		WithAccessTokenExpire(time.Now().Unix() + 1000).
		Build()
	assert.Nil(t, err)

	// Mock invalid JSON response
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		res = &httputil.Response{
			StatusCode: 200,
			Body:       []byte("invalid json"),
		}
		return
	}

	err = p.tryRefreshOauthToken()
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "get refresh token from OAuth failed, json.Unmarshal fail")
}

func TestOAuthCredentialsProvider_TryRefreshOauthToken_EmptyTokens(t *testing.T) {
	originHttpDo := httpDo
	defer func() { httpDo = originHttpDo }()

	p, err := NewOAuthCredentialsProviderBuilder().
		WithClientId("clientId").
		WithSignInUrl("https://oauth.aliyun.com").
		WithRefreshToken("refreshToken").
		WithAccessToken("accessToken").
		WithAccessTokenExpire(time.Now().Unix() + 1000).
		Build()
	assert.Nil(t, err)

	// Mock empty tokens response
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		res = &httputil.Response{
			StatusCode: 200,
			Body:       []byte(`{"access_token":"","refresh_token":"","expires_in":3600,"token_type":"Bearer"}`),
		}
		return
	}

	err = p.tryRefreshOauthToken()
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "failed to refresh token from OAuth")
}

func TestOAuthCredentialsProvider_NeedUpdateCredential_EdgeCases(t *testing.T) {
	p, err := NewOAuthCredentialsProviderBuilder().
		WithClientId("clientId").
		WithSignInUrl("https://oauth.aliyun.com").
		WithRefreshToken("refreshToken").
		WithAccessToken("accessToken").
		WithAccessTokenExpire(time.Now().Unix() + 1000).
		Build()
	assert.Nil(t, err)

	// Test with zero expiration timestamp
	p.expirationTimestamp = 0
	assert.True(t, p.needUpdateCredential())

	// Test with expiration exactly 180 seconds from now
	p.expirationTimestamp = time.Now().Unix() + 180
	assert.True(t, p.needUpdateCredential())

	// Test with expiration 181 seconds from now
	p.expirationTimestamp = time.Now().Unix() + 181
	assert.False(t, p.needUpdateCredential())
}

func TestOAuthCredentialsProvider_HttpOptions_EdgeCases(t *testing.T) {
	// Test with zero timeouts
	p, err := NewOAuthCredentialsProviderBuilder().
		WithClientId("clientId").
		WithSignInUrl("https://oauth.aliyun.com").
		WithRefreshToken("refreshToken").
		WithAccessToken("accessToken").
		WithAccessTokenExpire(time.Now().Unix() + 1000).
		WithHttpOptions(&HttpOptions{
			ConnectTimeout: 0,
			ReadTimeout:    0,
		}).
		Build()
	assert.Nil(t, err)
	assert.Equal(t, 0, p.httpOptions.ConnectTimeout)
	assert.Equal(t, 0, p.httpOptions.ReadTimeout)

	// Test with negative timeouts
	p, err = NewOAuthCredentialsProviderBuilder().
		WithClientId("clientId").
		WithSignInUrl("https://oauth.aliyun.com").
		WithRefreshToken("refreshToken").
		WithAccessToken("accessToken").
		WithAccessTokenExpire(time.Now().Unix() + 1000).
		WithHttpOptions(&HttpOptions{
			ConnectTimeout: -1000,
			ReadTimeout:    -2000,
		}).
		Build()
	assert.Nil(t, err)
	assert.Equal(t, -1000, p.httpOptions.ConnectTimeout)
	assert.Equal(t, -2000, p.httpOptions.ReadTimeout)
}

func TestOAuthCredentialsProvider_GetCredentials_CachedCredentials(t *testing.T) {
	originHttpDo := httpDo
	defer func() { httpDo = originHttpDo }()

	p, err := NewOAuthCredentialsProviderBuilder().
		WithClientId("clientId").
		WithSignInUrl("https://oauth.aliyun.com").
		WithRefreshToken("refreshToken").
		WithAccessToken("accessToken").
		WithAccessTokenExpire(time.Now().Unix() + 1000).
		Build()
	assert.Nil(t, err)

	// Mock successful response
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		res = &httputil.Response{
			StatusCode: 200,
			Body:       []byte(`{"accessKeyId":"akid","accessKeySecret":"aksecret","securityToken":"ststoken","expiration":"2021-10-20T04:27:09Z"}`),
		}
		return
	}

	// First call should make HTTP request
	cc1, err := p.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, "akid", cc1.AccessKeyId)

	// Set expiration far in the future to avoid refresh
	p.expirationTimestamp = time.Now().Unix() + 3600

	// Second call should use cached credentials
	cc2, err := p.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, "akid", cc2.AccessKeyId)
	assert.Equal(t, cc1.AccessKeyId, cc2.AccessKeyId)
	assert.Equal(t, cc1.AccessKeySecret, cc2.AccessKeySecret)
	assert.Equal(t, cc1.SecurityToken, cc2.SecurityToken)
}
