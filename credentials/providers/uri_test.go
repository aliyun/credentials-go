package providers

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	httputil "github.com/aliyun/credentials-go/credentials/internal/http"
	"github.com/aliyun/credentials-go/credentials/internal/utils"
	"github.com/stretchr/testify/assert"
)

func TestNewURLCredentialsProvider(t *testing.T) {
	rollback := utils.Memory("ALIBABA_CLOUD_CREDENTIALS_URI")
	defer func() {
		rollback()
	}()
	// case 1: no credentials provider
	_, err := NewURLCredentialsProviderBuilder().
		Build()
	assert.EqualError(t, err, "the url is empty")

	// case 2: no role arn
	os.Setenv("ALIBABA_CLOUD_CREDENTIALS_URI", "http://localhost:8080")
	p, err := NewURLCredentialsProviderBuilder().
		Build()
	assert.Nil(t, err)
	assert.True(t, strings.HasPrefix(p.url, "http://localhost:8080"))

	// case 3: check default role session name
	p, err = NewURLCredentialsProviderBuilder().
		WithUrl("http://localhost:9090").
		Build()
	assert.Nil(t, err)
	assert.True(t, strings.HasPrefix(p.url, "http://localhost:9090"))
}

func TestURLCredentialsProvider_getCredentials(t *testing.T) {
	originHttpDo := httpDo
	defer func() { httpDo = originHttpDo }()
	p, err := NewURLCredentialsProviderBuilder().
		WithUrl("http://localhost:8080").
		Build()
	assert.Nil(t, err)

	// case 1: server error
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
	assert.Equal(t, "get credentials from GET http://localhost:8080 failed: 4xx error", err.Error())

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
	assert.Equal(t, "get credentials from GET http://localhost:8080 failed with error, json unmarshal fail: invalid character 'i' looking for beginning of value", err.Error())

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
	assert.Equal(t, "refresh credentials from GET http://localhost:8080 failed: null", err.Error())

	// case 5: empty session ak response json
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		res = &httputil.Response{
			StatusCode: 200,
			Body:       []byte(`{}`),
		}
		return
	}
	_, err = p.getCredentials()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh credentials from GET http://localhost:8080 failed: {}", err.Error())

	// case 6: mock ok value
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		res = &httputil.Response{
			StatusCode: 200,
			Body:       []byte(`{"AccessKeyId":"saki","AccessKeySecret":"saks","Expiration":"2021-10-20T04:27:09Z","SecurityToken":"token"}`),
		}
		return
	}
	creds, err := p.getCredentials()
	assert.Nil(t, err)
	assert.Equal(t, "saki", creds.AccessKeyId)
	assert.Equal(t, "saks", creds.AccessKeySecret)
	assert.Equal(t, "token", creds.SecurityToken)
	assert.Equal(t, "2021-10-20T04:27:09Z", creds.Expiration)

	// needUpdateCredential
	assert.True(t, p.needUpdateCredential())
	p.expirationTimestamp = time.Now().Unix()
	assert.True(t, p.needUpdateCredential())

	p.expirationTimestamp = time.Now().Unix() + 300
	assert.False(t, p.needUpdateCredential())
}

func TestURLCredentialsProvider_GetCredentials(t *testing.T) {
	originHttpDo := httpDo
	defer func() { httpDo = originHttpDo }()

	// case 0: get previous credentials failed
	p, err := NewURLCredentialsProviderBuilder().
		WithUrl("http://localhost:8080").
		Build()
	assert.Nil(t, err)

	// case 1: get credentials failed
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
			Body:       []byte(`{"AccessKeyId":"akid","AccessKeySecret":"aksecret","Expiration":"invalidexpiration","SecurityToken":"ststoken"}`),
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
			Body:       []byte(`{"AccessKeyId":"akid","AccessKeySecret":"aksecret","Expiration":"2021-10-20T04:27:09Z","SecurityToken":"ststoken"}`),
		}
		return
	}
	cc, err := p.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, "akid", cc.AccessKeyId)
	assert.Equal(t, "aksecret", cc.AccessKeySecret)
	assert.Equal(t, "ststoken", cc.SecurityToken)
	assert.Equal(t, "credential_uri", cc.ProviderName)
	assert.True(t, p.needUpdateCredential())
	// get credentials again
	cc, err = p.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, "akid", cc.AccessKeyId)
	assert.Equal(t, "aksecret", cc.AccessKeySecret)
	assert.Equal(t, "ststoken", cc.SecurityToken)
	assert.Equal(t, "credential_uri", cc.ProviderName)
	assert.True(t, p.needUpdateCredential())
}

func TestURLCredentialsProviderWithHttpOptions(t *testing.T) {
	p, err := NewURLCredentialsProviderBuilder().
		WithUrl("http://localhost:8080").
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
