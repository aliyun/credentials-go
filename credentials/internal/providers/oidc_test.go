package providers

import (
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestOIDCCredentialsProviderGetCredentialsWithError(t *testing.T) {
	wd, _ := os.Getwd()
	p, err := NewOIDCCredentialsProviderBuilder().
		// read a normal token
		WithOIDCTokenFilePath(path.Join(wd, "fixtures/mock_oidctoken")).
		WithOIDCProviderARN("provider-arn").
		WithRoleArn("roleArn").
		WithRoleSessionName("rsn").
		WithPolicy("policy").
		WithDurationSeconds(1000).
		Build()

	assert.Nil(t, err)
	_, err = p.GetCredentials()
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "AuthenticationFail.NoPermission")
}

func TestNewOIDCCredentialsProvider(t *testing.T) {
	_, err := NewOIDCCredentialsProviderBuilder().Build()
	assert.NotNil(t, err)
	assert.Equal(t, "the OIDCTokenFilePath is empty", err.Error())

	_, err = NewOIDCCredentialsProviderBuilder().WithOIDCTokenFilePath("/path/to/invalid/oidc.token").Build()
	assert.NotNil(t, err)
	assert.Equal(t, "the OIDCProviderARN is empty", err.Error())

	_, err = NewOIDCCredentialsProviderBuilder().
		WithOIDCTokenFilePath("/path/to/invalid/oidc.token").
		WithOIDCProviderARN("provider-arn").
		Build()
	assert.NotNil(t, err)
	assert.Equal(t, "the RoleArn is empty", err.Error())

	p, err := NewOIDCCredentialsProviderBuilder().
		WithOIDCTokenFilePath("/path/to/invalid/oidc.token").
		WithOIDCProviderARN("provider-arn").
		WithRoleArn("roleArn").
		Build()
	assert.Nil(t, err)

	assert.Equal(t, "/path/to/invalid/oidc.token", p.oidcTokenFilePath)
	assert.True(t, strings.HasPrefix(p.roleSessionName, "credentials-go-"))
	assert.Equal(t, 3600, p.durationSeconds)

	_, err = NewOIDCCredentialsProviderBuilder().
		WithOIDCTokenFilePath("/path/to/invalid/oidc.token").
		WithOIDCProviderARN("provider-arn").
		WithRoleArn("roleArn").
		WithDurationSeconds(100).
		Build()
	assert.NotNil(t, err)
	assert.Equal(t, "the Assume Role session duration should be in the range of 15min - max duration seconds", err.Error())

	os.Setenv("ALIBABA_CLOUD_OIDC_TOKEN_FILE", "/path/from/env")
	os.Setenv("ALIBABA_CLOUD_OIDC_PROVIDER_ARN", "provider_arn_from_env")
	os.Setenv("ALIBABA_CLOUD_ROLE_ARN", "role_arn_from_env")

	defer func() {
		os.Unsetenv("ALIBABA_CLOUD_OIDC_TOKEN_FILE")
		os.Unsetenv("ALIBABA_CLOUD_OIDC_PROVIDER_ARN")
		os.Unsetenv("ALIBABA_CLOUD_ROLE_ARN")
	}()

	p, err = NewOIDCCredentialsProviderBuilder().
		Build()
	assert.Nil(t, err)

	assert.Equal(t, "/path/from/env", p.oidcTokenFilePath)
	assert.Equal(t, "provider_arn_from_env", p.oidcProviderARN)
	assert.Equal(t, "role_arn_from_env", p.roleArn)
	// sts endpoint: default
	assert.Equal(t, "sts.aliyuncs.com", p.stsEndpoint)
	// sts endpoint: with sts endpoint
	p, err = NewOIDCCredentialsProviderBuilder().
		WithSTSEndpoint("sts.cn-shanghai.aliyuncs.com").
		Build()
	assert.Nil(t, err)
	assert.Equal(t, "sts.cn-shanghai.aliyuncs.com", p.stsEndpoint)

	// sts endpoint: with sts regionId
	p, err = NewOIDCCredentialsProviderBuilder().
		WithStsRegionId("cn-beijing").
		Build()
	assert.Nil(t, err)
	assert.Equal(t, "sts.cn-beijing.aliyuncs.com", p.stsEndpoint)

	p, err = NewOIDCCredentialsProviderBuilder().
		WithOIDCTokenFilePath("/path/to/invalid/oidc.token").
		WithOIDCProviderARN("provider-arn").
		WithRoleArn("roleArn").
		WithRoleSessionName("rsn").
		WithStsRegionId("cn-hangzhou").
		WithPolicy("policy").
		Build()
	assert.Nil(t, err)

	assert.Equal(t, "/path/to/invalid/oidc.token", p.oidcTokenFilePath)
	assert.Equal(t, "provider-arn", p.oidcProviderARN)
	assert.Equal(t, "roleArn", p.roleArn)
	assert.Equal(t, "rsn", p.roleSessionName)
	assert.Equal(t, "cn-hangzhou", p.stsRegionId)
	assert.Equal(t, "policy", p.policy)
	assert.Equal(t, 3600, p.durationSeconds)
	assert.Equal(t, "sts.cn-hangzhou.aliyuncs.com", p.stsEndpoint)
}

func TestOIDCCredentialsProvider_getCredentials(t *testing.T) {
	// case 0: invalid oidc token file path
	p, err := NewOIDCCredentialsProviderBuilder().
		WithOIDCTokenFilePath("/path/to/invalid/oidc.token").
		WithOIDCProviderARN("provider-arn").
		WithRoleArn("roleArn").
		WithRoleSessionName("rsn").
		WithStsRegionId("cn-hangzhou").
		WithPolicy("policy").
		Build()
	assert.Nil(t, err)

	_, err = p.getCredentials()
	assert.NotNil(t, err)
	assert.Equal(t, "open /path/to/invalid/oidc.token: no such file or directory", err.Error())

	// case 1: mock new http request failed
	wd, _ := os.Getwd()
	p, err = NewOIDCCredentialsProviderBuilder().
		// read a normal token
		WithOIDCTokenFilePath(path.Join(wd, "fixtures/mock_oidctoken")).
		WithOIDCProviderARN("provider-arn").
		WithRoleArn("roleArn").
		WithRoleSessionName("rsn").
		WithStsRegionId("cn-hangzhou").
		WithPolicy("policy").
		Build()
	assert.Nil(t, err)

	originNewRequest := hookNewRequest
	defer func() { hookNewRequest = originNewRequest }()

	hookNewRequest = func(fn newReuqest) newReuqest {
		return func(method, url string, body io.Reader) (*http.Request, error) {
			return nil, errors.New("new http request failed")
		}
	}

	_, err = p.getCredentials()
	assert.NotNil(t, err)
	assert.Equal(t, "new http request failed", err.Error())

	// reset new request
	hookNewRequest = originNewRequest

	originDo := hookDo
	defer func() { hookDo = originDo }()

	// case 2: server error
	hookDo = func(fn do) do {
		return func(req *http.Request) (res *http.Response, err error) {
			err = errors.New("mock server error")
			return
		}
	}
	_, err = p.getCredentials()
	assert.NotNil(t, err)
	assert.Equal(t, "mock server error", err.Error())

	// case 3: mock read response error
	hookDo = func(fn do) do {
		return func(req *http.Request) (res *http.Response, err error) {
			status := strconv.Itoa(200)
			res = &http.Response{
				Proto:      "HTTP/1.1",
				ProtoMajor: 1,
				Header:     map[string][]string{},
				StatusCode: 200,
				Status:     status + " " + http.StatusText(200),
			}
			res.Body = ioutil.NopCloser(&errorReader{})
			return
		}
	}
	_, err = p.getCredentials()
	assert.NotNil(t, err)
	assert.Equal(t, "read failed", err.Error())

	// case 4: 4xx error
	hookDo = func(fn do) do {
		return func(req *http.Request) (res *http.Response, err error) {
			res = mockResponse(400, "4xx error")
			return
		}
	}
	_, err = p.getCredentials()
	assert.NotNil(t, err)
	assert.Equal(t, "get session token failed: 4xx error", err.Error())

	// case 5: invalid json
	hookDo = func(fn do) do {
		return func(req *http.Request) (res *http.Response, err error) {
			res = mockResponse(200, "invalid json")
			return
		}
	}
	_, err = p.getCredentials()
	assert.NotNil(t, err)
	assert.Equal(t, "get oidc sts token err, json.Unmarshal fail: invalid character 'i' looking for beginning of value", err.Error())

	// case 6: empty response json
	hookDo = func(fn do) do {
		return func(req *http.Request) (res *http.Response, err error) {
			res = mockResponse(200, "null")
			return
		}
	}
	_, err = p.getCredentials()
	assert.NotNil(t, err)
	assert.Equal(t, "get oidc sts token err, fail to get credentials", err.Error())

	// case 7: empty session ak response json
	hookDo = func(fn do) do {
		return func(req *http.Request) (res *http.Response, err error) {
			res = mockResponse(200, `{"Credentials": {}}`)
			return
		}
	}
	_, err = p.getCredentials()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh RoleArn sts token err, fail to get credentials", err.Error())

	// case 8: mock ok value
	hookDo = func(fn do) do {
		return func(req *http.Request) (res *http.Response, err error) {
			res = mockResponse(200, `{"Credentials": {"AccessKeyId":"saki","AccessKeySecret":"saks","Expiration":"2021-10-20T04:27:09Z","SecurityToken":"token"}}`)
			return
		}
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

func TestOIDCCredentialsProvider_getCredentialsWithRequestCheck(t *testing.T) {
	originDo := hookDo
	defer func() { hookDo = originDo }()

	// case 1: mock new http request failed
	wd, _ := os.Getwd()
	p, err := NewOIDCCredentialsProviderBuilder().
		// read a normal token
		WithOIDCTokenFilePath(path.Join(wd, "fixtures/mock_oidctoken")).
		WithOIDCProviderARN("provider-arn").
		WithRoleArn("roleArn").
		WithRoleSessionName("rsn").
		WithPolicy("policy").
		WithDurationSeconds(1000).
		Build()

	assert.Nil(t, err)

	// case 1: server error
	hookDo = func(fn do) do {
		return func(req *http.Request) (res *http.Response, err error) {
			assert.Equal(t, "sts.aliyuncs.com", req.Host)
			assert.Contains(t, req.URL.String(), "Action=AssumeRoleWithOIDC")
			body, err := ioutil.ReadAll(req.Body)
			assert.Nil(t, err)
			bodyString := string(body)
			assert.Contains(t, bodyString, "Policy=policy")
			assert.Contains(t, bodyString, "RoleArn=roleArn")
			assert.Contains(t, bodyString, "RoleSessionName=rsn")
			assert.Contains(t, bodyString, "DurationSeconds=1000")

			err = errors.New("mock server error")
			return
		}
	}

	_, err = p.getCredentials()
	assert.NotNil(t, err)
	assert.Equal(t, "mock server error", err.Error())
}

func TestOIDCCredentialsProviderGetCredentials(t *testing.T) {
	originDo := hookDo
	defer func() { hookDo = originDo }()

	// case 1: mock new http request failed
	wd, _ := os.Getwd()
	p, err := NewOIDCCredentialsProviderBuilder().
		// read a normal token
		WithOIDCTokenFilePath(path.Join(wd, "fixtures/mock_oidctoken")).
		WithOIDCProviderARN("provider-arn").
		WithRoleArn("roleArn").
		WithRoleSessionName("rsn").
		WithPolicy("policy").
		WithDurationSeconds(1000).
		Build()

	assert.Nil(t, err)

	// case 1: get credentials failed
	hookDo = func(fn do) do {
		return func(req *http.Request) (res *http.Response, err error) {
			err = errors.New("mock server error")
			return
		}
	}
	_, err = p.GetCredentials()
	assert.NotNil(t, err)
	assert.Equal(t, "mock server error", err.Error())

	// case 2: get invalid expiration
	hookDo = func(fn do) do {
		return func(req *http.Request) (res *http.Response, err error) {
			res = mockResponse(200, `{"Credentials": {"AccessKeyId":"akid","AccessKeySecret":"aksecret","Expiration":"invalidexpiration","SecurityToken":"ststoken"}}`)
			return
		}
	}
	_, err = p.GetCredentials()
	assert.NotNil(t, err)
	assert.Equal(t, "parsing time \"invalidexpiration\" as \"2006-01-02T15:04:05Z\": cannot parse \"invalidexpiration\" as \"2006\"", err.Error())

	// case 3: happy result
	hookDo = func(fn do) do {
		return func(req *http.Request) (res *http.Response, err error) {
			res = mockResponse(200, `{"Credentials": {"AccessKeyId":"akid","AccessKeySecret":"aksecret","Expiration":"2021-10-20T04:27:09Z","SecurityToken":"ststoken"}}`)
			return
		}
	}
	cc, err := p.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, "akid", cc.AccessKeyId)
	assert.Equal(t, "aksecret", cc.AccessKeySecret)
	assert.Equal(t, "ststoken", cc.SecurityToken)
	assert.Equal(t, "oidc_role_arn", cc.ProviderName)
	assert.True(t, p.needUpdateCredential())
}
