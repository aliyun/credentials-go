package providers

import (
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type errorReader struct {
}

func (r *errorReader) Read(p []byte) (n int, err error) {
	err = errors.New("read failed")
	return
}

func TestNewRAMRoleARNCredentialsProvider(t *testing.T) {
	// case 1: no credentials provider
	_, err := NewRAMRoleARNCredentialsProviderBuilder().
		Build()
	assert.EqualError(t, err, "must specify a previous credentials provider to asssume role")

	// case 2: no role arn
	akProvider, err := NewStaticAKCredentialsProviderBuilder().
		WithAccessKeyId("akid").
		WithAccessKeySecret("aksecret").
		Build()
	assert.Nil(t, err)
	_, err = NewRAMRoleARNCredentialsProviderBuilder().
		WithCredentialsProvider(akProvider).
		Build()
	assert.EqualError(t, err, "the RoleArn is empty")

	// case 3: check default role session name
	p, err := NewRAMRoleARNCredentialsProviderBuilder().
		WithCredentialsProvider(akProvider).
		WithRoleArn("roleArn").
		Build()
	assert.Nil(t, err)
	assert.True(t, strings.HasPrefix(p.roleSessionName, "credentials-go-"))

	// case 4: check default duration seconds
	p, err = NewRAMRoleARNCredentialsProviderBuilder().
		WithCredentialsProvider(akProvider).
		WithRoleArn("roleArn").Build()
	assert.Nil(t, err)
	assert.Equal(t, 3600, p.durationSeconds)

	// case 5: check invalid duration seconds
	_, err = NewRAMRoleARNCredentialsProviderBuilder().
		WithCredentialsProvider(akProvider).
		WithRoleArn("roleArn").
		WithDurationSeconds(100).
		Build()
	assert.EqualError(t, err, "session duration should be in the range of 900s - max session duration")

	// case 6: check all duration seconds
	p, err = NewRAMRoleARNCredentialsProviderBuilder().
		WithCredentialsProvider(akProvider).
		WithRoleArn("roleArn").
		WithStsRegion("cn-hangzhou").
		WithPolicy("policy").
		WithExternalId("externalId").
		WithRoleSessionName("rsn").
		WithDurationSeconds(1000).
		Build()
	assert.Nil(t, err)
	assert.Equal(t, "rsn", p.roleSessionName)
	assert.Equal(t, "roleArn", p.roleArn)
	assert.Equal(t, "policy", p.policy)
	assert.Equal(t, "externalId", p.externalId)
	assert.Equal(t, "cn-hangzhou", p.stsRegion)
	assert.Equal(t, 1000, p.durationSeconds)
}

func TestRAMRoleARNCredentialsProvider_getCredentials(t *testing.T) {
	akProvider, err := NewStaticAKCredentialsProviderBuilder().
		WithAccessKeyId("akid").
		WithAccessKeySecret("aksecret").
		Build()
	assert.Nil(t, err)
	p, err := NewRAMRoleARNCredentialsProviderBuilder().
		WithCredentialsProvider(akProvider).
		WithRoleArn("roleArn").
		WithRoleSessionName("rsn").
		WithDurationSeconds(1000).
		Build()
	assert.Nil(t, err)

	cc, err := akProvider.GetCredentials()
	assert.Nil(t, err)

	originNewRequest := hookNewRequest
	defer func() { hookNewRequest = originNewRequest }()

	// case 1: mock new http request failed
	hookNewRequest = func(fn newReuqest) newReuqest {
		return func(method, url string, body io.Reader) (*http.Request, error) {
			return nil, errors.New("new http request failed")
		}
	}
	_, err = p.getCredentials(cc)
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
	_, err = p.getCredentials(cc)
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
	_, err = p.getCredentials(cc)
	assert.NotNil(t, err)
	assert.Equal(t, "read failed", err.Error())

	// case 4: 4xx error
	hookDo = func(fn do) do {
		return func(req *http.Request) (res *http.Response, err error) {
			res = mockResponse(400, "4xx error")
			return
		}
	}
	_, err = p.getCredentials(cc)
	assert.NotNil(t, err)
	assert.Equal(t, "refresh session token failed: 4xx error", err.Error())

	// case 5: invalid json
	hookDo = func(fn do) do {
		return func(req *http.Request) (res *http.Response, err error) {
			res = mockResponse(200, "invalid json")
			return
		}
	}
	_, err = p.getCredentials(cc)
	assert.NotNil(t, err)
	assert.Equal(t, "refresh RoleArn sts token err, json.Unmarshal fail: invalid character 'i' looking for beginning of value", err.Error())

	// case 6: empty response json
	hookDo = func(fn do) do {
		return func(req *http.Request) (res *http.Response, err error) {
			res = mockResponse(200, "null")
			return
		}
	}
	_, err = p.getCredentials(cc)
	assert.NotNil(t, err)
	assert.Equal(t, "refresh RoleArn sts token err, fail to get credentials", err.Error())

	// case 7: empty session ak response json
	hookDo = func(fn do) do {
		return func(req *http.Request) (res *http.Response, err error) {
			res = mockResponse(200, `{"Credentials": {}}`)
			return
		}
	}
	_, err = p.getCredentials(cc)
	assert.NotNil(t, err)
	assert.Equal(t, "refresh RoleArn sts token err, fail to get credentials", err.Error())

	// case 8: mock ok value
	hookDo = func(fn do) do {
		return func(req *http.Request) (res *http.Response, err error) {
			res = mockResponse(200, `{"Credentials": {"AccessKeyId":"saki","AccessKeySecret":"saks","Expiration":"2021-10-20T04:27:09Z","SecurityToken":"token"}}`)
			return
		}
	}
	creds, err := p.getCredentials(cc)
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

func TestRAMRoleARNCredentialsProvider_getCredentialsWithRequestCheck(t *testing.T) {
	originDo := hookDo
	defer func() { hookDo = originDo }()

	stsProvider, err := NewStaticSTSCredentialsProviderBuilder().
		WithAccessKeyId("akid").
		WithAccessKeySecret("aksecret").
		WithSecurityToken("ststoken").
		Build()
	assert.Nil(t, err)
	p, err := NewRAMRoleARNCredentialsProviderBuilder().
		WithCredentialsProvider(stsProvider).
		WithRoleArn("roleArn").
		WithRoleSessionName("rsn").
		WithDurationSeconds(1000).
		WithPolicy("policy").
		WithStsRegion("cn-beijing").
		WithExternalId("externalId").
		Build()
	assert.Nil(t, err)

	// case 1: server error
	hookDo = func(fn do) do {
		return func(req *http.Request) (res *http.Response, err error) {
			assert.Equal(t, "sts.cn-beijing.aliyuncs.com", req.Host)
			assert.Contains(t, req.URL.String(), "SecurityToken=ststoken")
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

	cc, err := stsProvider.GetCredentials()
	assert.Nil(t, err)
	_, err = p.getCredentials(cc)
	assert.NotNil(t, err)
	assert.Equal(t, "mock server error", err.Error())
}

type errorCredentialsProvider struct {
}

func (p *errorCredentialsProvider) GetCredentials() (cc *Credentials, err error) {
	err = errors.New("get credentials failed")
	return
}

func (p *errorCredentialsProvider) GetProviderName() string {
	return "error_credentials_provider"
}

func TestRAMRoleARNCredentialsProviderGetCredentials(t *testing.T) {
	originDo := hookDo
	defer func() { hookDo = originDo }()

	// case 0: get previous credentials failed
	p, err := NewRAMRoleARNCredentialsProviderBuilder().
		WithCredentialsProvider(&errorCredentialsProvider{}).
		WithRoleArn("roleArn").
		WithRoleSessionName("rsn").
		WithDurationSeconds(1000).
		Build()
	assert.Nil(t, err)
	_, err = p.GetCredentials()
	assert.Equal(t, "get credentials failed", err.Error())

	akProvider, err := NewStaticAKCredentialsProviderBuilder().
		WithAccessKeyId("akid").
		WithAccessKeySecret("aksecret").
		Build()
	assert.Nil(t, err)

	p, err = NewRAMRoleARNCredentialsProviderBuilder().
		WithCredentialsProvider(akProvider).
		WithRoleArn("roleArn").
		WithRoleSessionName("rsn").
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
	assert.True(t, p.needUpdateCredential())
}

func TestRAMRoleARNCredentialsProviderGetCredentialsWithError(t *testing.T) {
	akProvider, err := NewStaticAKCredentialsProviderBuilder().
		WithAccessKeyId("akid").
		WithAccessKeySecret("aksecret").
		Build()
	assert.Nil(t, err)
	p, err := NewRAMRoleARNCredentialsProviderBuilder().
		WithCredentialsProvider(akProvider).
		WithRoleArn("roleArn").
		WithRoleSessionName("rsn").
		WithDurationSeconds(1000).
		Build()
	assert.Nil(t, err)
	_, err = p.GetCredentials()
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "InvalidAccessKeyId.NotFound")
}
