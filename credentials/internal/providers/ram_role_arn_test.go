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

func TestNewRAMRoleARNCredentialsProvider(t *testing.T) {
	rollback := utils.Memory("ALIBABA_CLOUD_STS_REGION")
	defer func() {
		rollback()
	}()
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
		WithStsRegionId("cn-hangzhou").
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
	assert.Equal(t, "cn-hangzhou", p.stsRegionId)
	assert.Equal(t, 1000, p.durationSeconds)
	// sts endpoint with sts region
	assert.Equal(t, "sts.cn-hangzhou.aliyuncs.com", p.stsEndpoint)

	// default sts endpoint
	p, err = NewRAMRoleARNCredentialsProviderBuilder().
		WithCredentialsProvider(akProvider).
		WithRoleArn("roleArn").
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
	assert.Equal(t, "", p.stsRegionId)
	assert.Equal(t, 1000, p.durationSeconds)
	assert.Equal(t, "sts.aliyuncs.com", p.stsEndpoint)

	// sts endpoint with env
	os.Setenv("ALIBABA_CLOUD_STS_REGION", "cn-hangzhou")
	p, err = NewRAMRoleARNCredentialsProviderBuilder().
		WithCredentialsProvider(akProvider).
		WithRoleArn("roleArn").
		WithPolicy("policy").
		WithExternalId("externalId").
		WithRoleSessionName("rsn").
		WithDurationSeconds(1000).
		Build()
	assert.Nil(t, err)
	assert.Equal(t, "sts.cn-hangzhou.aliyuncs.com", p.stsEndpoint)

	// sts endpoint with sts endpoint
	p, err = NewRAMRoleARNCredentialsProviderBuilder().
		WithCredentialsProvider(akProvider).
		WithRoleArn("roleArn").
		WithStsEndpoint("sts.cn-shanghai.aliyuncs.com").
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
	assert.Equal(t, "", p.stsRegionId)
	assert.Equal(t, 1000, p.durationSeconds)
	assert.Equal(t, "sts.cn-shanghai.aliyuncs.com", p.stsEndpoint)
}

func TestRAMRoleARNCredentialsProvider_getCredentials(t *testing.T) {
	originHttpDo := httpDo
	defer func() { httpDo = originHttpDo }()

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

	// case 1: server error
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		err = errors.New("mock server error")
		return
	}
	_, err = p.getCredentials(cc)
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

	_, err = p.getCredentials(cc)
	assert.NotNil(t, err)
	assert.Equal(t, "refresh session token failed: 4xx error", err.Error())

	// case 3: invalid json
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		res = &httputil.Response{
			StatusCode: 200,
			Body:       []byte("invalid json"),
		}
		return
	}
	_, err = p.getCredentials(cc)
	assert.NotNil(t, err)
	assert.Equal(t, "refresh RoleArn sts token err, json.Unmarshal fail: invalid character 'i' looking for beginning of value", err.Error())

	// case 4: empty response json
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		res = &httputil.Response{
			StatusCode: 200,
			Body:       []byte("null"),
		}
		return
	}
	_, err = p.getCredentials(cc)
	assert.NotNil(t, err)
	assert.Equal(t, "refresh RoleArn sts token err, fail to get credentials", err.Error())

	// case 5: empty session ak response json
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		res = &httputil.Response{
			StatusCode: 200,
			Body:       []byte(`{"Credentials": {}}`),
		}
		return
	}
	_, err = p.getCredentials(cc)
	assert.NotNil(t, err)
	assert.Equal(t, "refresh RoleArn sts token err, fail to get credentials", err.Error())

	// case 6: mock ok value
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		res = &httputil.Response{
			StatusCode: 200,
			Body:       []byte(`{"Credentials": {"AccessKeyId":"saki","AccessKeySecret":"saks","Expiration":"2021-10-20T04:27:09Z","SecurityToken":"token"}}`),
		}
		return
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
	originHttpDo := httpDo
	defer func() { httpDo = originHttpDo }()

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
		WithStsRegionId("cn-beijing").
		WithExternalId("externalId").
		Build()
	assert.Nil(t, err)

	// case 1: server error
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		assert.Equal(t, "sts.cn-beijing.aliyuncs.com", req.Host)
		assert.Equal(t, "ststoken", req.Queries["SecurityToken"])
		assert.Equal(t, "policy", req.Form["Policy"])
		assert.Equal(t, "roleArn", req.Form["RoleArn"])
		assert.Equal(t, "rsn", req.Form["RoleSessionName"])
		assert.Equal(t, "1000", req.Form["DurationSeconds"])

		err = errors.New("mock server error")
		return
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
	originHttpDo := httpDo
	defer func() { httpDo = originHttpDo }()

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
			Body:       []byte(`{"Credentials": {"AccessKeyId":"akid","AccessKeySecret":"aksecret","Expiration":"invalidexpiration","SecurityToken":"ststoken"}}`),
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
			Body:       []byte(`{"Credentials": {"AccessKeyId":"akid","AccessKeySecret":"aksecret","Expiration":"2021-10-20T04:27:09Z","SecurityToken":"ststoken"}}`),
		}
		return
	}
	cc, err := p.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, "akid", cc.AccessKeyId)
	assert.Equal(t, "aksecret", cc.AccessKeySecret)
	assert.Equal(t, "ststoken", cc.SecurityToken)
	assert.Equal(t, "ram_role_arn/static_ak", cc.ProviderName)
	assert.True(t, p.needUpdateCredential())
	// get credentials again
	cc, err = p.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, "akid", cc.AccessKeyId)
	assert.Equal(t, "aksecret", cc.AccessKeySecret)
	assert.Equal(t, "ststoken", cc.SecurityToken)
	assert.Equal(t, "ram_role_arn/static_ak", cc.ProviderName)
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

func TestRAMRoleARNCredentialsProviderWithHttpOptions(t *testing.T) {
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
		WithHttpOptions(&HttpOptions{
			ConnectTimeout: 1,
			ReadTimeout:    1,
			Proxy:          "localhost:3999",
		}).
		Build()
	assert.Nil(t, err)
	_, err = p.GetCredentials()
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "proxyconnect tcp:")
}
