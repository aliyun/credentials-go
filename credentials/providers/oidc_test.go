package providers

import (
	"errors"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	httputil "github.com/aliyun/credentials-go/credentials/internal/http"
	"github.com/aliyun/credentials-go/credentials/internal/utils"
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
		WithHttpOptions(&HttpOptions{
			ConnectTimeout: 10000,
		}).
		Build()

	assert.Nil(t, err)
	assert.Equal(t, 10000, p.httpOptions.ConnectTimeout)
	_, err = p.GetCredentials()
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "AuthenticationFail.NoPermission")
}

func TestNewOIDCCredentialsProvider(t *testing.T) {
	rollback := utils.Memory("ALIBABA_CLOUD_OIDC_TOKEN_FILE", "ALIBABA_CLOUD_OIDC_PROVIDER_ARN", "ALIBABA_CLOUD_ROLE_ARN", "ALIBABA_CLOUD_STS_REGION", "ALIBABA_CLOUD_VPC_ENDPOINT_ENABLED")
	defer func() {
		rollback()
	}()

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

	p, err = NewOIDCCredentialsProviderBuilder().
		Build()
	assert.Nil(t, err)

	assert.Equal(t, "/path/from/env", p.oidcTokenFilePath)
	assert.Equal(t, "provider_arn_from_env", p.oidcProviderARN)
	assert.Equal(t, "role_arn_from_env", p.roleArn)
	// sts endpoint: default
	assert.Equal(t, "sts.aliyuncs.com", p.stsEndpoint)

	// sts endpoint: with sts endpoint env
	os.Setenv("ALIBABA_CLOUD_STS_REGION", "cn-hangzhou")
	os.Setenv("ALIBABA_CLOUD_VPC_ENDPOINT_ENABLED", "true")
	p, err = NewOIDCCredentialsProviderBuilder().
		Build()
	assert.Nil(t, err)
	assert.Equal(t, "sts-vpc.cn-hangzhou.aliyuncs.com", p.stsEndpoint)

	// sts endpoint: with sts endpoint
	p, err = NewOIDCCredentialsProviderBuilder().
		WithSTSEndpoint("sts.cn-shanghai.aliyuncs.com").
		Build()
	assert.Nil(t, err)
	assert.Equal(t, "sts.cn-shanghai.aliyuncs.com", p.stsEndpoint)

	// sts endpoint: with sts regionId
	p, err = NewOIDCCredentialsProviderBuilder().
		WithStsRegionId("cn-beijing").
		WithEnableVpc(true).
		Build()
	assert.Nil(t, err)
	assert.Equal(t, "sts-vpc.cn-beijing.aliyuncs.com", p.stsEndpoint)

	os.Setenv("ALIBABA_CLOUD_VPC_ENDPOINT_ENABLED", "false")
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
	originHttpDo := httpDo
	defer func() { httpDo = originHttpDo }()

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

	// case 2: server error
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		err = errors.New("mock server error")
		return
	}
	_, err = p.getCredentials()
	assert.NotNil(t, err)
	assert.Equal(t, "mock server error", err.Error())

	// case 3: 4xx error
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		res = &httputil.Response{
			StatusCode: 400,
			Body:       []byte("4xx error"),
		}
		return
	}
	_, err = p.getCredentials()
	assert.NotNil(t, err)
	assert.Equal(t, "get session token failed: 4xx error", err.Error())

	// case 4: invalid json
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		res = &httputil.Response{
			StatusCode: 200,
			Body:       []byte("invalid json"),
		}
		return
	}
	_, err = p.getCredentials()
	assert.NotNil(t, err)
	assert.Equal(t, "get oidc sts token err, json.Unmarshal fail: invalid character 'i' looking for beginning of value", err.Error())

	// case 5: empty response json
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		res = &httputil.Response{
			StatusCode: 200,
			Body:       []byte("null"),
		}
		return
	}
	_, err = p.getCredentials()
	assert.NotNil(t, err)
	assert.Equal(t, "get oidc sts token err, fail to get credentials", err.Error())

	// case 6: empty session ak response json
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		res = &httputil.Response{
			StatusCode: 200,
			Body:       []byte(`{"Credentials": {}}`),
		}
		return
	}
	_, err = p.getCredentials()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh RoleArn sts token err, fail to get credentials", err.Error())

	// case 7: mock ok value
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		res = &httputil.Response{
			StatusCode: 200,
			Body:       []byte(`{"Credentials": {"AccessKeyId":"saki","AccessKeySecret":"saks","Expiration":"2021-10-20T04:27:09Z","SecurityToken":"token"}}`),
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

func TestOIDCCredentialsProvider_getCredentialsWithRequestCheck(t *testing.T) {
	originHttpDo := httpDo
	defer func() { httpDo = originHttpDo }()

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
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		assert.Equal(t, "sts.aliyuncs.com", req.Host)
		assert.Equal(t, "AssumeRoleWithOIDC", req.Queries["Action"])
		assert.Equal(t, "policy", req.Form["Policy"])
		assert.Equal(t, "roleArn", req.Form["RoleArn"])
		assert.Equal(t, "rsn", req.Form["RoleSessionName"])
		assert.Equal(t, "1000", req.Form["DurationSeconds"])

		err = errors.New("mock server error")
		return
	}
	_, err = p.getCredentials()
	assert.NotNil(t, err)
	assert.Equal(t, "mock server error", err.Error())
}

func TestOIDCCredentialsProviderGetCredentials(t *testing.T) {
	originHttpDo := httpDo
	defer func() { httpDo = originHttpDo }()

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

	// case 2: get credentials failed
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
	assert.Equal(t, "oidc_role_arn", cc.ProviderName)
	assert.True(t, p.needUpdateCredential())
}

func TestOIDCCredentialsProviderGetCredentialsWithHttpOptions(t *testing.T) {
	wd, _ := os.Getwd()
	p, err := NewOIDCCredentialsProviderBuilder().
		// read a normal token
		WithOIDCTokenFilePath(path.Join(wd, "fixtures/mock_oidctoken")).
		WithOIDCProviderARN("provider-arn").
		WithRoleArn("roleArn").
		WithRoleSessionName("rsn").
		WithPolicy("policy").
		WithDurationSeconds(1000).
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
