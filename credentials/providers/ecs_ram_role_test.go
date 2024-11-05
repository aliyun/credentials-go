package providers

import (
	"errors"
	"os"
	"testing"
	"time"

	httputil "github.com/aliyun/credentials-go/credentials/internal/http"
	"github.com/aliyun/credentials-go/credentials/internal/utils"
	"github.com/stretchr/testify/assert"
)

func TestNewECSRAMRoleCredentialsProvider(t *testing.T) {
	rollback := utils.Memory("ALIBABA_CLOUD_ECS_METADATA_DISABLED", "ALIBABA_CLOUD_ECS_METADATA", "ALIBABA_CLOUD_IMDSV1_DISABLED")
	defer func() {
		rollback()
	}()
	p, err := NewECSRAMRoleCredentialsProviderBuilder().Build()
	assert.Nil(t, err)
	assert.Equal(t, "", p.roleName)

	os.Setenv("ALIBABA_CLOUD_ECS_METADATA", "rolename")
	p, err = NewECSRAMRoleCredentialsProviderBuilder().Build()
	assert.Nil(t, err)
	assert.Equal(t, "rolename", p.roleName)

	p, err = NewECSRAMRoleCredentialsProviderBuilder().WithRoleName("role").Build()
	assert.Nil(t, err)
	assert.Equal(t, "role", p.roleName)
	assert.False(t, p.disableIMDSv1)

	os.Setenv("ALIBABA_CLOUD_IMDSV1_DISABLED", "True")
	p, err = NewECSRAMRoleCredentialsProviderBuilder().Build()
	assert.Nil(t, err)
	assert.True(t, p.disableIMDSv1)

	os.Setenv("ALIBABA_CLOUD_IMDSV1_DISABLED", "1")
	p, err = NewECSRAMRoleCredentialsProviderBuilder().WithDisableIMDSv1(true).Build()
	assert.Nil(t, err)
	assert.True(t, p.disableIMDSv1)

	os.Setenv("ALIBABA_CLOUD_ECS_METADATA_DISABLED", "True")
	_, err = NewECSRAMRoleCredentialsProviderBuilder().Build()
	assert.Equal(t, "IMDS credentials is disabled", err.Error())

	assert.True(t, p.needUpdateCredential())
}

func TestECSRAMRoleCredentialsProvider_getRoleName(t *testing.T) {
	originHttpDo := httpDo
	defer func() { httpDo = originHttpDo }()

	p, err := NewECSRAMRoleCredentialsProviderBuilder().Build()
	assert.Nil(t, err)

	// case 1: server error
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		err = errors.New("mock server error")
		return
	}

	_, err = p.getRoleName()
	assert.NotNil(t, err)
	assert.Equal(t, "get role name failed: mock server error", err.Error())

	// case 2: 4xx error
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		res = &httputil.Response{
			StatusCode: 400,
			Body:       []byte("4xx error"),
		}
		return
	}

	_, err = p.getRoleName()
	assert.NotNil(t, err)
	assert.Equal(t, "get role name failed: GET http://100.100.100.200/latest/meta-data/ram/security-credentials/ 400", err.Error())

	// case 3: ok
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		res = &httputil.Response{
			StatusCode: 200,
			Body:       []byte("rolename"),
		}
		return
	}
	roleName, err := p.getRoleName()
	assert.Nil(t, err)
	assert.Equal(t, "rolename", roleName)
}

func TestECSRAMRoleCredentialsProvider_getRoleNameWithMetadataV2(t *testing.T) {
	originHttpDo := httpDo
	defer func() { httpDo = originHttpDo }()

	p, err := NewECSRAMRoleCredentialsProviderBuilder().WithDisableIMDSv1(true).Build()
	assert.Nil(t, err)

	// case 1: get metadata token failed
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		err = errors.New("mock server error")
		return
	}

	_, err = p.getRoleName()
	assert.NotNil(t, err)
	assert.Equal(t, "get metadata token failed: mock server error", err.Error())

	// case 2: return token
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		if req.Path == "/latest/api/token" {
			res = &httputil.Response{
				StatusCode: 200,
				Body:       []byte("tokenxxxxx"),
			}
		} else {
			assert.Equal(t, "tokenxxxxx", req.Headers["x-aliyun-ecs-metadata-token"])

			res = &httputil.Response{
				StatusCode: 200,
				Body:       []byte("rolename"),
			}
		}
		return
	}

	roleName, err := p.getRoleName()
	assert.Nil(t, err)
	assert.Equal(t, "rolename", roleName)
}

func TestECSRAMRoleCredentialsProvider_getCredentials(t *testing.T) {
	originHttpDo := httpDo
	defer func() { httpDo = originHttpDo }()

	p, err := NewECSRAMRoleCredentialsProviderBuilder().Build()
	assert.Nil(t, err)

	// case 1: server error
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		err = errors.New("mock server error")
		return
	}
	_, err = p.getCredentials()
	assert.NotNil(t, err)
	assert.Equal(t, "get role name failed: mock server error", err.Error())

	// case 2: get role name ok, get credentials failed with server error
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		if req.Path == "/latest/meta-data/ram/security-credentials/" {
			res = &httputil.Response{
				StatusCode: 200,
				Body:       []byte("rolename"),
			}
			return
		}
		err = errors.New("mock server error")
		return
	}

	_, err = p.getCredentials()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh Ecs sts token err: mock server error", err.Error())

	// case 3: 4xx error
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		if req.Path == "/latest/meta-data/ram/security-credentials/" {
			res = &httputil.Response{
				StatusCode: 200,
				Body:       []byte("rolename"),
			}
			return
		}

		res = &httputil.Response{
			StatusCode: 400,
			Body:       []byte("4xx error"),
		}
		return
	}

	_, err = p.getCredentials()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh Ecs sts token err, httpStatus: 400, message = 4xx error", err.Error())

	// case 4: invalid json
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		if req.Path == "/latest/meta-data/ram/security-credentials/" {
			res = &httputil.Response{
				StatusCode: 200,
				Body:       []byte("rolename"),
			}
			return
		}

		res = &httputil.Response{
			StatusCode: 200,
			Body:       []byte("invalid json"),
		}
		return
	}

	_, err = p.getCredentials()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh Ecs sts token err, json.Unmarshal fail: invalid character 'i' looking for beginning of value", err.Error())

	// case 5: empty response json
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		if req.Path == "/latest/meta-data/ram/security-credentials/" {
			res = &httputil.Response{
				StatusCode: 200,
				Body:       []byte("rolename"),
			}
			return
		}

		res = &httputil.Response{
			StatusCode: 200,
			Body:       []byte("null"),
		}
		return
	}

	_, err = p.getCredentials()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh Ecs sts token err, fail to get credentials", err.Error())

	// case 6: empty session ak response json
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		if req.Path == "/latest/meta-data/ram/security-credentials/" {
			res = &httputil.Response{
				StatusCode: 200,
				Body:       []byte("rolename"),
			}
			return
		}

		res = &httputil.Response{
			StatusCode: 200,
			Body:       []byte("{}"),
		}
		return
	}
	_, err = p.getCredentials()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh Ecs sts token err, fail to get credentials", err.Error())

	// case 7: non-success response
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		if req.Path == "/latest/meta-data/ram/security-credentials/" {
			res = &httputil.Response{
				StatusCode: 200,
				Body:       []byte("rolename"),
			}
			return
		}

		res = &httputil.Response{
			StatusCode: 200,
			Body:       []byte(`{"AccessKeyId":"saki","AccessKeySecret":"saks","Expiration":"2021-10-20T04:27:09Z","SecurityToken":"token","Code":"Failed"}`),
		}
		return
	}
	_, err = p.getCredentials()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh Ecs sts token err, Code is not Success", err.Error())

	// case 8: mock ok value
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		if req.Path == "/latest/meta-data/ram/security-credentials/" {
			res = &httputil.Response{
				StatusCode: 200,
				Body:       []byte("rolename"),
			}
			return
		}

		res = &httputil.Response{
			StatusCode: 200,
			Body:       []byte(`{"AccessKeyId":"saki","AccessKeySecret":"saks","Expiration":"2021-10-20T04:27:09Z","SecurityToken":"token","Code":"Success"}`),
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

func TestECSRAMRoleCredentialsProvider_getCredentialsWithMetadataV2(t *testing.T) {
	originHttpDo := httpDo
	defer func() { httpDo = originHttpDo }()

	p, err := NewECSRAMRoleCredentialsProviderBuilder().WithDisableIMDSv1(true).WithRoleName("rolename").Build()
	assert.Nil(t, err)

	// case 1: get metadata token failed
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		err = errors.New("mock server error")
		return
	}

	_, err = p.getCredentials()
	assert.NotNil(t, err)
	assert.Equal(t, "get metadata token failed: mock server error", err.Error())

	// case 2: return token
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		if req.Path == "/latest/api/token" {
			res = &httputil.Response{
				StatusCode: 200,
				Body:       []byte("tokenxxxxx"),
			}
		} else if req.Path == "/latest/meta-data/ram/security-credentials/rolename" {
			assert.Equal(t, "tokenxxxxx", req.Headers["x-aliyun-ecs-metadata-token"])
			res = &httputil.Response{
				StatusCode: 200,
				Body:       []byte(`{"AccessKeyId":"saki","AccessKeySecret":"saks","Expiration":"2021-10-20T04:27:09Z","SecurityToken":"token","Code":"Success"}`),
			}
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

func TestECSRAMRoleCredentialsProviderGetCredentials(t *testing.T) {
	originHttpDo := httpDo
	defer func() { httpDo = originHttpDo }()

	p, err := NewECSRAMRoleCredentialsProviderBuilder().WithRoleName("rolename").Build()
	assert.Nil(t, err)
	// case 1: get credentials failed
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		err = errors.New("mock server error")
		return
	}
	_, err = p.GetCredentials()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh Ecs sts token err: mock server error", err.Error())

	// case 2: get invalid expiration
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		res = &httputil.Response{
			StatusCode: 200,
			Body:       []byte(`{"AccessKeyId":"saki","AccessKeySecret":"saks","Expiration":"invalidexpiration","SecurityToken":"token","Code":"Success"}`),
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
			Body:       []byte(`{"AccessKeyId":"akid","AccessKeySecret":"aksecret","Expiration":"2021-10-20T04:27:09Z","SecurityToken":"token","Code":"Success"}`),
		}
		return
	}
	cc, err := p.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, "akid", cc.AccessKeyId)
	assert.Equal(t, "aksecret", cc.AccessKeySecret)
	assert.Equal(t, "token", cc.SecurityToken)
	assert.True(t, p.needUpdateCredential())
}

func TestECSRAMRoleCredentialsProvider_getMetadataToken(t *testing.T) {
	rollback := utils.Memory("ALIBABA_CLOUD_IMDSV1_DISABLED")
	defer func() {
		rollback()
	}()

	originHttpDo := httpDo
	defer func() { httpDo = originHttpDo }()

	p, err := NewECSRAMRoleCredentialsProviderBuilder().Build()
	assert.Nil(t, err)

	// case 1: server error
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		err = errors.New("mock server error")
		return
	}

	_, err = p.getMetadataToken()
	assert.Nil(t, err)

	p, err = NewECSRAMRoleCredentialsProviderBuilder().WithDisableIMDSv1(false).Build()
	assert.Nil(t, err)

	_, err = p.getMetadataToken()
	assert.Nil(t, err)

	os.Setenv("ALIBABA_CLOUD_IMDSV1_DISABLED", "true")
	p, err = NewECSRAMRoleCredentialsProviderBuilder().Build()
	assert.Nil(t, err)

	_, err = p.getMetadataToken()
	assert.NotNil(t, err)

	os.Setenv("ALIBABA_CLOUD_IMDSV1_DISABLED", "")
	p, err = NewECSRAMRoleCredentialsProviderBuilder().Build()
	assert.Nil(t, err)

	_, err = p.getMetadataToken()
	assert.Nil(t, err)

	p, err = NewECSRAMRoleCredentialsProviderBuilder().WithDisableIMDSv1(true).Build()
	assert.Nil(t, err)

	_, err = p.getMetadataToken()
	assert.NotNil(t, err)

	assert.Equal(t, "get metadata token failed: mock server error", err.Error())

	// case 2: return token
	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		res = &httputil.Response{
			StatusCode: 200,
			Body:       []byte("tokenxxxxx"),
		}
		return
	}
	metadataToken, err := p.getMetadataToken()
	assert.Nil(t, err)
	assert.Equal(t, "tokenxxxxx", metadataToken)

	// case 3: return 404
	p, err = NewECSRAMRoleCredentialsProviderBuilder().WithDisableIMDSv1(false).Build()
	assert.Nil(t, err)

	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		res = &httputil.Response{
			StatusCode: 404,
			Body:       []byte("not found"),
		}
		return
	}
	metadataToken, err = p.getMetadataToken()
	assert.Nil(t, err)
	assert.Equal(t, "", metadataToken)

	p, err = NewECSRAMRoleCredentialsProviderBuilder().WithDisableIMDSv1(true).Build()
	assert.Nil(t, err)

	metadataToken, err = p.getMetadataToken()
	assert.NotNil(t, err)
	assert.Equal(t, "", metadataToken)
}

func TestNewECSRAMRoleCredentialsProviderWithHttpOptions(t *testing.T) {
	p, err := NewECSRAMRoleCredentialsProviderBuilder().
		WithRoleName("test").
		WithHttpOptions(&HttpOptions{
			ConnectTimeout: 1000,
			ReadTimeout:    1000,
			Proxy:          "localhost:3999",
		}).
		Build()
	assert.Nil(t, err)

	_, err = p.getRoleName()
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "proxyconnect tcp:")

	_, err = p.getCredentials()
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "proxyconnect tcp:")

	_, err = p.GetCredentials()
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "proxyconnect tcp:")
}
