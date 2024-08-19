package providers

import (
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewECSRAMRoleCredentialsProvider(t *testing.T) {
	p, err := NewECSRAMRoleCredentialsProviderBuilder().Build()
	assert.Nil(t, err)
	assert.Equal(t, "", p.roleName)
	assert.Equal(t, 21600, p.metadataTokenDurationSeconds)

	_, err = NewECSRAMRoleCredentialsProviderBuilder().WithMetadataTokenDurationSeconds(1000000000).Build()
	assert.EqualError(t, err, "the metadata token duration seconds must be 1-21600")

	p, err = NewECSRAMRoleCredentialsProviderBuilder().WithRoleName("role").WithMetadataTokenDurationSeconds(3600).Build()
	assert.Nil(t, err)
	assert.Equal(t, "role", p.roleName)
	assert.Equal(t, 3600, p.metadataTokenDurationSeconds)

	assert.True(t, p.needUpdateCredential())
}

func TestECSRAMRoleCredentialsProvider_getRoleName(t *testing.T) {
	p, err := NewECSRAMRoleCredentialsProviderBuilder().Build()
	assert.Nil(t, err)

	originNewRequest := hookNewRequest
	defer func() { hookNewRequest = originNewRequest }()

	// case 1: mock new http request failed
	hookNewRequest = func(fn newReuqest) newReuqest {
		return func(method, url string, body io.Reader) (*http.Request, error) {
			return nil, errors.New("new http request failed")
		}
	}
	_, err = p.getRoleName()
	assert.NotNil(t, err)
	assert.Equal(t, "get role name failed: new http request failed", err.Error())
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
	_, err = p.getRoleName()
	assert.NotNil(t, err)
	assert.Equal(t, "get role name failed: mock server error", err.Error())

	// case 3: 4xx error
	hookDo = func(fn do) do {
		return func(req *http.Request) (res *http.Response, err error) {
			res = mockResponse(400, "4xx error")
			return
		}
	}

	_, err = p.getRoleName()
	assert.NotNil(t, err)
	assert.Equal(t, "get role name failed: request http://100.100.100.200/latest/meta-data/ram/security-credentials/ 400", err.Error())

	// case 4: mock read response error
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
	_, err = p.getRoleName()
	assert.NotNil(t, err)
	assert.Equal(t, "read failed", err.Error())

	// case 5: value json
	hookDo = func(fn do) do {
		return func(req *http.Request) (res *http.Response, err error) {
			res = mockResponse(200, "rolename")
			return
		}
	}
	roleName, err := p.getRoleName()
	assert.Nil(t, err)
	assert.Equal(t, "rolename", roleName)
}

func TestECSRAMRoleCredentialsProvider_getRoleNameWithMetadataV2(t *testing.T) {
	p, err := NewECSRAMRoleCredentialsProviderBuilder().WithEnableIMDSv2(true).Build()
	assert.Nil(t, err)

	// case 1: get metadata token failed
	originDo := hookDo
	defer func() { hookDo = originDo }()

	hookDo = func(fn do) do {
		return func(req *http.Request) (res *http.Response, err error) {
			err = errors.New("mock server error")
			return
		}
	}
	_, err = p.getRoleName()
	assert.NotNil(t, err)
	assert.Equal(t, "get metadata token failed: mock server error", err.Error())

	// case 2: return token
	hookDo = func(fn do) do {
		return func(req *http.Request) (res *http.Response, err error) {
			if req.URL.Path == "/latest/api/token" {
				res = mockResponse(200, `tokenxxxxx`)
			} else {
				assert.Equal(t, "tokenxxxxx", req.Header.Get("x-aliyun-ecs-metadata-token"))
				res = mockResponse(200, "rolename")
			}
			return
		}
	}

	roleName, err := p.getRoleName()
	assert.Nil(t, err)
	assert.Equal(t, "rolename", roleName)
}

func TestECSRAMRoleCredentialsProvider_getCredentials(t *testing.T) {
	originDo := hookDo
	defer func() { hookDo = originDo }()

	p, err := NewECSRAMRoleCredentialsProviderBuilder().Build()
	assert.Nil(t, err)

	// case 1: server error
	hookDo = func(fn do) do {
		return func(req *http.Request) (res *http.Response, err error) {
			err = errors.New("mock server error")
			return
		}
	}
	_, err = p.getCredentials()
	assert.NotNil(t, err)
	assert.Equal(t, "get role name failed: mock server error", err.Error())

	hookDo = func(fn do) do {
		return func(req *http.Request) (res *http.Response, err error) {
			if req.URL.Path == "/latest/meta-data/ram/security-credentials/" {
				res = mockResponse(200, "rolename")
				return
			}

			err = errors.New("mock server error")
			return
		}
	}

	originNewRequest := hookNewRequest
	defer func() { hookNewRequest = originNewRequest }()

	// case 2: mock new http request failed
	hookNewRequest = func(fn newReuqest) newReuqest {
		return func(method, url string, body io.Reader) (*http.Request, error) {
			if url == "http://100.100.100.200/latest/meta-data/ram/security-credentials/rolename" {
				return nil, errors.New("new http request failed")
			}
			return http.NewRequest(method, url, body)
		}
	}

	_, err = p.getCredentials()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh Ecs sts token err: new http request failed", err.Error())

	hookNewRequest = originNewRequest

	// case 3
	hookDo = func(fn do) do {
		return func(req *http.Request) (res *http.Response, err error) {
			if req.URL.Path == "/latest/meta-data/ram/security-credentials/" {
				res = mockResponse(200, "rolename")
				return
			}

			if req.URL.Path == "/latest/meta-data/ram/security-credentials/rolename" {
				err = errors.New("mock server error")
				return
			}
			return
		}
	}
	_, err = p.getCredentials()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh Ecs sts token err: mock server error", err.Error())

	// case 4: mock read response error
	hookDo = func(fn do) do {
		return func(req *http.Request) (res *http.Response, err error) {
			if req.URL.Path == "/latest/meta-data/ram/security-credentials/" {
				res = mockResponse(200, "rolename")
				return
			}

			if req.URL.Path == "/latest/meta-data/ram/security-credentials/rolename" {
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
			return
		}
	}
	_, err = p.getCredentials()
	assert.NotNil(t, err)
	assert.Equal(t, "read failed", err.Error())

	// case 4: 4xx error
	hookDo = func(fn do) do {
		return func(req *http.Request) (res *http.Response, err error) {
			if req.URL.Path == "/latest/meta-data/ram/security-credentials/" {
				res = mockResponse(200, "rolename")
				return
			}

			if req.URL.Path == "/latest/meta-data/ram/security-credentials/rolename" {
				res = mockResponse(400, "4xx error")
				return
			}
			return
		}
	}
	_, err = p.getCredentials()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh Ecs sts token err, httpStatus: 400, message = 4xx error", err.Error())

	// case 5: invalid json
	hookDo = func(fn do) do {
		return func(req *http.Request) (res *http.Response, err error) {
			if req.URL.Path == "/latest/meta-data/ram/security-credentials/" {
				res = mockResponse(200, "rolename")
				return
			}

			if req.URL.Path == "/latest/meta-data/ram/security-credentials/rolename" {
				res = mockResponse(200, "invalid json")
				return
			}
			return
		}
	}
	_, err = p.getCredentials()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh Ecs sts token err, json.Unmarshal fail: invalid character 'i' looking for beginning of value", err.Error())

	// case 6: empty response json
	hookDo = func(fn do) do {
		return func(req *http.Request) (res *http.Response, err error) {
			if req.URL.Path == "/latest/meta-data/ram/security-credentials/" {
				res = mockResponse(200, "rolename")
				return
			}

			if req.URL.Path == "/latest/meta-data/ram/security-credentials/rolename" {
				res = mockResponse(200, "null")
				return
			}
			return
		}
	}
	_, err = p.getCredentials()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh Ecs sts token err, fail to get credentials", err.Error())

	// case 7: empty session ak response json
	hookDo = func(fn do) do {
		return func(req *http.Request) (res *http.Response, err error) {
			if req.URL.Path == "/latest/meta-data/ram/security-credentials/" {
				res = mockResponse(200, "rolename")
				return
			}

			if req.URL.Path == "/latest/meta-data/ram/security-credentials/rolename" {
				res = mockResponse(200, `{}`)
				return
			}
			return
		}
	}
	_, err = p.getCredentials()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh Ecs sts token err, fail to get credentials", err.Error())

	// case 8: non-success response
	hookDo = func(fn do) do {
		return func(req *http.Request) (res *http.Response, err error) {
			if req.URL.Path == "/latest/meta-data/ram/security-credentials/" {
				res = mockResponse(200, "rolename")
				return
			}

			if req.URL.Path == "/latest/meta-data/ram/security-credentials/rolename" {
				res = mockResponse(200, `{"AccessKeyId":"saki","AccessKeySecret":"saks","Expiration":"2021-10-20T04:27:09Z","SecurityToken":"token","Code":"Failed"}`)
				return
			}
			return
		}
	}
	_, err = p.getCredentials()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh Ecs sts token err, Code is not Success", err.Error())

	// case 8: mock ok value
	hookDo = func(fn do) do {
		return func(req *http.Request) (res *http.Response, err error) {
			if req.URL.Path == "/latest/meta-data/ram/security-credentials/" {
				res = mockResponse(200, "rolename")
				return
			}

			if req.URL.Path == "/latest/meta-data/ram/security-credentials/rolename" {
				res = mockResponse(200, `{"AccessKeyId":"saki","AccessKeySecret":"saks","Expiration":"2021-10-20T04:27:09Z","SecurityToken":"token","Code":"Success"}`)
				return
			}
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

func TestECSRAMRoleCredentialsProvider_getCredentialsWithMetadataV2(t *testing.T) {
	originDo := hookDo
	defer func() { hookDo = originDo }()

	p, err := NewECSRAMRoleCredentialsProviderBuilder().WithRoleName("rolename").WithEnableIMDSv2(true).Build()
	assert.Nil(t, err)

	// case 1: get metadata token failed
	hookDo = func(fn do) do {
		return func(req *http.Request) (res *http.Response, err error) {
			err = errors.New("mock server error")
			return
		}
	}
	_, err = p.getCredentials()
	assert.NotNil(t, err)
	assert.Equal(t, "get metadata token failed: mock server error", err.Error())

	// case 2: return token
	hookDo = func(fn do) do {
		return func(req *http.Request) (res *http.Response, err error) {
			if req.URL.Path == "/latest/api/token" {
				res = mockResponse(200, `tokenxxxxx`)
				return
			}
			if req.URL.Path == "/latest/meta-data/ram/security-credentials/rolename" {
				assert.Equal(t, "tokenxxxxx", req.Header.Get("x-aliyun-ecs-metadata-token"))
				res = mockResponse(200, `{"AccessKeyId":"saki","AccessKeySecret":"saks","Expiration":"2021-10-20T04:27:09Z","SecurityToken":"token","Code":"Success"}`)
			}
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

func TestECSRAMRoleCredentialsProviderGetCredentials(t *testing.T) {
	originDo := hookDo
	defer func() { hookDo = originDo }()

	p, err := NewECSRAMRoleCredentialsProviderBuilder().WithRoleName("rolename").Build()
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
	assert.Equal(t, "refresh Ecs sts token err: mock server error", err.Error())

	// case 2: get invalid expiration
	hookDo = func(fn do) do {
		return func(req *http.Request) (res *http.Response, err error) {
			res = mockResponse(200, `{"AccessKeyId":"saki","AccessKeySecret":"saks","Expiration":"invalidexpiration","SecurityToken":"token","Code":"Success"}`)
			return
		}
	}
	_, err = p.GetCredentials()
	assert.NotNil(t, err)
	assert.Equal(t, "parsing time \"invalidexpiration\" as \"2006-01-02T15:04:05Z\": cannot parse \"invalidexpiration\" as \"2006\"", err.Error())

	// case 3: happy result
	hookDo = func(fn do) do {
		return func(req *http.Request) (res *http.Response, err error) {
			res = mockResponse(200, `{"AccessKeyId":"akid","AccessKeySecret":"aksecret","Expiration":"2021-10-20T04:27:09Z","SecurityToken":"token","Code":"Success"}`)
			return
		}
	}
	cc, err := p.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, "akid", cc.AccessKeyId)
	assert.Equal(t, "aksecret", cc.AccessKeySecret)
	assert.Equal(t, "token", cc.SecurityToken)
	assert.True(t, p.needUpdateCredential())
}

func TestECSRAMRoleCredentialsProvider_getMetadataToken(t *testing.T) {
	originDo := hookDo
	defer func() { hookDo = originDo }()

	p, err := NewECSRAMRoleCredentialsProviderBuilder().Build()
	assert.Nil(t, err)

	// case 1: server error
	hookDo = func(fn do) do {
		return func(req *http.Request) (res *http.Response, err error) {
			err = errors.New("mock server error")
			return
		}
	}
	_, err = p.getMetadataToken()
	assert.NotNil(t, err)
	assert.Equal(t, "get metadata token failed: mock server error", err.Error())
	// case 2: return token
	hookDo = func(fn do) do {
		return func(req *http.Request) (res *http.Response, err error) {
			res = mockResponse(200, `tokenxxxxx`)
			return
		}
	}
	metadataToken, err := p.getMetadataToken()
	assert.Nil(t, err)
	assert.Equal(t, "tokenxxxxx", metadataToken)
}
