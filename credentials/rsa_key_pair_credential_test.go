package credentials

import (
	"errors"
	"net/http"
	"testing"

	"github.com/aliyun/credentials-go/credentials/utils"

	"github.com/stretchr/testify/assert"
)

func Test_KeyPairCredential(t *testing.T) {
	privatekey := `
MIICeQIBADANBgkqhkiG9w0BAQEFAASCAmMwggJfAgEAAoGBAOJC+2WXtkXZ+6sa
3+qJp4mDOsiZb3BghHT9nVbjTeaw4hsZWHYxQ6l6XDmTg4twPB59LOGAlAjYrT31
3pdwEawnmdf6zyF93Zvxxpy7lO2HoxYKSjbtXO4I0pcq3WTnw2xlbhqHvrcuWwt+
FqH9akzcnwHjc03siZBzt/dwDL3vAgMBAAECgYEAzwgZPqFuUEYgaTVDFDl2ynYA
kNMMzBgUu3Pgx0Nf4amSitdLQYLcdbQXtTtMT4eYCxHgwkpDqkCRbLOQRKNwFo0I
oaCuhjZlxWcKil4z4Zb/zB7gkeuXPOVUjFSS3FogsRWMtnNAMgR/yJRlbcg/Puqk
Magt/yDk+7cJCe6H96ECQQDxMT4S+tVP9nOw//QT39Dk+kWe/YVEhnWnCMZmGlEq
1gnN6qpUi68ts6b3BVgrDPrPN6wm/Z9vpcKNeWpIvxXRAkEA8CcT2UEUwDGRKAUu
WVPJqdAJjpjc072eRF5g792NyO+TAF6thBlDKNslRvFQDB6ymLsjfy8JYCnGbbSb
WqbHvwJBAIs7KeI6+jiWxGJA3t06LpSABQCqyOut0u0Bm8YFGyXnOPGtrXXwzMdN
Fe0zIJp5e69zK+W2Mvt4bL7OgBROeoECQQDsE+4uLw0gFln0tosmovhmp60NcfX7
bLbtzL2MbwbXlbOztF7ssgzUWAHgKI6hK3g0LhsqBuo3jzmSVO43giZvAkEA08Nm
2TI9EvX6DfCVfPOiKZM+Pijh0xLN4Dn8qUgt3Tcew/vfj4WA2ZV6qiJqL01vMsHc
vftlY0Hs1vNXcaBgEA==`
	auth := newRsaKeyPairCredential(privatekey, "publicKeyId", 100, &utils.Runtime{Host: "www.aliyun.com", Proxy: "www.aliyuncs.com"})
	origTestHookDo := hookDo
	defer func() { hookDo = origTestHookDo }()
	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(200, `{"Credentials":{"AccessKeyId":"accessKeyId","AccessKeySecret":"accessKeySecret","SecurityToken":"securitytoken","Expiration":"expiration"}}`, errors.New("Internal error"))
		}
	}
	accesskeyId, err := auth.GetAccessKeyId()
	assert.NotNil(t, err)
	assert.Equal(t, "[InvalidParam]:Key Pair session duration should be in the range of 15min - 1Hr", err.Error())
	assert.Equal(t, "", accesskeyId)

	accesskeySecret, err := auth.GetAccessSecret()
	assert.NotNil(t, err)
	assert.Equal(t, "[InvalidParam]:Key Pair session duration should be in the range of 15min - 1Hr", err.Error())
	assert.Equal(t, "", accesskeySecret)

	ststoken, err := auth.GetSecurityToken()
	assert.Nil(t, err)
	assert.Equal(t, "", ststoken)

	assert.Equal(t, "", auth.GetBearerToken())
	assert.Equal(t, "rsa_key_pair", auth.GetType())

	auth.SessionExpiration = 1000
	accesskeyId, err = auth.GetAccessKeyId()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh KeyPair err: Internal error", err.Error())
	assert.Equal(t, "", accesskeyId)

	auth.SessionExpiration = 0
	accesskeyId, err = auth.GetAccessKeyId()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh KeyPair err: Internal error", err.Error())
	assert.Equal(t, "", accesskeyId)

	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(300, ``, nil)
		}
	}
	accesskeyId, err = auth.GetAccessKeyId()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh KeyPair err: httpStatus: 300, message = ", err.Error())
	assert.Equal(t, "", accesskeyId)

	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(200, `"SessionAccessKey":{"SessionAccessKeyId":"accessKeyId","SessionAccessKeySecret":"accessKeySecret","Expiration":"expiration"}}`, nil)
		}
	}
	accesskeyId, err = auth.GetAccessKeyId()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh KeyPair err: Json.Unmarshal fail: invalid character ':' after top-level value", err.Error())
	assert.Equal(t, "", accesskeyId)

	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(200, `{"SessionAccessKey":{"SessionAccessKeySecret":"accessKeySecret","Expiration":"expiration"}}`, nil)
		}
	}
	accesskeyId, err = auth.GetAccessKeyId()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh KeyPair err: SessionAccessKeyId: <nil>, SessionAccessKeySecret: accessKeySecret, Expiration: expiration", err.Error())
	assert.Equal(t, "", accesskeyId)

	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(200, `{"SessionAccessKey":{"SessionAccessKeyId":"accessKeyId","SessionAccessKeySecret":"accessKeySecret","Expiration":"2020-01-02T15:04:05Z"}}`, nil)
		}
	}
	accesskeyId, err = auth.GetAccessKeyId()
	assert.Nil(t, err)
	assert.Equal(t, "accessKeyId", accesskeyId)

	accesskeySecret, err = auth.GetAccessSecret()
	assert.Nil(t, err)
	assert.Equal(t, "accessKeySecret", accesskeySecret)

	auth.runtime = nil
	auth.lastUpdateTimestamp = 0
	accesskeyId, err = auth.GetAccessKeyId()
	assert.Nil(t, err)
	assert.Equal(t, "accessKeyId", accesskeyId)
}
