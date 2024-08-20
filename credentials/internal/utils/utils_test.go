package utils

import (
	"crypto"
	"crypto/rsa"
	"errors"
	"io"
	"os"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetUUID(t *testing.T) {
	uuid := newUUID()
	assert.Equal(t, 16, len(uuid))
	assert.Equal(t, 36, len(uuid.String()))
	uuidString := GetUUID()
	assert.Equal(t, 32, len(uuidString))
}

func TestGetMD5Base64(t *testing.T) {
	assert.Equal(t, "ERIHLmRX2uZmssDdxQnnxQ==",
		GetMD5Base64([]byte("That's all folks!!")))
	assert.Equal(t, "GsJRdI3kAbAnHo/0+3wWJw==",
		GetMD5Base64([]byte("中文也没啥问题")))
}

func TestGetTimeInFormatISO8601(t *testing.T) {
	s := GetTimeInFormatISO8601()
	assert.Equal(t, 20, len(s))
	// 2006-01-02T15:04:05Z
	re := regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
	assert.True(t, re.MatchString(s))
}

func TestGetURLFormedMap(t *testing.T) {
	m := make(map[string]string)
	m["key"] = "value"
	s := GetURLFormedMap(m)
	assert.Equal(t, "key=value", s)
	m["key2"] = "http://domain/?key=value&key2=value2"
	s2 := GetURLFormedMap(m)
	assert.Equal(t, "key=value&key2=http%3A%2F%2Fdomain%2F%3Fkey%3Dvalue%26key2%3Dvalue2", s2)
}

func TestShaHmac1(t *testing.T) {
	result := ShaHmac1("source", "secret")
	assert.Equal(t, "Jv4yi8SobFhg5t1C7nWLbhBSFZQ=", result)

	assert.Equal(t, "CqCYIa39h9SSWuXnTz8F5hh9UPA=", ShaHmac1("中文", "secret"))
}

func TestSha256WithRsa(t *testing.T) {
	secret := `
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
	result := Sha256WithRsa("source", secret)
	assert.Equal(t, "UNyJPD27jjSNl70b02E/DUtgtNESdtAuxbNBZTlksk1t/GYjiQNRlFIubp/EGKcWsqs7p5SFKnNiSRqWG3A51VmJFBXXtyW1nwLC9xY/MbUj6JVWNYCuLkPWM942O+GAk7N+G8ZQZt7ib2MhruDAUmv1lLN26lDaCPBX2MJQJCo=", result)

	assert.Equal(t, "CKE0osxUnFFH+oYP3Q427saucBuignE+Mrni63G9w46yZFtVoXFOu5lNiNCnUtaPNpGmBf9X5oGCY+otqPf7bP93nB59rfdteQs0sS65PWH9yjH8RwYCWGCbuyRul/0qIv/nYYGzkLON1C1Vx9Z4Yep6llYuJang5RIXrAkQLmQ=", Sha256WithRsa("中文", secret))
}

func TestSha256WithRsa_DecodeString_Error(t *testing.T) {
	defer func() { // 进行异常捕捉
		err := recover()
		assert.NotNil(t, err)
		assert.Equal(t, "illegal base64 data at input byte 0", err.(error).Error())
	}()
	secret := `==`
	Sha256WithRsa("source", secret)
}

func TestSha256WithRsa_ParsePKCS8PrivateKey_Error(t *testing.T) {
	defer func() { // 进行异常捕捉
		err := recover()
		assert.NotNil(t, err)
		assert.Equal(t, "asn1: structure error: length too large", err.(error).Error())
	}()
	secret := `Jv4yi8SobFhg5t1C7nWLbhBSFZQ=`
	Sha256WithRsa("source", secret)
}

func TestHookRead(t *testing.T) {
	fn := func(p []byte) (n int, err error) {
		return 0, errors.New("hookRead")
	}
	result := hookRead(fn)
	n, err := result(nil)
	assert.Equal(t, 0, n)
	assert.Equal(t, "hookRead", err.Error())

	originHookRead := hookRead
	hookRead = func(old func(p []byte) (n int, err error)) func(p []byte) (n int, err error) {
		return fn
	}
	defer func() {
		err := recover()
		assert.Equal(t, "hookRead", err.(error).Error())
		hookRead = originHookRead
	}()
	safeRandom([]byte("credentialtest"))
}

func TestHookRSA(t *testing.T) {
	fn := func(rand io.Reader, priv *rsa.PrivateKey, hash crypto.Hash, hashed []byte) ([]byte, error) {
		return nil, errors.New("hookRSA")
	}
	result := hookRSA(fn)
	hash := crypto.Hash(10)
	byt, err := result(nil, nil, hash, nil)
	assert.Nil(t, byt)
	assert.Equal(t, "hookRSA", err.Error())

	originHookRSA := hookRSA
	hookRSA = func(old func(rand io.Reader, priv *rsa.PrivateKey, hash crypto.Hash, hashed []byte) ([]byte, error)) func(rand io.Reader, priv *rsa.PrivateKey, hash crypto.Hash, hashed []byte) ([]byte, error) {
		return fn
	}
	defer func() {
		err := recover()
		assert.Equal(t, "hookRSA", err.(error).Error())
		hookRSA = originHookRSA
	}()
	secret := `
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
	Sha256WithRsa("source", secret)
}

func TestGetDefaultString(t *testing.T) {
	assert.Equal(t, "default", GetDefaultString("", "default"))
	assert.Equal(t, "custom", GetDefaultString("custom", "default"))
	assert.Equal(t, "", GetDefaultString("", "", ""))
}

func TestMemoryAndRollback(t *testing.T) {
	os.Setenv("test", "old")
	rollback := Memory("test")
	os.Setenv("test", "new")
	rollback()

	assert.Equal(t, "old", os.Getenv("test"))
}

func TestGetNonce(t *testing.T) {
	assert.Equal(t, 32, len(GetNonce()))
	assert.NotEqual(t, GetNonce(), GetNonce())
}
