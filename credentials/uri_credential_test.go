package credentials

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestURLCredential_updateCredential(t *testing.T) {
	provider := newURLCredential("http://127.0.0.1")
	hookDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			return mockResponse(300, ``, errors.New("sdk test"))
		}
	}
	_, err := provider.GetAccessKeyId()
	assert.NotNil(t, err)
	assert.Equal(t, "refresh Ecs sts token err: sdk test", err.Error())

	assert.Equal(t, "credential_uri", *provider.GetType())

	cred, err := provider.GetCredential()
	assert.Equal(t, "refresh Ecs sts token err: sdk test", err.Error())
	assert.Nil(t, cred)
}
