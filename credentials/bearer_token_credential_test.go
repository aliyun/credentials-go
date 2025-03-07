package credentials

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_BearerTokenCredential(t *testing.T) {
	auth := newBearerTokenCredential("bearertoken")
	accessKeyId, err := auth.GetAccessKeyId()
	assert.Nil(t, err)
	assert.Equal(t, "", *accessKeyId)

	accessKeySecret, err := auth.GetAccessKeySecret()
	assert.Nil(t, err)
	assert.Equal(t, "", *accessKeySecret)

	token, err := auth.GetSecurityToken()
	assert.Nil(t, err)
	assert.Equal(t, "", *token)

	assert.Equal(t, "bearertoken", *auth.GetBearerToken())
	assert.Equal(t, "bearer", *auth.GetType())

	cred, err := auth.GetCredential()
	assert.Nil(t, err)
	assert.Equal(t, "bearertoken", *cred.BearerToken)
	assert.Nil(t, cred.AccessKeyId)
	assert.Nil(t, cred.AccessKeySecret)
	assert.Nil(t, cred.SecurityToken)
	assert.Equal(t, "bearer", *cred.Type)
	assert.Equal(t, "bearer", *cred.ProviderName)
}
