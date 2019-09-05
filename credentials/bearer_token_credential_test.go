package credentials

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_BearerTokenCredential(t *testing.T) {
	auth := newBearerTokenCredential("bearertoken")
	accessKeyID, err := auth.GetAccessKeyID()
	assert.Nil(t, err)
	assert.Equal(t, "", accessKeyID)

	accessKeySecret, err := auth.GetAccessSecret()
	assert.Nil(t, err)
	assert.Equal(t, "", accessKeySecret)

	token, err := auth.GetSecurityToken()
	assert.Nil(t, err)
	assert.Equal(t, "", token)

	assert.Equal(t, "bearertoken", auth.GetBearerToken())
	assert.Equal(t, "bearer", auth.GetType())
}
