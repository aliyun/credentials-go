package credentials

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_StsCredential(t *testing.T) {
	auth := newStsTokenCredential("accessKeyId", "accessKeySecret", "securityToken")
	accessKeyId, err := auth.GetAccessKeyId()
	assert.Nil(t, err)
	assert.Equal(t, "accessKeyId", accessKeyId)

	accessKeySecret, err := auth.GetAccessSecret()
	assert.Nil(t, err)
	assert.Equal(t, "accessKeySecret", accessKeySecret)

	token, err := auth.GetSecurityToken()
	assert.Nil(t, err)
	assert.Equal(t, "securityToken", token)

	assert.Equal(t, "", auth.GetBearerToken())
	assert.Equal(t, "sts", auth.GetType())
}
