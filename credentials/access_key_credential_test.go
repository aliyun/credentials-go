package credentials

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_AccessKeyCredential(t *testing.T) {
	auth := newAccessKeyCredential("accessKeyId", "accessKeySecret")
	accessKeyId, err := auth.GetAccessKeyId()
	assert.Nil(t, err)
	assert.Equal(t, "accessKeyId", accessKeyId)

	accessKeySecret, err := auth.GetAccessKeySecret()
	assert.Nil(t, err)
	assert.Equal(t, "accessKeySecret", accessKeySecret)

	token, err := auth.GetSecurityToken()
	assert.Nil(t, err)
	assert.Equal(t, "", token)

	assert.Equal(t, "", auth.GetBearerToken())

	assert.Equal(t, "access_key", auth.GetType())
}
