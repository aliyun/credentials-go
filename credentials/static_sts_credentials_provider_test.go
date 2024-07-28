package credentials

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_StsCredential(t *testing.T) {
	auth := NewStaticSTSCredentialsProvider("accessKeyId", "accessKeySecret", "securityToken")
	accessKeyId, err := auth.GetAccessKeyId()
	assert.Nil(t, err)
	assert.Equal(t, "accessKeyId", *accessKeyId)

	accessKeySecret, err := auth.GetAccessKeySecret()
	assert.Nil(t, err)
	assert.Equal(t, "accessKeySecret", *accessKeySecret)

	token, err := auth.GetSecurityToken()
	assert.Nil(t, err)
	assert.Equal(t, "securityToken", *token)

	assert.Equal(t, "", *auth.GetBearerToken())
	assert.Equal(t, "sts", *auth.GetType())

	cred, err := auth.GetCredential()
	assert.Nil(t, err)
	assert.Equal(t, "accessKeyId", *cred.AccessKeyId)
	assert.Equal(t, "accessKeySecret", *cred.AccessKeySecret)
	assert.Equal(t, "securityToken", *cred.SecurityToken)
	assert.Nil(t, cred.BearerToken)
	assert.Equal(t, "sts", *cred.Type)
}
