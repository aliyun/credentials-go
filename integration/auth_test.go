package integeration

import (
	"os"
	"strconv"
	"testing"

	"github.com/aliyun/credentials-go/credentials"
	"github.com/stretchr/testify/assert"
)

const (
	EnvVarSubAccessKeyID        = "SUB_ALICLOUD_ACCESS_KEY"
	EnvVarSubAccessKeySecret    = "SUB_ALICLOUD_SECRET_KEY"
	EnvVarRoleArn               = "ALICLOUD_ROLE_ARN"
	EnvVarRoleSessionName       = "ALICLOUD_ROLE_SESSION_NAME"
	EnvVarRoleSessionExpiration = "ALICLOUD_ROLE_SESSION_EXPIRATION"
)

func Test_Arn(t *testing.T) {
	rawexpiration := os.Getenv(EnvVarRoleSessionExpiration)
	expiration := 0
	if rawexpiration != "" {
		expiration, _ = strconv.Atoi(rawexpiration)
	}
	config := &credentials.Configuration{
		Type:                  "ram_role_arn",
		AccessKeyID:           os.Getenv(EnvVarSubAccessKeyID),
		AccessKeySecret:       os.Getenv(EnvVarSubAccessKeySecret),
		RoleArn:               os.Getenv(EnvVarRoleArn),
		RoleSessionName:       os.Getenv(EnvVarRoleSessionName),
		RoleSessionExpiration: expiration,
	}
	cred, err := credentials.NewCredential(config)
	assert.Nil(t, err)
	assert.NotNil(t, cred)
	accesskey, err := cred.GetAccessKeyID()
	assert.Nil(t, err)
	assert.NotNil(t, accesskey)
}
