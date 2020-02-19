package integeration

import (
	"os"
	"strconv"
	"testing"

	"github.com/alibabacloud-go/tea/tea"
	"github.com/aliyun/credentials-go/credentials"
	"github.com/stretchr/testify/assert"
)

const (
	EnvVarSubAccessKeyId        = "SUB_ALICLOUD_ACCESS_KEY"
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
	config := &credentials.Config{
		Type:                  tea.String("ram_role_arn"),
		AccessKeyId:           tea.String(os.Getenv(EnvVarSubAccessKeyId)),
		AccessKeySecret:       tea.String(os.Getenv(EnvVarSubAccessKeySecret)),
		RoleArn:               tea.String(os.Getenv(EnvVarRoleArn)),
		RoleSessionName:       tea.String(os.Getenv(EnvVarRoleSessionName)),
		RoleSessionExpiration: tea.Int(expiration),
	}
	cred, err := credentials.NewCredential(config)
	assert.Nil(t, err)
	assert.NotNil(t, cred)
	accesskey, err := cred.GetAccessKeyId()
	assert.Nil(t, err)
	assert.NotNil(t, accesskey)
}
