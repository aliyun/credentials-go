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

func TestRAMRoleArn(t *testing.T) {
	rawexpiration := os.Getenv(EnvVarRoleSessionExpiration)
	expiration := 0
	if rawexpiration != "" {
		expiration, _ = strconv.Atoi(rawexpiration)
	}
	// assume role fisrt time
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
	c, err := cred.GetCredential()
	assert.Nil(t, err)
	assert.NotNil(t, c.AccessKeyId)
	assert.NotNil(t, c.AccessKeySecret)
	assert.NotNil(t, c.SecurityToken)

	// asume role second time with pre sts
	config2 := &credentials.Config{
		Type:                  tea.String("ram_role_arn"),
		AccessKeyId:           c.AccessKeyId,
		AccessKeySecret:       c.AccessKeySecret,
		SecurityToken:         c.SecurityToken,
		RoleArn:               tea.String(os.Getenv(EnvVarRoleArn)),
		RoleSessionName:       tea.String(os.Getenv(EnvVarRoleSessionName)),
		RoleSessionExpiration: tea.Int(expiration),
	}
	cred2, err := credentials.NewCredential(config2)
	assert.Nil(t, err)
	assert.NotNil(t, cred2)
	c2, err := cred.GetCredential()
	assert.Nil(t, err)
	assert.NotNil(t, c2.AccessKeyId)
	assert.NotNil(t, c2.AccessKeySecret)
	assert.NotNil(t, c2.SecurityToken)
}

func Test_Oidc(t *testing.T) {
	path, _ := os.Getwd()
	oidcTokenFilePath := path + "../credentials/oidc_token"
	config := &credentials.Config{
		Type:              tea.String("oidc_role_arn"),
		RoleArn:           tea.String("acs:ram::roleArn:role/roleArn"),
		OIDCProviderArn:   tea.String("acs:ram::roleArn"),
		OIDCTokenFilePath: tea.String(oidcTokenFilePath),
	}
	cred, err := credentials.NewCredential(config)
	assert.Nil(t, err)
	assert.NotNil(t, cred)
	_, err = cred.GetAccessKeyId()
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "AuthenticationFail.OIDCToken.Invalid")
}
