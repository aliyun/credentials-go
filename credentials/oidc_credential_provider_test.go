package credentials

import (
	"os"
	"testing"

	"github.com/alibabacloud-go/tea/tea"
	"github.com/stretchr/testify/assert"
)

func TestOidcCredentialsProvider(t *testing.T) {
	p := newOidcCredentialsProvider()
	roleArn := os.Getenv(ENVRoleArn)
	oidcProviderArn := os.Getenv(ENVOIDCProviderArn)
	oidcTokenFilePath := os.Getenv(ENVOIDCTokenFile)
	roleSessionName := os.Getenv(ENVRoleSessionName)
	os.Setenv(ENVRoleArn, "")
	os.Setenv(ENVOIDCProviderArn, "")
	os.Setenv(ENVOIDCTokenFile, "")
	os.Setenv(ENVRoleSessionName, "")
	defer func() {
		os.Setenv(ENVRoleArn, roleArn)
		os.Setenv(ENVOIDCProviderArn, oidcProviderArn)
		os.Setenv(ENVOIDCTokenFile, oidcTokenFilePath)
		os.Setenv(ENVRoleSessionName, roleSessionName)
	}()
	c, err := p.resolve()
	assert.NotNil(t, c)
	assert.Nil(t, err)

	os.Setenv(ENVRoleArn, "roleArn")
	os.Setenv(ENVOIDCProviderArn, "oidcProviderArn")
	os.Setenv(ENVOIDCTokenFile, "oidcTokenFilePath")
	os.Unsetenv(ENVRoleSessionName)
	c, err = p.resolve()
	assert.Nil(t, err)
	assert.Equal(t, "roleArn", tea.StringValue(c.RoleArn))
	assert.Equal(t, "oidcProviderArn", tea.StringValue(c.OIDCProviderArn))
	assert.Equal(t, "oidcTokenFilePath", tea.StringValue(c.OIDCTokenFilePath))
	assert.Equal(t, "defaultSessionName", tea.StringValue(c.RoleSessionName))
	assert.Equal(t, "oidc_role_arn", tea.StringValue(c.Type))

	os.Setenv(ENVRoleSessionName, "roleSessionName")
	c, err = p.resolve()
	assert.Nil(t, err)
	assert.Equal(t, "roleArn", tea.StringValue(c.RoleArn))
	assert.Equal(t, "oidcProviderArn", tea.StringValue(c.OIDCProviderArn))
	assert.Equal(t, "oidcTokenFilePath", tea.StringValue(c.OIDCTokenFilePath))
	assert.Equal(t, "roleSessionName", tea.StringValue(c.RoleSessionName))
	assert.Equal(t, "oidc_role_arn", tea.StringValue(c.Type))

	os.Unsetenv(ENVRoleArn)
	os.Unsetenv(ENVOIDCProviderArn)
	os.Unsetenv(ENVOIDCTokenFile)
	os.Unsetenv(ENVRoleSessionName)
	c, err = p.resolve()
	assert.Nil(t, c)
	assert.Nil(t, err)
}
