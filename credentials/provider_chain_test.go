package credentials

import (
	"os"
	"testing"

	"github.com/alibabacloud-go/tea/tea"
	"github.com/stretchr/testify/assert"
)

func TestProviderChain(t *testing.T) {
	env := newEnvProvider()
	pp := newProfileProvider()
	instanceP := newInstanceCredentialsProvider()

	pc := newProviderChain([]Provider{env, pp, instanceP})

	originAccessKeyIdNew := os.Getenv(EnvVarAccessKeyIdNew)
	originAccessKeyId := os.Getenv(EnvVarAccessKeyId)
	originAccessKeySecret := os.Getenv(EnvVarAccessKeySecret)
	os.Setenv(EnvVarAccessKeyId, "")
	os.Setenv(EnvVarAccessKeyIdNew, "")
	os.Setenv(EnvVarAccessKeySecret, "")
	defer func() {
		os.Setenv(EnvVarAccessKeyIdNew, originAccessKeyIdNew)
		os.Setenv(EnvVarAccessKeyId, originAccessKeyId)
		os.Setenv(EnvVarAccessKeySecret, originAccessKeySecret)
	}()
	c, err := pc.resolve()
	assert.Nil(t, c)
	assert.EqualError(t, err, "ALIBABA_CLOUD_ACCESS_KEY_ID or ALIBABA_CLOUD_ACCESS_KEY_Id cannot be empty")

	os.Setenv(EnvVarAccessKeyId, "AccessKeyId")
	os.Setenv(EnvVarAccessKeySecret, "AccessKeySecret")
	c, err = pc.resolve()
	assert.NotNil(t, c)
	assert.Nil(t, err)

	os.Unsetenv(EnvVarAccessKeyId)
	os.Unsetenv(EnvVarAccessKeySecret)
	os.Unsetenv(ENVCredentialFile)
	os.Unsetenv(ENVEcsMetadata)

	c, err = pc.resolve()
	assert.Nil(t, c)
	assert.EqualError(t, err, "no credential found")
}

func TestDefaultChainNoCred(t *testing.T) {
	accessKeyIdNew := os.Getenv(EnvVarAccessKeyIdNew)
	accessKeyId := os.Getenv(EnvVarAccessKeyId)
	accessKeySecret := os.Getenv(EnvVarAccessKeySecret)
	ecsMetadata := os.Getenv(ENVEcsMetadata)
	roleArn := os.Getenv(ENVRoleArn)
	oidcProviderArn := os.Getenv(ENVOIDCProviderArn)
	oidcTokenFilePath := os.Getenv(ENVOIDCTokenFile)
	roleSessionName := os.Getenv(ENVRoleSessionName)
	os.Unsetenv(EnvVarAccessKeyId)
	os.Unsetenv(EnvVarAccessKeySecret)
	os.Unsetenv(ENVCredentialFile)
	os.Unsetenv(ENVEcsMetadata)
	os.Unsetenv(ENVRoleArn)
	os.Unsetenv(ENVOIDCProviderArn)
	os.Unsetenv(ENVOIDCTokenFile)
	os.Unsetenv(ENVRoleSessionName)
	defer func() {
		os.Setenv(EnvVarAccessKeyIdNew, accessKeyIdNew)
		os.Setenv(EnvVarAccessKeyId, accessKeyId)
		os.Setenv(EnvVarAccessKeySecret, accessKeySecret)
		os.Setenv(ENVEcsMetadata, ecsMetadata)
		os.Setenv(ENVRoleArn, roleArn)
		os.Setenv(ENVOIDCProviderArn, oidcProviderArn)
		os.Setenv(ENVOIDCTokenFile, oidcTokenFilePath)
		os.Setenv(ENVRoleSessionName, roleSessionName)
	}()

	chain, err := defaultChain.resolve()
	assert.Nil(t, chain)
	assert.Equal(t, "no credential found", err.Error())
}

func TestDefaultChainHasCred(t *testing.T) {
	accessKeyIdNew := os.Getenv(EnvVarAccessKeyIdNew)
	accessKeyId := os.Getenv(EnvVarAccessKeyId)
	accessKeySecret := os.Getenv(EnvVarAccessKeySecret)
	os.Unsetenv(EnvVarAccessKeyId)
	os.Unsetenv(EnvVarAccessKeySecret)
	os.Unsetenv(ENVCredentialFile)

	path, _ := os.Getwd()
	oidcTokenFilePathVar := path + "/oidc_token"
	roleArn := os.Getenv(ENVRoleArn)
	oidcProviderArn := os.Getenv(ENVOIDCProviderArn)
	oidcTokenFilePath := os.Getenv(ENVOIDCTokenFile)
	roleSessionName := os.Getenv(ENVRoleSessionName)
	os.Setenv(ENVRoleArn, "acs:ram::roleArn:role/roleArn")
	os.Setenv(ENVOIDCProviderArn, "acs:ram::roleArn")
	os.Setenv(ENVOIDCTokenFile, oidcTokenFilePathVar)
	os.Setenv(ENVRoleSessionName, "roleSessionName")
	defer func() {
		os.Setenv(EnvVarAccessKeyIdNew, accessKeyIdNew)
		os.Setenv(EnvVarAccessKeyId, accessKeyId)
		os.Setenv(EnvVarAccessKeySecret, accessKeySecret)
		os.Setenv(ENVRoleArn, roleArn)
		os.Setenv(ENVOIDCProviderArn, oidcProviderArn)
		os.Setenv(ENVOIDCTokenFile, oidcTokenFilePath)
		os.Setenv(ENVRoleSessionName, roleSessionName)
	}()

	config, err := defaultChain.resolve()
	assert.NotNil(t, config)
	assert.Nil(t, err)
	assert.Equal(t, "acs:ram::roleArn:role/roleArn", tea.StringValue(config.RoleArn))
	assert.Equal(t, "acs:ram::roleArn", tea.StringValue(config.OIDCProviderArn))
	assert.Equal(t, oidcTokenFilePathVar, tea.StringValue(config.OIDCTokenFilePath))
	assert.Equal(t, "roleSessionName", tea.StringValue(config.RoleSessionName))
	assert.Equal(t, "oidc_role_arn", tea.StringValue(config.Type))

	os.Setenv("ALIBABA_CLOUD_CLI_PROFILE_DISABLED", "true")
	cred, err := NewCredential(nil)
	assert.Nil(t, err)
	assert.NotNil(t, cred)
	assert.Equal(t, "default", *cred.GetType())
}
