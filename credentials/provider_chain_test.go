package credentials

import (
	"os"
	"testing"

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
	assert.EqualError(t, err, "No credential found")
}
