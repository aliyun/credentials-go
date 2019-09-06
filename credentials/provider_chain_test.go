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

	originAccessKeyID := os.Getenv(EnvVarAccessKeyID)
	originAccessKeySecret := os.Getenv(EnvVarAccessKeySecret)
	os.Setenv(EnvVarAccessKeyID, "")
	os.Setenv(EnvVarAccessKeySecret, "")
	defer func() {
		os.Setenv(EnvVarAccessKeyID, originAccessKeyID)
		os.Setenv(EnvVarAccessKeySecret, originAccessKeySecret)
	}()
	c, err := pc.resolve()
	assert.Nil(t, c)
	assert.EqualError(t, err, "ALIBABA_CLOUD_ACCESS_KEY_ID cannot be empty")

	os.Setenv(EnvVarAccessKeyID, "AccessKeyID")
	os.Setenv(EnvVarAccessKeySecret, "AccessKeySecret")
	c, err = pc.resolve()
	assert.NotNil(t, c)
	assert.Nil(t, err)

	os.Unsetenv(EnvVarAccessKeyID)
	os.Unsetenv(EnvVarAccessKeySecret)
	os.Unsetenv(ENVCredentialFile)
	os.Unsetenv(ENVEcsMetadata)

	c, err = pc.resolve()
	assert.Nil(t, c)
	assert.EqualError(t, err, "No credential found")
}
