package credentials

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEnvResolve(t *testing.T) {
	p := NewEnvProvider()
	assert.Equal(t, &EnvProvider{}, p)
	originAccessKeyID := os.Getenv(EnvVarAccessKeyID)
	originAccessKeySecret := os.Getenv(EnvVarAccessKeySecret)
	os.Setenv(EnvVarAccessKeyID, "")
	os.Setenv(EnvVarAccessKeySecret, "")
	defer func() {
		os.Setenv(EnvVarAccessKeyID, originAccessKeyID)
		os.Setenv(EnvVarAccessKeySecret, originAccessKeySecret)
	}()
	c, err := p.Resolve()
	assert.Nil(t, c)
	assert.EqualError(t, err, "ALIBABA_CLOUD_ACCESS_KEY_ID cannot be empty.")

	os.Setenv(EnvVarAccessKeyID, "AccessKeyId")
	c, err = p.Resolve()
	assert.Nil(t, c)
	assert.EqualError(t, err, "ALIBABA_CLOUD_ACCESS_KEY_SECRET cannot be empty.")
	os.Setenv(EnvVarAccessKeySecret, "AccessKeySecret")
	c, err = p.Resolve()
	assert.Nil(t, err)
	assert.Equal(t, "access_key", c.Type)
	assert.Equal(t, "AccessKeyId", c.AccessKeyId)
	assert.Equal(t, "AccessKeySecret", c.AccessKeySecret)
}
