package credentials

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/alibabacloud-go/tea/tea"
)

func TestEnvresolve(t *testing.T) {
	p := newEnvProvider()
	assert.Equal(t, &envProvider{}, p)
	originAccessKeyId := os.Getenv(EnvVarAccessKeyId)
	originAccessKeySecret := os.Getenv(EnvVarAccessKeySecret)
	os.Setenv(EnvVarAccessKeyId, "")
	os.Setenv(EnvVarAccessKeySecret, "")
	defer func() {
		os.Setenv(EnvVarAccessKeyId, originAccessKeyId)
		os.Setenv(EnvVarAccessKeySecret, originAccessKeySecret)
	}()
	c, err := p.resolve()
	assert.Nil(t, c)
	assert.EqualError(t, err, "ALIBABA_CLOUD_ACCESS_KEY_Id cannot be empty")

	os.Setenv(EnvVarAccessKeyId, "AccessKeyId")
	c, err = p.resolve()
	assert.Nil(t, c)
	assert.EqualError(t, err, "ALIBABA_CLOUD_ACCESS_KEY_SECRET cannot be empty")
	os.Setenv(EnvVarAccessKeySecret, "AccessKeySecret")
	c, err = p.resolve()
	assert.Nil(t, err)
	assert.Equal(t, "access_key", tea.StringValue(c.Type))
	assert.Equal(t, "AccessKeyId",  tea.StringValue(c.AccessKeyId))
	assert.Equal(t, "AccessKeySecret",  tea.StringValue(c.AccessKeySecret))
}
