package credentials

import (
	"os"
	"testing"

	"github.com/alibabacloud-go/tea/tea"
	"github.com/stretchr/testify/assert"
)

func TestEnvresolve(t *testing.T) {
	p := newEnvProvider()
	assert.Equal(t, &envProvider{}, p)
	originAccessKeyIdNew := os.Getenv(EnvVarAccessKeyIdNew)
	originAccessKeyId := os.Getenv(EnvVarAccessKeyId)
	originAccessKeySecret := os.Getenv(EnvVarAccessKeySecret)
	originSecurityToken := os.Getenv("ALIBABA_CLOUD_SECURITY_TOKEN")
	os.Setenv(EnvVarAccessKeyId, "")
	os.Setenv(EnvVarAccessKeyIdNew, "")
	os.Setenv(EnvVarAccessKeySecret, "")
	os.Setenv("ALIBABA_CLOUD_SECURITY_TOKEN", "")
	defer func() {
		os.Setenv(EnvVarAccessKeyIdNew, originAccessKeyIdNew)
		os.Setenv(EnvVarAccessKeyId, originAccessKeyId)
		os.Setenv(EnvVarAccessKeySecret, originAccessKeySecret)
		os.Setenv("ALIBABA_CLOUD_SECURITY_TOKEN", originSecurityToken)
	}()
	c, err := p.resolve()
	assert.Nil(t, c)
	assert.EqualError(t, err, "ALIBABA_CLOUD_ACCESS_KEY_ID or ALIBABA_CLOUD_ACCESS_KEY_Id cannot be empty")

	os.Setenv(EnvVarAccessKeyIdNew, "")
	os.Setenv(EnvVarAccessKeyId, "")
	c, err = p.resolve()
	assert.Nil(t, c)
	assert.EqualError(t, err, "ALIBABA_CLOUD_ACCESS_KEY_ID or ALIBABA_CLOUD_ACCESS_KEY_Id cannot be empty")

	os.Setenv(EnvVarAccessKeyIdNew, "")
	os.Setenv(EnvVarAccessKeyId, "AccessKeyId")
	c, err = p.resolve()
	assert.Nil(t, c)
	assert.EqualError(t, err, "ALIBABA_CLOUD_ACCESS_KEY_SECRET cannot be empty")
	os.Setenv(EnvVarAccessKeySecret, "AccessKeySecret")
	c, err = p.resolve()
	assert.Nil(t, err)
	assert.Equal(t, "access_key", tea.StringValue(c.Type))
	assert.Equal(t, "AccessKeyId", tea.StringValue(c.AccessKeyId))
	assert.Equal(t, "AccessKeySecret", tea.StringValue(c.AccessKeySecret))

	os.Setenv(EnvVarAccessKeyId, "AccessKeyId")
	os.Setenv(EnvVarAccessKeyIdNew, "AccessKeyIdNew")
	os.Setenv(EnvVarAccessKeySecret, "AccessKeySecret")
	c, err = p.resolve()
	assert.Nil(t, err)
	assert.Equal(t, "access_key", tea.StringValue(c.Type))
	assert.Equal(t, "AccessKeyIdNew", tea.StringValue(c.AccessKeyId))
	assert.Equal(t, "AccessKeySecret", tea.StringValue(c.AccessKeySecret))

	os.Setenv("ALIBABA_CLOUD_SECURITY_TOKEN", "token")
	c, err = p.resolve()
	assert.Nil(t, err)
	assert.Equal(t, "sts", tea.StringValue(c.Type))
	assert.Equal(t, "AccessKeyIdNew", tea.StringValue(c.AccessKeyId))
	assert.Equal(t, "AccessKeySecret", tea.StringValue(c.AccessKeySecret))
	assert.Equal(t, "token", tea.StringValue(c.SecurityToken))
}
