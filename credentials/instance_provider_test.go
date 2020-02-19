package credentials

import (
	"os"
	"testing"

	"github.com/alibabacloud-go/tea/tea"
	"github.com/stretchr/testify/assert"
)

func TestInstanceCredentialsProvider(t *testing.T) {
	p := newInstanceCredentialsProvider()
	originEcsMetadata := os.Getenv(ENVEcsMetadata)
	os.Setenv(ENVEcsMetadata, "")
	defer func() {
		os.Setenv(ENVEcsMetadata, originEcsMetadata)
	}()
	c, err := p.resolve()
	assert.NotNil(t, c)
	assert.Nil(t, err)

	os.Setenv(ENVEcsMetadata, "role_name")
	c, err = p.resolve()
	assert.Nil(t, err)
	assert.Equal(t, "role_name", tea.StringValue(c.RoleName))
	assert.Equal(t, "ecs_ram_role", tea.StringValue(c.Type))

	os.Unsetenv(ENVEcsMetadata)
	c, err = p.resolve()
	assert.Nil(t, c)
	assert.Nil(t, err)
}
