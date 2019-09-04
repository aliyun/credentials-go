package utils

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_NewRuntime(t *testing.T) {
	runitme := NewRuntime(10, 10, "proxy", "host")
	assert.Equal(t, 10, runitme.ReadTimeout)
	assert.Equal(t, 10, runitme.ConnectTimeout)
	assert.Equal(t, "proxy", runitme.Proxy)
	assert.Equal(t, "host", runitme.Host)

	dialContext := Timeout(5 * time.Second)
	ctx, cancelFunc := context.WithTimeout(context.Background(), 1*time.Second)
	assert.NotNil(t, cancelFunc)
	c, err := dialContext(ctx, "127.0.0.1", "127.0.0.2")
	assert.Nil(t, c)
	assert.Equal(t, "dial 127.0.0.1: unknown network 127.0.0.1", err.Error())
}
