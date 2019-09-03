package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_NewRuntime(t *testing.T) {
	runitme := NewRuntime(10, 10, "proxy", "host")
	assert.Equal(t, 10, runitme.ReadTimeout)
	assert.Equal(t, 10, runitme.ConnectTimeout)
	assert.Equal(t, "proxy", runitme.Proxy)
	assert.Equal(t, "host", runitme.Host)
}
