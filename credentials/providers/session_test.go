package providers

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSessionStaleConstants(t *testing.T) {
	assert.Equal(t, int64(15*60), SessionStaleTimeSeconds)
	assert.Equal(t, int64(180), ExternalExpirationSlotSeconds)
	assert.Equal(t, int64(60*60), EcsPrefetchTimeSeconds)
	assert.Equal(t, time.Minute, defaultEcsAsyncCheckInterval)
}

func TestIsSessionCredentialStale(t *testing.T) {
	assert.True(t, isSessionCredentialStale(0))
	assert.True(t, isSessionCredentialStale(time.Now().Unix()-10))
	assert.True(t, isSessionCredentialStale(time.Now().Unix()+100))
	assert.True(t, isSessionCredentialStale(time.Now().Unix()+SessionStaleTimeSeconds))
	assert.False(t, isSessionCredentialStale(time.Now().Unix()+SessionStaleTimeSeconds+1))
	assert.False(t, isSessionCredentialStale(time.Now().Unix()+3600))
}
