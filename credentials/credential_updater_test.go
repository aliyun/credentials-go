package credentials

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_needUpdateCredential(t *testing.T) {
	updater := &credentialUpdater{
		lastUpdateTimestamp:  100,
		credentialExpiration: 200,
	}
	isNeed := updater.needUpdateCredential()
	assert.True(t, isNeed)
}
