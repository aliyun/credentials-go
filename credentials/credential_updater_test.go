package credentials

import (
	"errors"
	"net/http"
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

func Test_hookdo(t *testing.T) {
	fn := func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("hookdo")
	}
	result := hookDo(fn)
	resp, err := result(nil)
	assert.Nil(t, resp)
	assert.Equal(t, "hookdo", err.Error())
}
