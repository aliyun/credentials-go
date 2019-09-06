package request

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_BuildURL(t *testing.T) {
	r := NewCommonRequest()
	r.Domain = "domain.com"
	r.Scheme = "http"
	assert.Equal(t, "http://domain.com/?", r.BuildURL())
	r.QueryParams["key"] = "value"
	assert.Equal(t, "http://domain.com/?key=value", r.BuildURL())
	r.QueryParams["key"] = "https://domain/?q=v"
	assert.Equal(t, "http://domain.com/?key=https%3A%2F%2Fdomain%2F%3Fq%3Dv", r.BuildURL())
}

func Test_BuildRpcStringToSign(t *testing.T) {
	request := NewCommonRequest()
	stringToSign := request.BuildStringToSign()
	assert.Equal(t, "&%2F&", stringToSign)
	request.QueryParams["q"] = "value"
	stringToSign = request.BuildStringToSign()
	assert.Equal(t, "&%2F&q%3Dvalue", stringToSign)
	request.QueryParams["q"] = "http://domain/?q=value&q2=value2"
	stringToSign = request.BuildStringToSign()
	assert.Equal(t, "&%2F&q%3Dhttp%253A%252F%252Fdomain%252F%253Fq%253Dvalue%2526q2%253Dvalue2", stringToSign)
}
