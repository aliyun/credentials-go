package response

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_ParseFromHttpResponse(t *testing.T) {
	r := &CommonResponse{}
	res := &http.Response{
		Body:       ioutil.NopCloser(bytes.NewReader([]byte(""))),
		StatusCode: 200,
		Header:     make(map[string][]string),
	}
	res.Header.Add("Server", "GitHub.com")
	r.ParseFromHttpResponse(res)
	assert.Equal(t, []byte{}, r.GetHttpContentBytes())
	assert.Equal(t, "", r.GetHttpContentString())
	assert.Equal(t, "GitHub.com", r.GetHttpHeaders()["Server"][0])
	assert.Equal(t, 200, r.GetHttpStatus())
}
