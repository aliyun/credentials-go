package providers

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"strconv"
)

func mockResponse(statusCode int, content string) (res *http.Response) {
	status := strconv.Itoa(statusCode)
	res = &http.Response{
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		Header:     map[string][]string{"sdk": {"test"}},
		StatusCode: statusCode,
		Status:     status + " " + http.StatusText(statusCode),
	}
	res.Body = ioutil.NopCloser(bytes.NewReader([]byte(content)))
	return
}
