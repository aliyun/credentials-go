package response

import (
	"io"
	"io/ioutil"
	"net/http"
)

var hookReadAll = func(fn func(r io.Reader) (b []byte, err error)) func(r io.Reader) (b []byte, err error) {
	return fn
}

type CommonResponse struct {
	httpStatus        int
	httpHeaders       map[string][]string
	httpContentString string
	httpContentBytes  []byte
}

func (resp *CommonResponse) ParseFromHttpResponse(httpResponse *http.Response) (err error) {
	defer httpResponse.Body.Close()
	body, err := hookReadAll(ioutil.ReadAll)(httpResponse.Body)
	if err != nil {
		return
	}
	resp.httpStatus = httpResponse.StatusCode
	resp.httpHeaders = httpResponse.Header
	resp.httpContentBytes = body
	resp.httpContentString = string(body)
	return
}

func (resp *CommonResponse) GetHttpStatus() int {
	return resp.httpStatus
}

func (resp *CommonResponse) GetHttpHeaders() map[string][]string {
	return resp.httpHeaders
}

func (resp *CommonResponse) GetHttpContentString() string {
	return resp.httpContentString
}

func (resp *CommonResponse) GetHttpContentBytes() []byte {
	return resp.httpContentBytes
}
