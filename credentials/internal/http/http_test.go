package http

import (
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRequest(t *testing.T) {
	req := &Request{
		Method:   "GET",
		Protocol: "http",
		Host:     "www.aliyun.com",
		Path:     "/",
	}
	assert.Equal(t, "GET http://www.aliyun.com/", req.BuildRequestURL())

	req = &Request{
		Method: "GET",
		URL:    "http://www.aliyun.com",
		Path:   "/",
	}
	assert.Equal(t, "GET http://www.aliyun.com", req.BuildRequestURL())

	// With query
	req = &Request{
		Method:   "GET",
		Protocol: "http",
		Host:     "www.aliyun.com",
		Path:     "/",
		Queries: map[string]string{
			"spm": "test",
		},
	}
	assert.Equal(t, "GET http://www.aliyun.com/?spm=test", req.BuildRequestURL())
}

func TestDoGet(t *testing.T) {
	req := &Request{
		Method:   "GET",
		Protocol: "http",
		Host:     "www.aliyun.com",
		Path:     "/",
	}
	res, err := Do(req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
	assert.Equal(t, 200, res.StatusCode)
	assert.Equal(t, "text/html;charset=UTF-8", res.Headers["Content-Type"])

	req = &Request{
		Method: "GET",
		URL:    "http://www.aliyun.com",
	}
	res, err = Do(req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
	assert.Equal(t, 200, res.StatusCode)
	assert.Equal(t, "text/html;charset=UTF-8", res.Headers["Content-Type"])
}

func TestDoPost(t *testing.T) {
	req := &Request{
		Method:   "POST",
		Protocol: "http",
		Host:     "www.aliyun.com",
		Path:     "/",
		Form: map[string]string{
			"URL": "HI",
		},
		Headers: map[string]string{
			"Accept-Language": "zh",
		},
	}
	res, err := Do(req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
	assert.Equal(t, 200, res.StatusCode)
	assert.Equal(t, "text/html; charset=utf-8", res.Headers["Content-Type"])
}

type errorReader struct {
}

func (r *errorReader) Read(p []byte) (n int, err error) {
	err = errors.New("read failed")
	return
}

func TestDoWithError(t *testing.T) {
	originNewRequest := newRequest
	defer func() { newRequest = originNewRequest }()

	// case 1: mock new http request failed
	newRequest = func(method, url string, body io.Reader) (*http.Request, error) {
		return nil, errors.New("new http request failed")
	}

	req := &Request{
		Method:   "POST",
		Protocol: "http",
		Host:     "www.aliyun.com",
		Path:     "/",
		Form: map[string]string{
			"URL": "HI",
		},
		Headers: map[string]string{
			"Accept-Language": "zh",
		},
	}
	_, err := Do(req)
	assert.EqualError(t, err, "new http request failed")

	// reset new request
	newRequest = originNewRequest

	// case 2: server error
	originDo := hookDo
	defer func() { hookDo = originDo }()
	hookDo = func(fn do) do {
		return func(req *http.Request) (res *http.Response, err error) {
			err = errors.New("mock server error")
			return
		}
	}
	_, err = Do(req)
	assert.EqualError(t, err, "mock server error")

	// case 4: mock read response error
	hookDo = func(fn do) do {
		return func(req *http.Request) (res *http.Response, err error) {
			res = &http.Response{
				Proto:      "HTTP/1.1",
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header:     map[string][]string{},
				StatusCode: 200,
				Status:     "200 " + http.StatusText(200),
			}
			res.Body = ioutil.NopCloser(&errorReader{})
			return
		}
	}

	_, err = Do(req)
	assert.EqualError(t, err, "read failed")
}

func TestDoWithProxy(t *testing.T) {
	req := &Request{
		Method:   "POST",
		Protocol: "http",
		Host:     "www.aliyun.com",
		Path:     "/",
		Form: map[string]string{
			"URL": "HI",
		},
		Headers: map[string]string{
			"Accept-Language": "zh",
		},
		Proxy: "http://localhost:9999/",
	}
	_, err := Do(req)
	assert.Contains(t, err.Error(), "proxyconnect tcp: dial tcp")
	assert.Contains(t, err.Error(), "connect: connection refused")

	// invalid proxy url
	req.Proxy = string([]byte{0x7f})
	_, err = Do(req)
	assert.Contains(t, err.Error(), "net/url: invalid control character in URL")
}

func TestDoWithConnectTimeout(t *testing.T) {
	req := &Request{
		Method:   "POST",
		Protocol: "http",
		Host:     "www.aliyun.com",
		Path:     "/",
		Form: map[string]string{
			"URL": "HI",
		},
		Headers: map[string]string{
			"Accept-Language": "zh",
		},
		ConnectTimeout: 1 * time.Nanosecond,
	}
	_, err := Do(req)
	assert.Contains(t, err.Error(), "dial tcp: ")
	assert.Contains(t, err.Error(), "i/o timeout")
}

func TestDoWithReadTimeout(t *testing.T) {
	req := &Request{
		Method:      "POST",
		Protocol:    "http",
		Host:        "www.aliyun.com",
		Path:        "/",
		ReadTimeout: 1 * time.Nanosecond,
	}
	_, err := Do(req)
	assert.Contains(t, err.Error(), "(Client.Timeout exceeded while awaiting headers)")
}
