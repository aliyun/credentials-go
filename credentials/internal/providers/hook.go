package providers

import (
	"io"
	"net/http"

	httputil "github.com/aliyun/credentials-go/credentials/internal/http"
)

var httpDo = httputil.Do

type newReuqest func(method, url string, body io.Reader) (*http.Request, error)

var hookNewRequest = func(fn newReuqest) newReuqest {
	return fn
}

type do func(req *http.Request) (*http.Response, error)

var hookDo = func(fn do) do {
	return fn
}
