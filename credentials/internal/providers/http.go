package providers

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/alibabacloud-go/debug/debug"
	"github.com/aliyun/credentials-go/credentials/internal/utils"
	"github.com/aliyun/credentials-go/credentials/request"
	"github.com/aliyun/credentials-go/credentials/response"
)

var debuglog = debug.Init("credential")

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

func doAction(request *request.CommonRequest, runtime *utils.Runtime) (content []byte, err error) {
	var urlEncoded string
	if request.BodyParams != nil {
		urlEncoded = utils.GetURLFormedMap(request.BodyParams)
	}
	httpRequest, err := http.NewRequest(request.Method, request.URL, strings.NewReader(urlEncoded))
	if err != nil {
		return
	}
	httpRequest.Proto = "HTTP/1.1"
	httpRequest.Host = request.Domain
	debuglog("> %s %s %s", httpRequest.Method, httpRequest.URL.RequestURI(), httpRequest.Proto)
	debuglog("> Host: %s", httpRequest.Host)
	for key, value := range request.Headers {
		if value != "" {
			debuglog("> %s: %s", key, value)
			httpRequest.Header[key] = []string{value}
		}
	}
	debuglog(">")
	httpClient := &http.Client{}
	httpClient.Timeout = time.Duration(runtime.ReadTimeout) * time.Second
	proxy := &url.URL{}
	if runtime.Proxy != "" {
		proxy, err = url.Parse(runtime.Proxy)
		if err != nil {
			return
		}
	}
	trans := &http.Transport{}
	if proxy != nil && runtime.Proxy != "" {
		trans.Proxy = http.ProxyURL(proxy)
	}
	trans.DialContext = utils.Timeout(time.Duration(runtime.ConnectTimeout) * time.Second)
	httpClient.Transport = trans
	httpResponse, err := hookDo(httpClient.Do)(httpRequest)
	if err != nil {
		return
	}
	debuglog("< %s %s", httpResponse.Proto, httpResponse.Status)
	for key, value := range httpResponse.Header {
		debuglog("< %s: %v", key, strings.Join(value, ""))
	}
	debuglog("<")

	resp := &response.CommonResponse{}
	err = hookParse(resp.ParseFromHTTPResponse(httpResponse))
	if err != nil {
		return
	}
	debuglog("%s", resp.GetHTTPContentString())
	if resp.GetHTTPStatus() != http.StatusOK {
		err = fmt.Errorf("httpStatus: %d, message = %s", resp.GetHTTPStatus(), resp.GetHTTPContentString())
		return
	}
	return resp.GetHTTPContentBytes(), nil
}
