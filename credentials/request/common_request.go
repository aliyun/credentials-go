package request

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/aliyun/credentials-go/credentials/utils"
)

type CommonRequest struct {
	Scheme         string
	Method         string
	Domain         string
	RegionId       string
	Url            string
	ReadTimeout    time.Duration
	ConnectTimeout time.Duration
	isInsecure     *bool

	userAgent   map[string]string
	QueryParams map[string]string
	Headers     map[string]string

	queries string
}

func NewCommonRequest() *CommonRequest {
	return &CommonRequest{
		QueryParams: make(map[string]string),
		Headers:     make(map[string]string),
	}
}

func (request *CommonRequest) BuildUrl() string {
	url := fmt.Sprintf("%s://%s", strings.ToLower(request.Scheme), request.Domain)
	request.queries = "/?" + utils.GetUrlFormedMap(request.QueryParams)
	return url + request.queries
}

func (request *CommonRequest) BuildStringToSign() (stringToSign string) {
	signParams := make(map[string]string)
	for key, value := range request.QueryParams {
		signParams[key] = value
	}

	stringToSign = utils.GetUrlFormedMap(signParams)
	stringToSign = strings.Replace(stringToSign, "+", "%20", -1)
	stringToSign = strings.Replace(stringToSign, "*", "%2A", -1)
	stringToSign = strings.Replace(stringToSign, "%7E", "~", -1)
	stringToSign = url.QueryEscape(stringToSign)
	stringToSign = request.Method + "&%2F&" + stringToSign
	return
}
