package credentials

import (
	"bufio"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/alibabacloud-go/debug/debug"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/aliyun/credentials-go/credentials/request"
	"github.com/aliyun/credentials-go/credentials/response"
	"github.com/aliyun/credentials-go/credentials/utils"
)

var debuglog = debug.Init("credential")

var hookParse = func(err error) error {
	return err
}

// Credential is an interface for getting actual credential
type Credential interface {
	GetAccessKeyId() (string, error)
	GetAccessKeySecret() (string, error)
	GetSecurityToken() (string, error)
	GetBearerToken() string
	GetType() string
}

// Config is important when call NewCredential
type Config struct {
	Type                  *string `json:"type"`
	AccessKeyId           *string `json:"access_key_id"`
	AccessKeySecret       *string `json:"access_key_secret"`
	RoleArn               *string `json:"role_arn"`
	RoleSessionName       *string `json:"role_session_name"`
	PublicKeyId           *string `json:"public_key_id"`
	RoleName              *string `json:"role_name"`
	SessionExpiration     *int    `json:"session_expiration"`
	PrivateKeyFile        *string `json:"private_key_file"`
	BearerToken           *string `json:"bearer_token"`
	SecurityToken         *string `json:"security_token"`
	RoleSessionExpiration *int    `json:"role_session_expiratioon"`
	Policy                *string `json:"policy"`
	Host                  *string `json:"host"`
	Timeout               *int    `json:"timeout"`
	ConnectTimeout        *int    `json:"connect_timeout"`
	Proxy                 *string `json:"proxy"`
}

// NewCredential return a credential according to the type in config.
// if config is nil, the function will use default provider chain to get credential.
// please see README.md for detail.
func NewCredential(config *Config) (credential Credential, err error) {
	if config == nil {
		config, err = defaultChain.resolve()
		if err != nil {
			return
		}
		return NewCredential(config)
	}
	switch tea.StringValue(config.Type) {
	case "access_key":
		err = checkAccessKey(config)
		if err != nil {
			return
		}
		credential = newAccessKeyCredential(tea.StringValue(config.AccessKeyId), tea.StringValue(config.AccessKeySecret))
	case "sts":
		err = checkSTS(config)
		if err != nil {
			return
		}
		credential = newStsTokenCredential(tea.StringValue(config.AccessKeyId), tea.StringValue(config.AccessKeySecret), tea.StringValue(config.SecurityToken))
	case "ecs_ram_role":
		checkEcsRAMRole(config)
		runtime := &utils.Runtime{
			Host:           tea.StringValue(config.Host),
			Proxy:          tea.StringValue(config.Proxy),
			ReadTimeout:    tea.IntValue(config.Timeout),
			ConnectTimeout: tea.IntValue(config.ConnectTimeout),
		}
		credential = newEcsRAMRoleCredential(tea.StringValue(config.RoleName), runtime)
	case "ram_role_arn":
		err = checkRAMRoleArn(config)
		if err != nil {
			return
		}
		runtime := &utils.Runtime{
			Host:           tea.StringValue(config.Host),
			Proxy:          tea.StringValue(config.Proxy),
			ReadTimeout:    tea.IntValue(config.Timeout),
			ConnectTimeout: tea.IntValue(config.ConnectTimeout),
		}
		credential = newRAMRoleArnCredential(tea.StringValue(config.AccessKeyId), tea.StringValue(config.AccessKeySecret), tea.StringValue(config.RoleArn), tea.StringValue(config.RoleSessionName), tea.StringValue(config.Policy), tea.IntValue(config.RoleSessionExpiration), runtime)
	case "rsa_key_pair":
		err = checkRSAKeyPair(config)
		if err != nil {
			return
		}
		file, err1 := os.Open(tea.StringValue(config.PrivateKeyFile))
		if err1 != nil {
			err = fmt.Errorf("InvalidPath: Can not open PrivateKeyFile, err is %s", err1.Error())
			return
		}
		defer file.Close()
		var privateKey string
		scan := bufio.NewScanner(file)
		for scan.Scan() {
			if strings.HasPrefix(scan.Text(), "----") {
				continue
			}
			privateKey += scan.Text() + "\n"
		}
		runtime := &utils.Runtime{
			Host:           tea.StringValue(config.Host),
			Proxy:          tea.StringValue(config.Proxy),
			ReadTimeout:    tea.IntValue(config.Timeout),
			ConnectTimeout: tea.IntValue(config.ConnectTimeout),
		}
		credential = newRsaKeyPairCredential(privateKey, tea.StringValue(config.PublicKeyId), tea.IntValue(config.SessionExpiration), runtime)
	case "bearer":
		if tea.StringValue(config.BearerToken) == "" {
			err = errors.New("BearerToken cannot be empty")
			return
		}
		credential = newBearerTokenCredential(tea.StringValue(config.BearerToken))
	default:
		err = errors.New("Invalid type option, support: access_key, sts, ecs_ram_role, ram_role_arn, rsa_key_pair")
		return
	}
	return credential, nil
}

func checkRSAKeyPair(config *Config) (err error) {
	if tea.StringValue(config.PrivateKeyFile) == "" {
		err = errors.New("PrivateKeyFile cannot be empty")
		return
	}
	if tea.StringValue(config.PublicKeyId) == "" {
		err = errors.New("PublicKeyId cannot be empty")
		return
	}
	return
}

func checkRAMRoleArn(config *Config) (err error) {
	if tea.StringValue(config.AccessKeySecret) == "" {
		err = errors.New("AccessKeySecret cannot be empty")
		return
	}
	if tea.StringValue(config.RoleArn) == "" {
		err = errors.New("RoleArn cannot be empty")
		return
	}
	if tea.StringValue(config.RoleSessionName) == "" {
		err = errors.New("RoleSessionName cannot be empty")
		return
	}
	if tea.StringValue(config.AccessKeyId) == "" {
		err = errors.New("AccessKeyId cannot be empty")
		return
	}
	return
}

func checkEcsRAMRole(config *Config) (err error) {
	return
}

func checkSTS(config *Config) (err error) {
	if tea.StringValue(config.AccessKeyId) == "" {
		err = errors.New("AccessKeyId cannot be empty")
		return
	}
	if tea.StringValue(config.AccessKeySecret) == "" {
		err = errors.New("AccessKeySecret cannot be empty")
		return
	}
	if tea.StringValue(config.SecurityToken) == "" {
		err = errors.New("SecurityToken cannot be empty")
		return
	}
	return
}

func checkAccessKey(config *Config) (err error) {
	if tea.StringValue(config.AccessKeyId) == "" {
		err = errors.New("AccessKeyId cannot be empty")
		return
	}
	if tea.StringValue(config.AccessKeySecret) == "" {
		err = errors.New("AccessKeySecret cannot be empty")
		return
	}
	return
}

func doAction(request *request.CommonRequest, runtime *utils.Runtime) (content []byte, err error) {
	httpRequest, err := http.NewRequest(request.Method, request.URL, strings.NewReader(""))
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
