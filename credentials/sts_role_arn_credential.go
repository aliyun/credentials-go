package credentials

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/aliyun/credentials-go/credentials/request"
	"github.com/aliyun/credentials-go/credentials/utils"
	jmespath "github.com/jmespath/go-jmespath"
)

const defaultDurationSeconds = 3600

type RamRoleArnCredential struct {
	*credentialUpdater
	AccessKeyId           string
	AccessKeySecret       string
	RoleArn               string
	RoleSessionName       string
	RoleSessionExpiration int
	Policy                string
	sessionCredential     *SessionCredential
	runtime               *utils.Runtime
}

func newRamRoleArnCredential(accessKeyId, accessKeySecret, roleArn, roleSessionName, policy string, roleSessionExpiration int, runtime *utils.Runtime) *RamRoleArnCredential {
	return &RamRoleArnCredential{
		AccessKeyId:           accessKeyId,
		AccessKeySecret:       accessKeySecret,
		RoleArn:               roleArn,
		RoleSessionName:       roleSessionName,
		RoleSessionExpiration: roleSessionExpiration,
		Policy:                policy,
		credentialUpdater:     new(credentialUpdater),
		runtime:               runtime,
	}
}

func (r *RamRoleArnCredential) GetAccessKeyId() (string, error) {
	if r.sessionCredential == nil || r.needUpdateCredential() {
		err := r.UpdateCredential()
		if err != nil {
			return "", err
		}
	}
	return r.sessionCredential.AccessKeyId, nil
}

func (r *RamRoleArnCredential) GetAccessSecret() (string, error) {
	if r.sessionCredential == nil || r.needUpdateCredential() {
		err := r.UpdateCredential()
		if err != nil {
			return "", err
		}
	}
	return r.sessionCredential.AccessKeySecret, nil
}

func (r *RamRoleArnCredential) GetSecurityToken() (string, error) {
	if r.sessionCredential == nil || r.needUpdateCredential() {
		err := r.UpdateCredential()
		if err != nil {
			return "", err
		}
	}
	return r.sessionCredential.SecurityToken, nil
}

func (r *RamRoleArnCredential) GetBearerToken() string {
	return ""
}

func (r *RamRoleArnCredential) GetType() string {
	return "ram_role_arn"
}

func (r *RamRoleArnCredential) UpdateCredential() (err error) {
	if r.runtime == nil {
		r.runtime = new(utils.Runtime)
	}
	request := request.NewCommonRequest()
	request.Domain = "sts.aliyuncs.com"
	request.Scheme = "HTTPS"
	request.Method = "GET"
	request.QueryParams["AccessKeyId"] = r.AccessKeyId
	request.QueryParams["Action"] = "AssumeRole"
	request.QueryParams["Format"] = "JSON"
	if r.RoleSessionExpiration > 0 {
		if r.RoleSessionExpiration >= 900 && r.RoleSessionExpiration <= 3600 {
			request.QueryParams["DurationSeconds"] = strconv.Itoa(r.RoleSessionExpiration)
		} else {
			err = errors.New("[InvalidParam]:Assume Role session duration should be in the range of 15min - 1Hr")
			return
		}
	} else {
		request.QueryParams["DurationSeconds"] = strconv.Itoa(defaultDurationSeconds)
	}
	request.QueryParams["RoleArn"] = r.RoleArn
	if r.Policy != "" {
		request.QueryParams["Policy"] = r.Policy
	}
	request.QueryParams["RoleSessionName"] = r.RoleSessionName
	request.QueryParams["SignatureMethod"] = "HMAC-SHA1"
	request.QueryParams["SignatureVersion"] = "1.0"
	request.QueryParams["Version"] = "2015-04-01"
	request.QueryParams["Timestamp"] = utils.GetTimeInFormatISO8601()
	request.QueryParams["SignatureNonce"] = utils.GetUUID()
	signature := utils.ShaHmac1(request.BuildStringToSign(), r.AccessKeySecret+"&")
	request.QueryParams["Signature"] = signature
	request.Headers["Host"] = request.Domain
	request.Headers["Accept-Encoding"] = "identity"
	request.Url = request.BuildUrl()
	content, err := doAction(request, r.runtime)
	if err != nil {
		return fmt.Errorf("refresh RoleArn sts token err: %s", err.Error())
	}
	var data interface{}
	err = json.Unmarshal(content, &data)
	if err != nil {
		return fmt.Errorf("refresh RoleArn sts token err: Json.Unmarshal fail: %s", err.Error())
	}
	accessKeyId, err := jmespath.Search("Credentials.AccessKeyId", data)
	if err != nil {
		return fmt.Errorf("refresh RoleArn sts token err: Fail to get AccessKeyId: %s", err.Error())
	}
	accessKeySecret, err := jmespath.Search("Credentials.AccessKeySecret", data)
	if err != nil {
		return fmt.Errorf("refresh RoleArn sts token err: Fail to get AccessKeySecret: %s", err.Error())
	}
	securityToken, err := jmespath.Search("Credentials.SecurityToken", data)
	if err != nil {
		return fmt.Errorf("refresh RoleArn sts token err: Fail to get SecurityToken: %s", err.Error())
	}
	expiration, err := jmespath.Search("Credentials.Expiration", data)
	if err != nil {
		return fmt.Errorf("refresh RoleArn sts token err: Fail to get Expiration: %s", err.Error())
	}
	if accessKeyId == nil || accessKeySecret == nil || securityToken == nil || expiration == nil {
		return fmt.Errorf("refresh RoleArn sts token err: AccessKeyId: %v, AccessKeySecret: %v, SecurityToken: %v, Expiration: %v", accessKeyId, accessKeySecret, securityToken, expiration)
	}

	expirationTime, err := time.Parse("2006-01-02T15:04:05Z", expiration.(string))
	r.lastUpdateTimestamp = time.Now().Unix()
	r.credentialExpiration = int(expirationTime.Unix() - time.Now().Unix())
	r.sessionCredential = &SessionCredential{
		AccessKeyId:     accessKeyId.(string),
		AccessKeySecret: accessKeySecret.(string),
		SecurityToken:   securityToken.(string),
	}

	return
}
