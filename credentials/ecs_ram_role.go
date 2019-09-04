package credentials

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/aliyun/credentials-go/credentials/request"
	"github.com/aliyun/credentials-go/credentials/utils"
)

var securityCredURL = "http://100.100.100.200/latest/meta-data/ram/security-credentials/"

type EcsRamRoleCredential struct {
	*credentialUpdater
	RoleName          string
	sessionCredential *SessionCredential
	runtime           *utils.Runtime
}

type EcsRamRoleResponse struct {
	Code            string `json:"Code" xml:"Code"`
	AccessKeyId     string `json:"AccessKeyId" xml:"AccessKeyId"`
	AccessKeySecret string `json:"AccessKeySecret" xml:"AccessKeySecret"`
	SecurityToken   string `json:"SecurityToken" xml:"SecurityToken"`
	Expiration      string `json:"Expiration" xml:"Expiration"`
}

func newEcsRamRoleCredential(roleName string, runtime *utils.Runtime) *EcsRamRoleCredential {
	return &EcsRamRoleCredential{
		RoleName:          roleName,
		credentialUpdater: new(credentialUpdater),
		runtime:           runtime,
	}
}

func (e *EcsRamRoleCredential) GetAccessKeyId() (string, error) {
	if e.sessionCredential == nil || e.needUpdateCredential() {
		err := e.UpdateCredential()
		if err != nil {
			return "", err
		}
	}
	return e.sessionCredential.AccessKeyId, nil
}

func (e *EcsRamRoleCredential) GetAccessSecret() (string, error) {
	if e.sessionCredential == nil || e.needUpdateCredential() {
		err := e.UpdateCredential()
		if err != nil {
			return "", err
		}
	}
	return e.sessionCredential.AccessKeySecret, nil
}

func (e *EcsRamRoleCredential) GetSecurityToken() (string, error) {
	if e.sessionCredential == nil || e.needUpdateCredential() {
		err := e.UpdateCredential()
		if err != nil {
			return "", err
		}
	}
	return e.sessionCredential.SecurityToken, nil
}

func (e *EcsRamRoleCredential) GetBearerToken() string {
	return ""
}

func (e *EcsRamRoleCredential) GetType() string {
	return "ecs_ram_role"
}

func (e *EcsRamRoleCredential) UpdateCredential() (err error) {
	if e.runtime == nil {
		e.runtime = new(utils.Runtime)
	}
	request := request.NewCommonRequest()
	request.Url = securityCredURL + e.RoleName
	request.Method = "GET"
	content, err := doAction(request, e.runtime)
	if err != nil {
		return fmt.Errorf("refresh Ecs sts token err: %s", err.Error())
	}
	var resp *EcsRamRoleResponse
	err = json.Unmarshal(content, &resp)
	if err != nil {
		return fmt.Errorf("refresh Ecs sts token err: Json Unmarshal fail: %s", err.Error())
	}
	if resp.Code != "Success" {
		return fmt.Errorf("refresh Ecs sts token err: Code is not Success")
	}
	if resp.AccessKeyId == "" || resp.AccessKeySecret == "" || resp.SecurityToken == "" || resp.Expiration == "" {
		return fmt.Errorf("refresh Ecs sts token err: AccessKeyId: %s, AccessKeySecret: %s, SecurityToken: %s, Expiration: %s", resp.AccessKeyId, resp.AccessKeySecret, resp.SecurityToken, resp.Expiration)
	}

	expirationTime, err := time.Parse("2006-01-02T15:04:05Z", resp.Expiration)
	e.lastUpdateTimestamp = time.Now().Unix()
	e.credentialExpiration = int(expirationTime.Unix() - time.Now().Unix())
	e.sessionCredential = &SessionCredential{
		AccessKeyId:     resp.AccessKeyId,
		AccessKeySecret: resp.AccessKeySecret,
		SecurityToken:   resp.SecurityToken,
	}

	return
}
