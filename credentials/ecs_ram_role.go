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
	sessionCredential *sessionCredential
	runtime           *utils.Runtime
}

type EcsRamRoleResponse struct {
	Code            string `json:"Code" xml:"Code"`
	AccessKeyID     string `json:"AccessKeyID" xml:"AccessKeyID"`
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

// GetAccessKeyID reutrns  EcsRamRoleResponse's AccessKeyID
// if AccessKeyID is not exist or out of date, the function will update it.
func (e *EcsRamRoleCredential) GetAccessKeyID() (string, error) {
	if e.sessionCredential == nil || e.needUpdateCredential() {
		err := e.updateCredential()
		if err != nil {
			return "", err
		}
	}
	return e.sessionCredential.AccessKeyID, nil
}

// GetAccessSecret reutrns  EcsRamRoleResponse's AccessKeySecret
// if AccessKeySecret is not exist or out of date, the function will update it.
func (e *EcsRamRoleCredential) GetAccessSecret() (string, error) {
	if e.sessionCredential == nil || e.needUpdateCredential() {
		err := e.updateCredential()
		if err != nil {
			return "", err
		}
	}
	return e.sessionCredential.AccessKeySecret, nil
}

// GetSecurityToken reutrns  EcsRamRoleResponse's SecurityToken
// if SecurityToken is not exist or out of date, the function will update it.
func (e *EcsRamRoleCredential) GetSecurityToken() (string, error) {
	if e.sessionCredential == nil || e.needUpdateCredential() {
		err := e.updateCredential()
		if err != nil {
			return "", err
		}
	}
	return e.sessionCredential.SecurityToken, nil
}

// GetBearerToken is useless for EcsRamRoleCredential
func (e *EcsRamRoleCredential) GetBearerToken() string {
	return ""
}

// GetType reutrns  EcsRamRoleCredential's type
func (e *EcsRamRoleCredential) GetType() string {
	return "ecs_ram_role"
}

func (e *EcsRamRoleCredential) updateCredential() (err error) {
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
	if resp.AccessKeyID == "" || resp.AccessKeySecret == "" || resp.SecurityToken == "" || resp.Expiration == "" {
		return fmt.Errorf("refresh Ecs sts token err: AccessKeyID: %s, AccessKeySecret: %s, SecurityToken: %s, Expiration: %s", resp.AccessKeyID, resp.AccessKeySecret, resp.SecurityToken, resp.Expiration)
	}

	expirationTime, err := time.Parse("2006-01-02T15:04:05Z", resp.Expiration)
	e.lastUpdateTimestamp = time.Now().Unix()
	e.credentialExpiration = int(expirationTime.Unix() - time.Now().Unix())
	e.sessionCredential = &sessionCredential{
		AccessKeyID:     resp.AccessKeyID,
		AccessKeySecret: resp.AccessKeySecret,
		SecurityToken:   resp.SecurityToken,
	}

	return
}
