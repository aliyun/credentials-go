package credentials

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/aliyun/credentials-go/credentials/request"
	"github.com/aliyun/credentials-go/credentials/utils"
	jmespath "github.com/jmespath/go-jmespath"
)

var securityCredURL = "http://100.100.100.200/latest/meta-data/ram/security-credentials/"

type EcsRamRoleCredential struct {
	*credentialUpdater
	RoleName          string
	sessionCredential *SessionCredential
	runtime           *utils.Runtime
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
	var data interface{}
	err = json.Unmarshal(content, &data)
	if err != nil {
		return fmt.Errorf("refresh Ecs sts token err: Json.Unmarshal fail: %s", err.Error())
	}
	code, err := jmespath.Search("Code", data)
	if err != nil {
		return fmt.Errorf("refresh Ecs sts token err: Fail to get Code: %s", err.Error())
	}
	if code.(string) != "Success" {
		return fmt.Errorf("refresh Ecs sts token err: Code is not Success")
	}
	accessKeyId, err := jmespath.Search("AccessKeyId", data)
	if err != nil {
		return fmt.Errorf("refresh Ecs sts token err: Fail to get AccessKeyId: %s", err.Error())
	}
	accessKeySecret, err := jmespath.Search("AccessKeySecret", data)
	if err != nil {
		return fmt.Errorf("refresh Ecs sts token err: Fail to get AccessKeySecret: %s", err.Error())
	}
	securityToken, err := jmespath.Search("SecurityToken", data)
	if err != nil {
		return fmt.Errorf("refresh Ecs sts token err: Fail to get SecurityToken: %s", err.Error())
	}
	expiration, err := jmespath.Search("Expiration", data)
	if err != nil {
		return fmt.Errorf("refresh Ecs sts token err: Fail to get Expiration: %s", err.Error())
	}
	if accessKeyId == nil || accessKeySecret == nil || securityToken == nil || expiration == nil {
		return fmt.Errorf("refresh Ecs sts token err: AccessKeyId: %v, AccessKeySecret: %v, SecurityToken: %v, Expiration: %v", accessKeyId, accessKeySecret, securityToken, expiration)
	}

	expirationTime, err := time.Parse("2006-01-02T15:04:05Z", expiration.(string))
	e.lastUpdateTimestamp = time.Now().Unix()
	e.credentialExpiration = int(expirationTime.Unix() - time.Now().Unix())
	e.sessionCredential = &SessionCredential{
		AccessKeyId:     accessKeyId.(string),
		AccessKeySecret: accessKeySecret.(string),
		SecurityToken:   securityToken.(string),
	}

	return
}
