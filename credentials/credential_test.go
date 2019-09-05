package credentials

import (
	"os"
	"testing"

	"github.com/aliyun/credentials-go/credentials/utils"

	"github.com/aliyun/credentials-go/credentials/request"

	"github.com/stretchr/testify/assert"
)

func Test_NewCredential(t *testing.T) {
	originAccessKey := os.Getenv(EnvVarAccessKeyID)
	originAccessSecret := os.Getenv(EnvVarAccessKeySecret)
	os.Setenv(EnvVarAccessKeyID, "accesskey")
	os.Setenv(EnvVarAccessKeySecret, "accesssecret")
	defer func() {
		os.Setenv(EnvVarAccessKeyID, originAccessKey)
		os.Setenv(EnvVarAccessKeySecret, originAccessSecret)
	}()
	cred, err := NewCredential(nil)
	assert.Nil(t, err)
	assert.NotNil(t, cred)
	os.Unsetenv(EnvVarAccessKeyID)
	os.Unsetenv(EnvVarAccessKeySecret)
	cred, err = NewCredential(nil)
	assert.NotNil(t, err)
	assert.Equal(t, "No credential found", err.Error())
	assert.Nil(t, cred)

	config := &Configuration{
		Type: "access_key",
	}
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "AccessKeyID cannot be empty", err.Error())
	assert.Nil(t, cred)

	config.AccessKeyID = "AccessKeyID"
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "AccessKeySecret cannot be empty", err.Error())
	assert.Nil(t, cred)

	config.Type = "sts"
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "AccessKeySecret cannot be empty", err.Error())
	assert.Nil(t, cred)

	config.AccessKeySecret = "AccessKeySecret"
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "SecurityToken cannot be empty", err.Error())
	assert.Nil(t, cred)

	config.AccessKeyID = ""
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "AccessKeyID cannot be empty", err.Error())
	assert.Nil(t, cred)

	config.Type = "ecs_ram_role"
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "RoleName cannot be empty", err.Error())
	assert.Nil(t, cred)

	config.Type = "rsa_key_pair"
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "PrivateKeyFile cannot be empty", err.Error())
	assert.Nil(t, cred)

	config.PrivateKeyFile = "test"
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "PublicKeyID cannot be empty", err.Error())
	assert.Nil(t, cred)

	config.Type = "ram_role_arn"
	config.AccessKeySecret = ""
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "AccessKeySecret cannot be empty", err.Error())
	assert.Nil(t, cred)

	config.AccessKeySecret = "AccessKeySecret"
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "RoleArn cannot be empty", err.Error())
	assert.Nil(t, cred)

	config.RoleArn = "RoleArn"
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "RoleSessionName cannot be empty", err.Error())
	assert.Nil(t, cred)

	config.RoleSessionName = "RoleSessionName"
	config.AccessKeyID = ""
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "AccessKeyID cannot be empty", err.Error())
	assert.Nil(t, cred)

	config.Type = "bearer"
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "BearerToken cannot be empty", err.Error())
	assert.Nil(t, cred)

	config.Type = "sdk"
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "Invalid type option, support: access_key, sts, ecs_ram_role, ram_role_arn, rsa_key_pair", err.Error())
	assert.Nil(t, cred)

	config.Type = "sts"
	config.AccessKeyID = "AccessKeyID"
	config.AccessKeySecret = "AccessKeySecret"
	config.SecurityToken = "SecurityToken"
	cred, err = NewCredential(config)
	assert.Nil(t, err)
	assert.NotNil(t, cred)

	config.Type = "ecs_ram_role"
	config.RoleName = "AccessKeyID"
	cred, err = NewCredential(config)
	assert.Nil(t, err)
	assert.NotNil(t, cred)

	config.Type = "ram_role_arn"
	config.RoleArn = "roleArn"
	config.RoleSessionName = "RoleSessionName"
	cred, err = NewCredential(config)
	assert.Nil(t, err)
	assert.NotNil(t, cred)

	config.Type = "bearer"
	config.BearerToken = "BearerToken"
	cred, err = NewCredential(config)
	assert.Nil(t, err)
	assert.NotNil(t, cred)

	config.Type = "rsa_key_pair"
	config.PublicKeyID = "resource"
	config.PrivateKeyFile = "nofile"
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "InvalidPath: Can not open PrivateKeyFile, err is open nofile:")
	assert.Nil(t, cred)

	config.Type = "rsa_key_pair"
	config.PublicKeyID = "resource"
	config.PrivateKeyFile = "./encyptfile"
	cred, err = NewCredential(config)
	assert.Nil(t, err)
	assert.NotNil(t, cred)
}

func Test_doaction(t *testing.T) {
	request := request.NewCommonRequest()
	request.Method = "credential test"
	content, err := doAction(request, nil)
	assert.NotNil(t, err)
	assert.Equal(t, `net/http: invalid method "credential test"`, err.Error())
	assert.Nil(t, content)
	request.Method = "GET"
	request.Url = "http://www.aliyun.com"
	runtime := &utils.Runtime{
		Proxy: "# #%gfdf",
	}
	content, err = doAction(request, runtime)
	assert.Equal(t, `parse # #%gfdf: invalid URL escape "%gf"`, err.Error())
	assert.NotNil(t, err)
	assert.Nil(t, content)
}
