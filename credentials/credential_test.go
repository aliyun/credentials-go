package credentials

import (
	"os"
	"testing"

	"github.com/alibabacloud-go/tea/tea"
	"github.com/aliyun/credentials-go/credentials/request"
	"github.com/aliyun/credentials-go/credentials/utils"
	"github.com/stretchr/testify/assert"
)

var privatekey = `----
this is privatekey`

func Test_NewCredential(t *testing.T) {
	originAccessKey := os.Getenv(EnvVarAccessKeyId)
	originAccessSecret := os.Getenv(EnvVarAccessKeySecret)
	os.Setenv(EnvVarAccessKeyId, "accesskey")
	os.Setenv(EnvVarAccessKeySecret, "accesssecret")
	defer func() {
		os.Setenv(EnvVarAccessKeyId, originAccessKey)
		os.Setenv(EnvVarAccessKeySecret, originAccessSecret)
	}()
	cred, err := NewCredential(nil)
	assert.Nil(t, err)
	assert.NotNil(t, cred)
	os.Unsetenv(EnvVarAccessKeyId)
	os.Unsetenv(EnvVarAccessKeySecret)
	cred, err = NewCredential(nil)
	assert.NotNil(t, err)
	assert.Equal(t, "No credential found", err.Error())
	assert.Nil(t, cred)

	config := &Config{
		Type: tea.String("access_key"),
	}
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "AccessKeyId cannot be empty", err.Error())
	assert.Nil(t, cred)

	config.AccessKeyId = tea.String("AccessKeyId")
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "AccessKeySecret cannot be empty", err.Error())
	assert.Nil(t, cred)

	config.Type = tea.String("sts")
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "AccessKeySecret cannot be empty", err.Error())
	assert.Nil(t, cred)

	config.AccessKeySecret = tea.String("AccessKeySecret")
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "SecurityToken cannot be empty", err.Error())
	assert.Nil(t, cred)

	config.AccessKeyId = tea.String("")
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "AccessKeyId cannot be empty", err.Error())
	assert.Nil(t, cred)

	config.Type = tea.String("ecs_ram_role")
	cred, err = NewCredential(config)
	assert.Nil(t, err)
	assert.NotNil(t, cred)

	config.Type = tea.String("rsa_key_pair")
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "PrivateKeyFile cannot be empty", err.Error())
	assert.Nil(t, cred)

	config.PrivateKeyFile = tea.String("test")
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "PublicKeyId cannot be empty", err.Error())
	assert.Nil(t, cred)

	config.Type = tea.String("ram_role_arn")
	config.AccessKeySecret = tea.String("")
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "AccessKeySecret cannot be empty", err.Error())
	assert.Nil(t, cred)

	config.AccessKeySecret = tea.String("AccessKeySecret")
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "RoleArn cannot be empty", err.Error())
	assert.Nil(t, cred)

	config.RoleArn = tea.String("RoleArn")
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "RoleSessionName cannot be empty", err.Error())
	assert.Nil(t, cred)

	config.RoleSessionName = tea.String("RoleSessionName")
	config.AccessKeyId = tea.String("")
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "AccessKeyId cannot be empty", err.Error())
	assert.Nil(t, cred)

	config.Type = tea.String("bearer")
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "BearerToken cannot be empty", err.Error())
	assert.Nil(t, cred)

	config.Type = tea.String("sdk")
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "Invalid type option, support: access_key, sts, ecs_ram_role, ram_role_arn, rsa_key_pair", err.Error())
	assert.Nil(t, cred)

	config.Type = tea.String("sts")
	config.AccessKeyId = tea.String("AccessKeyId")
	config.AccessKeySecret = tea.String("AccessKeySecret")
	config.SecurityToken = tea.String("SecurityToken")
	cred, err = NewCredential(config)
	assert.Nil(t, err)
	assert.NotNil(t, cred)

	config.Type = tea.String("ecs_ram_role")
	config.RoleName = tea.String("AccessKeyId")
	cred, err = NewCredential(config)
	assert.Nil(t, err)
	assert.NotNil(t, cred)

	config.Type = tea.String("ram_role_arn")
	config.RoleArn = tea.String("roleArn")
	config.RoleSessionName = tea.String("RoleSessionName")
	cred, err = NewCredential(config)
	assert.Nil(t, err)
	assert.NotNil(t, cred)

	config.Type = tea.String("bearer")
	config.BearerToken = tea.String("BearerToken")
	cred, err = NewCredential(config)
	assert.Nil(t, err)
	assert.NotNil(t, cred)

	config.Type = tea.String("rsa_key_pair")
	config.PublicKeyId = tea.String("resource")
	config.PrivateKeyFile = tea.String("nofile")
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "InvalidPath: Can not open PrivateKeyFile, err is open nofile:")
	assert.Nil(t, cred)

	file, err := os.Create("./pk.pem")
	assert.Nil(t, err)
	file.WriteString(privatekey)
	file.Close()
	config.Type = tea.String("rsa_key_pair")
	config.PublicKeyId = tea.String("resource")
	config.PrivateKeyFile = tea.String("./pk.pem")
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
	request.URL = "http://www.aliyun.com"
	runtime := &utils.Runtime{
		Proxy: "# #%gfdf",
	}
	content, err = doAction(request, runtime)
	assert.Equal(t, `parse # #%gfdf: invalid URL escape "%gf"`, err.Error())
	assert.NotNil(t, err)
	assert.Nil(t, content)
}
