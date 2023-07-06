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

	config := new(Config)
	assert.NotNil(t, config.String())
	assert.NotNil(t, config.GoString())

	config.SetType("access_key")
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "AccessKeyId cannot be empty", err.Error())
	assert.Nil(t, cred)

	config.SetAccessKeyId("AccessKeyId")
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "AccessKeySecret cannot be empty", err.Error())
	assert.Nil(t, cred)

	config.SetType("sts")
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "AccessKeySecret cannot be empty", err.Error())
	assert.Nil(t, cred)

	config.SetAccessKeySecret("AccessKeySecret")
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "SecurityToken cannot be empty", err.Error())
	assert.Nil(t, cred)

	config.SetAccessKeyId("")
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "AccessKeyId cannot be empty", err.Error())
	assert.Nil(t, cred)

	config.SetType("ecs_ram_role")
	cred, err = NewCredential(config)
	assert.Nil(t, err)
	assert.NotNil(t, cred)

	config.SetType("rsa_key_pair")
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "PrivateKeyFile cannot be empty", err.Error())
	assert.Nil(t, cred)

	config.SetPrivateKeyFile("test")
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "PublicKeyId cannot be empty", err.Error())
	assert.Nil(t, cred)

	config.SetType("ram_role_arn")
	config.SetAccessKeySecret("")
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "AccessKeySecret cannot be empty", err.Error())
	assert.Nil(t, cred)

	config.SetAccessKeySecret("AccessKeySecret")
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "RoleArn cannot be empty", err.Error())
	assert.Nil(t, cred)

	config.RoleArn = tea.String("RoleArn")
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "RoleSessionName cannot be empty", err.Error())
	assert.Nil(t, cred)

	config.SetRoleSessionName("RoleSessionName")
	config.SetAccessKeyId("")
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "AccessKeyId cannot be empty", err.Error())
	assert.Nil(t, cred)

	config.SetType("bearer")
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "BearerToken cannot be empty", err.Error())
	assert.Nil(t, cred)

	config.SetType("sdk")
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "Invalid type option, support: access_key, sts, ecs_ram_role, ram_role_arn, rsa_key_pair", err.Error())
	assert.Nil(t, cred)

	config.SetType("sts").
		SetAccessKeyId("AccessKeyId").
		SetAccessKeySecret("AccessKeySecret").
		SetSecurityToken("SecurityToken")
	cred, err = NewCredential(config)
	assert.Nil(t, err)
	assert.NotNil(t, cred)

	config.SetType("ecs_ram_role").
		SetRoleName("AccessKeyId")
	cred, err = NewCredential(config)
	assert.Nil(t, err)
	assert.NotNil(t, cred)

	config.SetType("ram_role_arn").
		SetRoleArn("roleArn").
		SetRoleSessionName("RoleSessionName")
	cred, err = NewCredential(config)
	assert.Nil(t, err)
	assert.NotNil(t, cred)

	config.SetType("bearer").
		SetBearerToken("BearerToken")
	cred, err = NewCredential(config)
	assert.Nil(t, err)
	assert.NotNil(t, cred)

	config.SetType("rsa_key_pair").
		SetPublicKeyId("resource").
		SetPrivateKeyFile("nofile").
		SetSessionExpiration(10).
		SetRoleSessionExpiration(10).
		SetPolicy("").
		SetHost("").
		SetTimeout(10).
		SetConnectTimeout(10).
		SetProxy("")
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "InvalidPath: Can not open PrivateKeyFile, err is open nofile:")
	assert.Nil(t, cred)

	file, err := os.Create("./pk.pem")
	assert.Nil(t, err)
	file.WriteString(privatekey)
	file.Close()

	config.SetType("rsa_key_pair").
		SetPublicKeyId("resource").
		SetPrivateKeyFile("./pk.pem")
	cred, err = NewCredential(config)
	assert.Nil(t, err)
	assert.NotNil(t, cred)

	config.SetType("oidc_role_arn").
		SetOIDCProviderArn("oidc_provider_arn_test").
		SetOIDCTokenFilePath("oidc_token_file_path_test").
		SetRoleArn("role_arn_test")
	cred, err = NewCredential(config)
	assert.Nil(t, err)
	assert.NotNil(t, cred)
	assert.Equal(t, "oidc_provider_arn_test", tea.StringValue(config.OIDCProviderArn))
	assert.Equal(t, "oidc_token_file_path_test", tea.StringValue(config.OIDCTokenFilePath))
	assert.Equal(t, "role_arn_test", tea.StringValue(config.RoleArn))
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
	assert.Contains(t, err.Error(), `invalid URL escape`)
	assert.NotNil(t, err)
	assert.Nil(t, content)
}
