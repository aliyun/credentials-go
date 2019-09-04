English | [简体中文](README-CN.md)

# Alibaba Cloud Credentials for Go
[![Latest Stable Version](https://badge.fury.io/gh/aliyun%2Fcredentials-go.svg)](https://badge.fury.io/gh/aliyun%2Fcredentials-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/aliyun/credentials-go)](https://goreportcard.com/report/github.com/aliyun/credentials-go)
[![codecov](https://codecov.io/gh/aliyun/credentials-go/branch/master/graph/badge.svg)](https://codecov.io/gh/aliyun/credentials-go)
[![License](https://poser.pugx.org/alibabacloud/credentials/license)](https://packagist.org/packages/alibabacloud/credentials)
[![Travis Build Status](https://travis-ci.org/aliyun/credentials-go.svg?branch=master)](https://travis-ci.org/aliyun/credentials-go)
[![Appveyor Build Status](https://ci.appveyor.com/api/projects/status/6sxnwbriw1gwehx8/branch/master?svg=true)](https://ci.appveyor.com/project/aliyun/credentials-go)

![](https://aliyunsdk-pages.alicdn.com/icons/AlibabaCloud.svg)

Alibaba Cloud Credentials for Go is a tool for Go developers to manage credentials.

This document introduces how to obtain and use Alibaba Cloud Credentials for Go.

## Requirements
- It's necessary for you to make sure your system have installed a Go environment which is new than 1.10.x.

## Installation
Use `go get` to install SDK：

```sh
$ go get -u github.com/aliyun/credentials-go
```

If you use `dep` to manage your dependence, you can use the following command:

```sh
$ dep ensure -add  github.com/aliyun/credentials-go
```

## Quick Examples
Before you begin, you need to sign up for an Alibaba Cloud account and retrieve your [Credentials](https://usercenter.console.aliyun.com/#/manage/ak).

### Credential Type

#### access_key
Setup access_key credential through [User Information Management][ak], it have full authority over the account, please keep it safe. Sometimes for security reasons, you cannot hand over a primary account AccessKey with full access to the developer of a project. You may create a sub-account [RAM Sub-account][ram] , grant its [authorization][permissions]，and use the AccessKey of RAM Sub-account.
```go
import (
	"github.com/aliyun/credentials-go/credentials"
)

func main(){
	config := &credentials.Configuration{
		Type:                  "access_key",       // Which type of credential you want
		AccessKeyId:           "AccessKeyId",      // AccessKeyId of your account
		AccessKeySecret:       "AccessKeySecret",  // AccessKeySecret of your account
    }
	akCredential, err := credentials.NewCredential(config)
	if err != nil {
		return err
	}
	accessKeyId, err := akCredential.GetAccessKeyId()
	accessSecret, err := akCredential.GetAccessSecret()
	credentialType := akCredential.GetType()
}
```

#### sts
Create a temporary security credential by applying Temporary Security Credentials (TSC) through the Security Token Service (STS).
```go
import (
	"github.com/aliyun/credentials-go/credentials"
)

func main(){
	config := &credentials.Configuration{
		Type:                  "sts",              // Which type of credential you want
		AccessKeyId:           "AccessKeyId",      // AccessKeyId of your account
		AccessKeySecret:       "AccessKeySecret",  // AccessKeySecret of your account
		SecurityToken:         "SecurityToken",    // Temporary Security Token
    }
	stsCredential, err := credentials.NewCredential(config)
	if err != nil {
		return err
	}
	accessKeyId, err := stsCredential.GetAccessKeyId()
	accessSecret, err := stsCredential.GetAccessSecret()
	securityToken, err := stsCredential.GetSecurityToken()
	credentialType := stsCredential.GetType()
}
```

#### ram_role_arn
By specifying [RAM Role][RAM Role], the credential will be able to automatically request maintenance of STS Token. If you want to limit the permissions([How to make a policy][policy]) of STS Token, you can assign value for `Policy`.
```go
import (
	"github.com/aliyun/credentials-go/credentials"
)

func main(){
	config := &credentials.Configuration{
		Type:                   "ram_role_arn",     // Which type of credential you want
		AccessKeyId:            "AccessKeyId",      // AccessKeyId of your account
		AccessKeySecret:        "AccessKeySecret",  // AccessKeySecret of your account
		RoleArn:                "RoleArn",          // Format: acs:ram::USER_ID:role/ROLE_NAME
		RoleSessionName:        "RoleSessionName",  // Role Session Name
		Policy:                 "Policy",           // Not required, limit the permissions of STS Token
		RoleSessionExpiration:  3600,               // Not required, limit the Valid time of STS Token
    }
	arnCredential, err := credentials.NewCredential(config)
	if err != nil {
		return err
	}
	accessKeyId, err := arnCredential.GetAccessKeyId()
	accessSecret, err := arnCredential.GetAccessSecret()
	securityToken, err := arnCredential.GetSecurityToken()
	credentialType := arnCredential.GetType()
}
```

#### ecs_ram_role
By specifying the role name, the credential will be able to automatically request maintenance of STS Token.
```go
import (
	"github.com/aliyun/credentials-go/credentials"
)

func main(){
	config := &credentials.Configuration{
		Type:                   "ecs_ram_role",     // Which type of credential you want
		RoleName:               "RoleName",         // RoleName of your account
    }
	ecsCredential, err := credentials.NewCredential(config)
	if err != nil {
		return err
	}
	accessKeyId, err := ecsCredential.GetAccessKeyId()
	accessSecret, err := ecsCredential.GetAccessSecret()
	securityToken, err := ecsCredential.GetSecurityToken()
	credentialType := ecsCredential.GetType()
}
```

#### rsa_key_pair
By specifying the public key ID and the private key file, the credential will be able to automatically request maintenance of the AccessKey before sending the request. Only Japan station is supported. 
```go
import (
	"github.com/aliyun/credentials-go/credentials"
)

func main(){
	config := &credentials.Configuration{
		Type:                   "rsa_key_pair",       // Which type of credential you want
		PrivateKeyFile:         "PrivateKeyFile",     // The file path to store the PrivateKey
		PublicKeyId:            "PublicKeyId",        // PublicKeyId of your account
    }
	rsaCredential, err := credentials.NewCredential(config)
	if err != nil {
		return err
	}
	accessKeyId, err := rsaCredential.GetAccessKeyId()
	accessSecret, err := rsaCredential.GetAccessSecret()
	securityToken, err := rsaCredential.GetSecurityToken()
	credentialType := rsaCredential.GetType()
}
```

#### bearer
If credential is required by the Cloud Call Centre (CCC), please apply for Bearer Token maintenance by yourself.
```go
import (
	"github.com/aliyun/credentials-go/credentials"
)

func main(){
	config := &credentials.Configuration{
		Type:                 "bearer",       // Which type of credential you want
		BearerToken:          "BearerToken",  // BearerToken of your account
    }
	bearerCredential, err := credentials.NewCredential(config)
	if err != nil {
		return err
	}
	bearerToken := bearerCredential.GetBearerToken()
	credentialType := bearerCredential.GetType()
}
```

### Provider
If you call `NewCredential()` with nil, it will use provider chain to get credential for you.

#### 1. Environment Credentials
The program first looks for environment credentials in the environment variable. If the `ALICLOUD_ACCESS_KEY` and `ALICLOUD_SECRET_KEY` environment variables are defined and are not empty, the program will use them to create the default credential. If not, the program loads and looks for the client in the configuration file.

#### 2. Configuration File
If there is `~/.alibabacloud/credentials` default file (Windows shows `C:\Users\USER_NAME\.alibabacloud\credentials`), the program will automatically create credential with the name of 'default'. The default file may not exist, but a parse error throws an exception. The specified files can also be loaded indefinitely: `AlibabaCloud::load('/data/credentials', 'vfs://AlibabaCloud/credentials', ...);` This configuration file can be shared between different projects and between different tools. Because it is outside the project and will not be accidentally committed to the version control. Environment variables can be used on Windows to refer to the home directory %UserProfile%. Unix-like systems can use the environment variable $HOME or ~ (tilde). The path to the default file can be modified by defining the `ALIBABA_CLOUD_CREDENTIALS_FILE` environment variable.

```ini
[default]                          # Default credential
type = access_key                  # Certification type: access_key
access_key_id = foo                # access key id
access_key_secret = bar            # access key secret
```

#### 3. Instance RAM Role
If the environment variable `ALIBABA_CLOUD_ECS_METADATA` is defined and not empty, the program will take the value of the environment variable as the role name and request `http://100.100.100.200/latest/meta-data/ram/security-credentials/` to get the temporary Security credential.


[ak]: https://usercenter.console.aliyun.com/#/manage/ak
[ram]: https://ram.console.aliyun.com/users
[policy]: https://www.alibabacloud.com/help/doc-detail/28664.htm?spm=a2c63.p38356.a3.3.27a63b01khWgdh
[permissions]: https://ram.console.aliyun.com/permissions
[RAM Role]: https://ram.console.aliyun.com/#/role/list