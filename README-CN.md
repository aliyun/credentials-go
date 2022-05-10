[English](README.md) | 简体中文

# Alibaba Cloud Credentials for Go
[![Latest Stable Version](https://badge.fury.io/gh/aliyun%2Fcredentials-go.svg)](https://badge.fury.io/gh/aliyun%2Fcredentials-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/aliyun/credentials-go)](https://goreportcard.com/report/github.com/aliyun/credentials-go)
[![codecov](https://codecov.io/gh/aliyun/credentials-go/branch/master/graph/badge.svg)](https://codecov.io/gh/aliyun/credentials-go)
[![License](https://poser.pugx.org/alibabacloud/credentials/license)](https://packagist.org/packages/alibabacloud/credentials)
[![Travis Build Status](https://travis-ci.org/aliyun/credentials-go.svg?branch=master)](https://travis-ci.org/aliyun/credentials-go)
[![Appveyor Build Status](https://ci.appveyor.com/api/projects/status/6sxnwbriw1gwehx8/branch/master?svg=true)](https://ci.appveyor.com/project/aliyun/credentials-go)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/aliyun/credentials-go/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/aliyun/credentials-go/?branch=master)

![](https://aliyunsdk-pages.alicdn.com/icons/AlibabaCloud.svg)

Alibaba Cloud Credentials for Go 是帮助 GO 开发者管理凭据的工具。
                   
本文将介绍如何获取和使用 Alibaba Cloud Credentials for Go。

## 要求
- 请确保你的系统安装了不低于 1.10.x 版本的 Go 环境。

## 安装
使用 `go get` 下载安装

```sh
$ go get -u github.com/aliyun/credentials-go
```

如果你使用 `dep` 来管理你的依赖包，你可以使用以下命令:

```sh
$ dep ensure -add  github.com/aliyun/credentials-go
```

##快速使用
在您开始之前，您需要注册阿里云帐户并获取您的[凭证](https://usercenter.console.aliyun.com/#/manage/ak)。

### 凭证类型

#### AccessKey
通过[用户信息管理][ak]设置 access_key，它们具有该账户完全的权限，请妥善保管。有时出于安全考虑，您不能把具有完全访问权限的主账户 AccessKey 交于一个项目的开发者使用，您可以[创建RAM子账户][ram]并为子账户[授权][permissions]，使用RAM子用户的 AccessKey 来进行API调用。
```go
import (
	"fmt"

	"github.com/aliyun/credentials-go/credentials"
)

func main(){
	config := new(credentials.Config).
		// Which type of credential you want
		SetType("access_key").
		// AccessKeyId of your account
		SetAccessKeyId("AccessKeyId").
		// AccessKeySecret of your account
		SetAccessKeySecret("AccessKeySecret")

	akCredential, err := credentials.NewCredential(config)
	if err != nil {
		return
	}
	accessKeyId, err := akCredential.GetAccessKeyId()
	accessSecret, err := akCredential.GetAccessKeySecret()
	credentialType := akCredential.GetType()
	fmt.Println(accessKeyId, accessSecret, credentialType)
}
```

#### STS
通过安全令牌服务（Security Token Service，简称 STS），申请临时安全凭证（Temporary Security Credentials，简称 TSC），创建临时安全凭证。
```go
import (
	"fmt"

	"github.com/aliyun/credentials-go/credentials"
)

func main() {
	config := new(credentials.Config).
		// Which type of credential you want
		SetType("sts").
		// AccessKeyId of your account
		SetAccessKeyId("AccessKeyId").
		// AccessKeySecret of your account
		SetAccessKeySecret("AccessKeySecret").
		// Temporary Security Token
		SetSecurityToken("SecurityToken")

	stsCredential, err := credentials.NewCredential(config)
	if err != nil {
		return
	}
	accessKeyId, err := stsCredential.GetAccessKeyId()
	accessSecret, err := stsCredential.GetAccessKeySecret()
	securityToken, err := stsCredential.GetSecurityToken()
	credentialType := stsCredential.GetType()
	fmt.Println(accessKeyId, accessSecret, securityToken, credentialType)
}
```

#### AssumeRoleWithOIDC
在执行oidc角色SSO时，通过调用AssumeRoleWithOIDC接口获取扮演RAM角色的临时身份凭证（STS令牌）。
``` go
package main

import (
	"fmt"
	"net/http"

	"github.com/aliyun/credentials-go/credentials"
)

func main() {
	config := new(credentials.Config).
		SetType("oidc_role_arn").
		SetOIDCProviderArn("OIDCProviderArn").
		SetOIDCTokenFilePath("OIDCTokenFilePath").
		SetRoleSessionName("RoleSessionName").
		SetPolicy("Policy").
		SetRoleArn("RoleArn").
		SetSessionExpiration(3600)
	oidcCredential, err := credentials.NewCredential(config)
	if err != nil {
		return
	}
	accessKeyId, err := oidcCredential.GetAccessKeyId()
	accessKeySecret, err := oidcCredential.GetAccessKeySecret()
	token, err := oidcCredential.GetSecurityToken()
	fmt.Println(accessKeyId, accessKeySecret, token)
}
```

#### RamRoleArn
通过指定[RAM角色][RAM Role]，让凭证自动申请维护 STS Token。你可以通过为 `Policy` 赋值来限制获取到的 STS Token 的权限。
```go
import (
	"fmt"

	"github.com/aliyun/credentials-go/credentials"
)

func main(){
	config := new(credentials.Config).
		// Which type of credential you want
		SetType("ram_role_arn").
		// AccessKeyId of your account
		SetAccessKeyId("AccessKeyId").
		// AccessKeySecret of your account
		SetAccessKeySecret("AccessKeySecret").
		// Format: acs:ram::USER_Id:role/ROLE_NAME
		SetRoleArn("RoleArn").
		// Role Session Name
		SetRoleSessionName("RoleSessionName").
		// Not required, limit the permissions of STS Token
		SetPolicy("Policy").
		// Not required, limit the Valid time of STS Token
		SetRoleSessionExpiration(3600)

	arnCredential, err := credentials.NewCredential(config)
	if err != nil {
		return
	}
	accessKeyId, err := arnCredential.GetAccessKeyId()
	accessSecret, err := arnCredential.GetAccessKeySecret()
	securityToken, err := arnCredential.GetSecurityToken()
	credentialType := arnCredential.GetType()
	fmt.Println(accessKeyId, accessSecret, securityToken, credentialType)
}
```

#### EcsRamRole
通过指定角色名称，让凭证自动申请维护 STS Token
```go
import (
	"fmt"

	"github.com/aliyun/credentials-go/credentials"
)

func main(){
	config := new(credentials.Config).
		// Which type of credential you want
		SetType("ecs_ram_role").
		// `roleName` is optional. It will be retrieved automatically if not set. It is highly recommended to set it up to reduce requests
		SetRoleName("RoleName")

	ecsCredential, err := credentials.NewCredential(config)
	if err != nil {
		return
	}
	accessKeyId, err := ecsCredential.GetAccessKeyId()
	accessSecret, err := ecsCredential.GetAccessKeySecret()
	securityToken, err := ecsCredential.GetSecurityToken()
	credentialType := ecsCredential.GetType()
	fmt.Println(accessKeyId, accessSecret, securityToken, credentialType)
}
```

#### RsaKeyPair
通过指定公钥Id和私钥文件，让凭证自动申请维护 AccessKey。仅支持日本站。
```go
import (
	"fmt"

	"github.com/aliyun/credentials-go/credentials"
)

func main(){
	config := new(credentials.Config).
		// Which type of credential you want
		SetType("rsa_key_pair").
		// The file path to store the PrivateKey
		SetPrivateKeyFile("PrivateKeyFile").
		// PublicKeyId of your account
		SetPublicKeyId("PublicKeyId")

	rsaCredential, err := credentials.NewCredential(config)
	if err != nil {
		return
	}
	accessKeyId, err := rsaCredential.GetAccessKeyId()
	accessSecret, err := rsaCredential.GetAccessKeySecret()
	securityToken, err := rsaCredential.GetSecurityToken()
	credentialType := rsaCredential.GetType()
	fmt.Println(accessKeyId, accessSecret, securityToken, credentialType)
}
```

#### Bearer Token
如呼叫中心(CCC)需用此凭证，请自行申请维护 Bearer Token。
```go
import (
	"fmt"

	"github.com/aliyun/credentials-go/credentials"
)

func main(){
	config := new(credentials.Config).
		// Which type of credential you want
		SetType("bearer").
		// BearerToken of your account
		SetBearerToken("BearerToken").
	config := &credentials.Config{

	bearerCredential, err := credentials.NewCredential(config)
	if err != nil {
		return
	}
	bearerToken := bearerCredential.GetBearerToken()
	credentialType := bearerCredential.GetType()
	fmt.Println(bearerToken, credentialType)
}
```

### 凭证提供程序链
如果你调用 `NewCredential()` 时传入空， 将通过凭证提供链来为你获取凭证。

#### 1. 环境凭证
程序首先会在环境变量里寻找环境凭证，如果定义了 `ALIBABA_CLOUD_ACCESS_KEY_ID`  和 `ALIBABA_CLOUD_ACCESS_KEY_SECRET` 环境变量且不为空，程序将使用他们创建凭证。如否则，程序会在配置文件中加载和寻找凭证。

#### 2. 配置文件
如果用户主目录存在默认文件 `~/.alibabacloud/credentials` （Windows 为 `C:\Users\USER_NAME\.alibabacloud\credentials`），程序会自动创建指定类型和名称的凭证。默认文件可以不存在，但解析错误会抛出异常。也可以手动加载指定文件： `AlibabaCloud::load('/data/credentials', 'vfs://AlibabaCloud/credentials', ...);` 不同的项目、工具之间可以共用这个配置文件，因为超出项目之外，也不会被意外提交到版本控制。Windows 上可以使用环境变量引用到主目录 %UserProfile%。类 Unix 的系统可以使用环境变量 $HOME 或 ~ (tilde)。 可以通过定义 `ALIBABA_CLOUD_CREDENTIALS_FILE` 环境变量修改默认文件的路径。

```ini
[default]                          # 默认凭证
type = access_key                  # 认证方式为 access_key
access_key_id = foo                # access key id
access_key_secret = bar            # access key secret
```

#### 3. 实例 RAM 角色
如果定义了环境变量 `ALIBABA_CLOUD_ECS_METADATA` 且不为空，程序会将该环境变量的值作为角色名称，请求 `http://100.100.100.200/latest/meta-data/ram/security-credentials/` 获取临时安全凭证。

## 许可证
[Apache-2.0](/LICENSE)

Copyright (c) 2009-present, Alibaba Cloud All rights reserved.

[ak]: https://usercenter.console.aliyun.com/#/manage/ak
[ram]: https://ram.console.aliyun.com/users
[policy]: https://www.alibabacloud.com/help/doc-detail/28664.htm?spm=a2c63.p38356.a3.3.27a63b01khWgdh
[permissions]: https://ram.console.aliyun.com/permissions
[RAM Role]: https://ram.console.aliyun.com/#/role/list
