# 阿里云凭证 Go SDK 常见问题 FAQ

本文档整理了阿里云凭证 Go SDK (credentials-go) 使用过程中的常见问题和解决方案。

## 目录

- [环境变量相关问题](#环境变量相关问题)
- [凭证类型配置问题](#凭证类型配置问题)
- [ECS RAM角色凭证问题](#ecs-ram角色凭证问题)
- [配置文件问题](#配置文件问题)
- [网络和超时问题](#网络和超时问题)
- [版本兼容性问题](#版本兼容性问题)
- [OIDC凭证问题](#oidc凭证问题)
- [凭证URI问题](#凭证uri问题)

---

## 环境变量相关问题

### Q1: 设置了 ALIBABA_CLOUD_ACCESS_KEY_ID 环境变量但无法获取凭证

**问题描述：** 按照文档设置了 `ALIBABA_CLOUD_ACCESS_KEY_ID` 环境变量，但程序报错无法获取到 ACCESS_KEY_ID。

**原因分析：** 早期版本中环境变量名称使用了不一致的大小写 `ALIBABA_CLOUD_ACCESS_KEY_Id`（注意最后的 `Id` 大小写）。Linux 系统下环境变量大小写敏感，导致无法识别。

**解决方案：**
1. 优先使用标准的全大写环境变量名（推荐）：
   ```bash
   export ALIBABA_CLOUD_ACCESS_KEY_ID="your-access-key-id"
   export ALIBABA_CLOUD_ACCESS_KEY_SECRET="your-access-key-secret"
   ```

2. 当前版本同时兼容两种写法，会优先读取 `ALIBABA_CLOUD_ACCESS_KEY_ID`，如果不存在则会尝试读取 `ALIBABA_CLOUD_ACCESS_KEY_Id`。

**相关 Issue：** [#37](https://github.com/aliyun/credentials-go/issues/37), [#57](https://github.com/aliyun/credentials-go/issues/57)

---

### Q2: 环境变量为空时的错误提示

**问题描述：** 设置了环境变量但值为空字符串，程序报错 `ALIBABA_CLOUD_ACCESS_KEY_ID or ALIBABA_CLOUD_ACCESS_KEY_Id cannot be empty`。

**原因分析：** SDK 会检查环境变量是否为空，空字符串被认为是无效配置。

**解决方案：**
```bash
# 确保环境变量有实际值
export ALIBABA_CLOUD_ACCESS_KEY_ID="your-actual-access-key-id"
export ALIBABA_CLOUD_ACCESS_KEY_SECRET="your-actual-access-key-secret"

# 如果使用 STS Token
export ALIBABA_CLOUD_SECURITY_TOKEN="your-security-token"
```

---

## 凭证类型配置问题

### Q3: 无效的凭证类型错误

**问题描述：** 配置凭证时收到错误 `invalid type option, support: access_key, sts, bearer, ecs_ram_role, ram_role_arn, rsa_key_pair, oidc_role_arn, credentials_uri`。

**原因分析：** 使用了不支持的凭证类型或类型名称拼写错误。

**解决方案：** 确保使用以下支持的凭证类型之一：
- `access_key` - AccessKey 凭证
- `sts` - STS Token 凭证
- `bearer` - Bearer Token 凭证
- `ecs_ram_role` - ECS 实例 RAM 角色
- `ram_role_arn` - RAM 角色 ARN 扮演
- `rsa_key_pair` - RSA 密钥对（已废弃）
- `oidc_role_arn` - OIDC 角色凭证
- `credentials_uri` - 外部凭证 URI

示例：
```go
config := new(credentials.Config).
    SetType("access_key").  // 确保类型正确
    SetAccessKeyId("your-access-key-id").
    SetAccessKeySecret("your-access-key-secret")
```

---

### Q4: Bearer Token 不能为空错误

**问题描述：** 使用 Bearer Token 类型时报错 `BearerToken cannot be empty`。

**原因分析：** Bearer Token 类型必须提供非空的 BearerToken 值。

**解决方案：**
```go
config := new(credentials.Config).
    SetType("bearer").
    SetBearerToken("your-bearer-token")  // 必须提供有效的 token
```

---

## ECS RAM角色凭证问题

### Q5: 刷新 ECS STS Token 失败

**问题描述：** 使用 ECS RAM 角色时报错 `refresh Ecs sts token err`。

**常见原因：**
1. ECS 实例未绑定 RAM 角色
2. 元数据服务不可访问（网络问题）
3. JSON 解析失败（响应格式错误）
4. Code 字段不是 "Success"

**解决方案：**

1. **确认 ECS 实例已绑定 RAM 角色：**
   - 登录阿里云控制台
   - 进入 ECS 实例详情页
   - 查看是否已绑定实例 RAM 角色

2. **测试元数据服务连通性：**
   ```bash
   # 在 ECS 实例内执行
   curl http://100.100.100.200/latest/meta-data/ram/security-credentials/
   ```

3. **显式指定角色名称（推荐）：**
   ```go
   config := new(credentials.Config).
       SetType("ecs_ram_role").
       SetRoleName("your-role-name")  // 指定角色名称减少请求次数
   ```

4. **使用 IMDS v2（安全加固）：**
   ```go
   config := new(credentials.Config).
       SetType("ecs_ram_role").
       SetRoleName("your-role-name").
       SetDisableIMDSv1(true)  // 禁用 IMDS v1
   ```

---

### Q6: 获取元数据 Token 失败

**问题描述：** 启用 IMDSv2 后报错 `failed to get token from ECS Metadata Service`。

**原因分析：** IMDSv2 需要额外的 token 请求，网络或配置问题可能导致获取失败。

**解决方案：**
1. 确认 ECS 实例支持 IMDSv2
2. 检查元数据服务是否可访问
3. 如果不需要 IMDSv2 安全加固，可以不设置 `DisableIMDSv1`

```go
// 标准配置（兼容 IMDSv1 和 IMDSv2）
config := new(credentials.Config).
    SetType("ecs_ram_role").
    SetRoleName("your-role-name")
```

---

## 配置文件问题

### Q7: 配置文件路径无效

**问题描述：** 程序报错 `the default credential file path is invalid` 或 `ALIBABA_CLOUD_CREDENTIALS_FILE cannot be empty`。

**原因分析：** 
1. 默认配置文件路径不存在（`~/.alibabacloud/credentials`）
2. 环境变量 `ALIBABA_CLOUD_CREDENTIALS_FILE` 设置为空字符串
3. HOME 目录获取失败

**解决方案：**

1. **创建默认配置文件：**
   ```bash
   mkdir -p ~/.alibabacloud
   cat > ~/.alibabacloud/credentials <<EOF
   [default]
   type = access_key
   access_key_id = your-access-key-id
   access_key_secret = your-access-key-secret
   EOF
   ```

2. **通过环境变量指定配置文件：**
   ```bash
   export ALIBABA_CLOUD_CREDENTIALS_FILE=/path/to/your/credentials
   ```

3. **使用 ALIBABA_CLOUD_PROFILE 指定配置段：**
   ```bash
   export ALIBABA_CLOUD_PROFILE=project1
   ```

---

### Q8: 无法读取指定的 profile

**问题描述：** 使用默认凭证链时无法读取特定的 profile 配置。

**原因分析：** credentials-go 的 Provider 接口不对外开放，无法像旧版 SDK 一样直接指定 profile。

**解决方案：**
使用环境变量 `ALIBABA_CLOUD_PROFILE` 指定要使用的 profile：

```bash
export ALIBABA_CLOUD_PROFILE=my-profile
```

或在配置文件中设置 `current` 字段（CLI config.json）：
```json
{
  "current": "my-profile",
  "profiles": [
    {
      "name": "my-profile",
      "mode": "AK",
      "access_key_id": "...",
      "access_key_secret": "..."
    }
  ]
}
```

**相关 Issue：** [#27](https://github.com/aliyun/credentials-go/issues/27), [#53](https://github.com/aliyun/credentials-go/issues/53)

---

### Q9: 配置文件字段校验失败

**问题描述：** 读取配置文件时报错，如 `access_key_id cannot be empty`、`role_arn cannot be empty` 等。

**原因分析：** 配置文件中必填字段缺失或为空。

**解决方案：** 根据不同凭证类型确保必填字段完整：

**access_key 类型：**
```ini
[default]
type = access_key
access_key_id = your-access-key-id        # 必填
access_key_secret = your-access-key-secret  # 必填
```

**sts 类型：**
```ini
[default]
type = sts
access_key_id = your-access-key-id        # 必填
access_key_secret = your-access-key-secret  # 必填
security_token = your-security-token      # 必填
```

**ram_role_arn 类型：**
```ini
[default]
type = ram_role_arn
access_key_id = your-access-key-id        # 必填
access_key_secret = your-access-key-secret  # 必填
role_arn = your-role-arn                  # 必填
role_session_name = your-session-name     # 必填
```

**oidc_role_arn 类型：**
```ini
[default]
type = oidc_role_arn
oidc_provider_arn = your-oidc-provider-arn      # 必填
oidc_token_file_path = /path/to/oidc/token     # 必填
role_arn = your-role-arn                        # 必填
role_session_name = your-session-name           # 必填
```

---

## 网络和超时问题

### Q10: 连接超时错误

**问题描述：** 请求凭证服务时出现 `i/o timeout` 或 `context deadline exceeded` 错误。

**原因分析：** 网络连接超时或读取超时设置过短。

**解决方案：**

1. **调整超时配置：**
   ```go
   config := new(credentials.Config).
       SetType("ram_role_arn").
       SetAccessKeyId("your-ak-id").
       SetAccessKeySecret("your-ak-secret").
       SetRoleArn("your-role-arn").
       SetRoleSessionName("session").
       SetTimeout(10000).         // 读取超时，单位毫秒，默认 5000
       SetConnectTimeout(10000)    // 连接超时，单位毫秒，默认 10000
   ```

2. **各凭证类型的默认超时：**
   - `ecs_ram_role`: 连接超时 1000ms，读取超时 1000ms
   - `ram_role_arn`: 连接超时 10000ms，读取超时 5000ms  
   - `oidc_role_arn`: 连接超时 10000ms，读取超时 5000ms

3. **检查网络连通性：**
   ```bash
   # 测试 STS 服务连通性
   curl -I https://sts.aliyuncs.com
   
   # 测试 ECS 元数据服务
   curl http://100.100.100.200/latest/meta-data/
   ```

---

### Q11: 使用代理时的配置问题

**问题描述：** 设置代理后无法正常获取凭证。

**解决方案：**
```go
config := new(credentials.Config).
    SetType("ram_role_arn").
    SetAccessKeyId("your-ak-id").
    SetAccessKeySecret("your-ak-secret").
    SetRoleArn("your-role-arn").
    SetRoleSessionName("session").
    SetProxy("http://proxy-server:port")  // 设置代理
```

确保代理 URL 格式正确，包含协议（http/https）和端口。

---

## 版本兼容性问题

### Q12: Go 1.25 版本编译失败 - syscall.Flock 问题

**问题描述：** 使用 Go 1.25.x 版本时，Windows 平台编译失败，报错 `syscall.Flock` 不可用。

**原因分析：** v1.4.8 版本引入了文件锁机制使用 `syscall.Flock`，但该函数在 Windows 上不可用，Go 1.25 对此进行了更严格的检查。

**解决方案：**

1. **升级到 v1.4.9 或更高版本（推荐）：**
   ```bash
   go get -u github.com/aliyun/credentials-go@latest
   ```
   v1.4.9 版本已使用条件编译实现了跨平台的文件锁。

2. **临时方案 - 降级到 v1.4.7：**
   ```bash
   go get github.com/aliyun/credentials-go@v1.4.7
   ```

**注意：** 如果使用 Solaris 等特殊平台，可能需要等待进一步的修复。

**相关 Issue：** [#138](https://github.com/aliyun/credentials-go/issues/138), [#141](https://github.com/aliyun/credentials-go/issues/141)

---

## OIDC凭证问题

### Q13: OIDC Token 文件读取失败

**问题描述：** 使用 OIDC 凭证时报错，无法读取 token 文件。

**原因分析：** OIDC Token 文件路径不正确或文件不存在。

**解决方案：**

1. **确认 token 文件路径：**
   ```bash
   ls -la /path/to/oidc/token/file
   ```

2. **正确配置 OIDC 凭证：**
   ```go
   config := new(credentials.Config).
       SetType("oidc_role_arn").
       SetOIDCProviderArn("acs:ram::account-id:oidc-provider/provider-name").
       SetOIDCTokenFilePath("/var/run/secrets/oidc-token").  // 确保路径正确
       SetRoleArn("acs:ram::account-id:role/role-name").
       SetRoleSessionName("session-name")
   ```

3. **在容器环境中使用环境变量：**
   ```bash
   export ALIBABA_CLOUD_ROLE_ARN="acs:ram::account-id:role/role-name"
   export ALIBABA_CLOUD_OIDC_PROVIDER_ARN="acs:ram::account-id:oidc-provider/provider-name"
   export ALIBABA_CLOUD_OIDC_TOKEN_FILE="/var/run/secrets/tokens/oidc-token"
   ```

---

### Q14: OIDC 会话过期时间配置

**问题描述：** 需要设置 OIDC 获取的临时凭证有效期。

**解决方案：**
```go
config := new(credentials.Config).
    SetType("oidc_role_arn").
    SetOIDCProviderArn("your-oidc-provider-arn").
    SetOIDCTokenFilePath("/path/to/token").
    SetRoleArn("your-role-arn").
    SetRoleSessionName("session-name").
    SetRoleSessionExpiration(3600).  // 设置过期时间（秒），范围 900-43200
    SetPolicy("{...}")               // 可选：限制权限策略
```

---

## 凭证URI问题

### Q15: 从外部 URI 获取凭证失败

**问题描述：** 使用 `credentials_uri` 类型时报错 `get credentials from ... failed`。

**原因分析：**
1. URI 地址不可访问
2. 返回的 JSON 格式不正确
3. 响应缺少必要字段

**解决方案：**

1. **确认 URI 返回正确格式：**
   ```json
   {
     "Code": "Success",
     "AccessKeyId": "your-access-key-id",
     "AccessKeySecret": "your-access-key-secret",
     "SecurityToken": "your-security-token",
     "Expiration": "2024-10-26T03:46:38Z"
   }
   ```

2. **测试 URI 可访问性：**
   ```bash
   curl http://your-credentials-uri/
   ```

3. **配置 credentials_uri：**
   ```go
   config := new(credentials.Config).
       SetType("credentials_uri").
       SetURLCredential("http://your-server/credentials")
   ```

4. **或使用环境变量：**
   ```bash
   export ALIBABA_CLOUD_CREDENTIALS_URI="http://your-server/credentials"
   ```

---

## RAM 角色扮演问题

### Q16: AssumeRole 会话时长限制错误

**问题描述：** 使用 RAM 角色扮演时报错 `Assume Role session duration should be in the range of 15min - 1Hr`。

**原因分析：** RoleSessionExpiration 参数设置超出允许范围（900-3600秒）。

**解决方案：**
```go
config := new(credentials.Config).
    SetType("ram_role_arn").
    SetAccessKeyId("your-ak-id").
    SetAccessKeySecret("your-ak-secret").
    SetRoleArn("your-role-arn").
    SetRoleSessionName("session-name").
    SetRoleSessionExpiration(3600)  // 必须在 900-3600 秒之间（15分钟-1小时）
```

---

### Q17: 刷新 RoleArn STS Token 失败

**问题描述：** 使用 RAM 角色扮演时报错 `refresh RoleArn sts token err`。

**常见原因：**
1. AccessKey 无效或没有 AssumeRole 权限
2. RoleArn 不存在或格式错误
3. 网络连接失败
4. STS 服务返回错误

**解决方案：**

1. **验证 AccessKey 权限：**
   - 确认 AccessKey 有效
   - 确认有 `sts:AssumeRole` 权限

2. **检查 RoleArn 格式：**
   ```
   正确格式：acs:ram::account-id:role/role-name
   示例：acs:ram::123456789012****:role/adminrole
   ```

3. **使用区域化 STS 端点（推荐）：**
   ```go
   config := new(credentials.Config).
       SetType("ram_role_arn").
       SetAccessKeyId("your-ak-id").
       SetAccessKeySecret("your-ak-secret").
       SetRoleArn("your-role-arn").
       SetRoleSessionName("session-name").
       SetSTSEndpoint("sts.cn-hangzhou.aliyuncs.com")  // 使用就近的区域端点
   ```

4. **设置外部 ID（如需要）：**
   ```go
   config.SetExternalId("external-id")  // 防止混淆代理人问题
   ```

---

## 默认凭证链问题

### Q18: 默认凭证链未找到凭证

**问题描述：** 使用 `NewCredential(nil)` 时报错 `no credential found`。

**原因分析：** 默认凭证链按优先级查找凭证，所有方式都未找到有效凭证。

**默认凭证链优先级顺序：**
1. 环境变量（`ALIBABA_CLOUD_ACCESS_KEY_ID` 等）
2. OIDC RAM 角色（`ALIBABA_CLOUD_ROLE_ARN` 等环境变量）
3. CLI 配置文件（`~/.aliyun/config.json`）
4. 凭证配置文件（`~/.alibabacloud/credentials`）
5. ECS 实例 RAM 角色（`ALIBABA_CLOUD_ECS_METADATA` 环境变量）
6. 凭证 URI（`ALIBABA_CLOUD_CREDENTIALS_URI` 环境变量）

**解决方案：** 至少配置以上一种凭证方式。推荐使用环境变量（开发环境）或 ECS RAM 角色（生产环境）。

---

## RSA 密钥对问题（已废弃）

### Q19: RSA 密钥对凭证类型使用问题

**问题描述：** 使用 `rsa_key_pair` 类型时遇到问题。

**重要说明：** `rsa_key_pair` 凭证类型已被废弃，不建议继续使用。

**推荐替代方案：**
1. 使用 `access_key` 类型
2. 使用 `sts` 类型获取临时凭证
3. 使用 `ram_role_arn` 进行角色扮演

---

## 最佳实践建议

### 开发环境
- 使用环境变量配置凭证，便于切换和测试
- 不要将凭证硬编码在代码中
- 使用 `.env` 文件管理环境变量（不提交到版本控制）

### 生产环境
- ECS/ECI：使用实例 RAM 角色（推荐）
- 容器服务 Kubernetes：使用 OIDC 凭证（RRSA）
- 函数计算：使用函数绑定的 RAM 角色
- 其他场景：使用 RAM 角色扮演，避免直接使用主账号 AccessKey

### 安全建议
1. 定期轮换 AccessKey
2. 使用 RAM 子账号，遵循最小权限原则
3. 启用 ECS IMDSv2（`SetDisableIMDSv1(true)`）
4. 使用 STS 临时凭证替代长期 AccessKey
5. 配置合理的凭证过期时间
6. 使用 Policy 参数进一步限制权限范围

### 性能优化
1. ECS RAM 角色配置时显式指定 `RoleName`，减少元数据服务请求
2. 合理设置超时时间，避免过长等待
3. 使用就近的区域化 STS 端点
4. 凭证会自动刷新，无需手动处理

---

## 获取帮助

如果以上 FAQ 未能解决您的问题，可以通过以下方式获取帮助：

1. **查看文档：**
   - [中文 README](README-CN.md)
   - [英文 README](README.md)

2. **提交 Issue：**
   - GitHub Issues: https://github.com/aliyun/credentials-go/issues

3. **参考示例代码：**
   - 项目中的测试文件包含了各种使用场景的示例

4. **联系支持：**
   - 阿里云技术支持：https://www.aliyun.com/support

---

## 版本更新说明

请关注项目的 [Release 页面](https://github.com/aliyun/credentials-go/releases) 获取最新版本更新和问题修复信息。

当前推荐版本：v1.4.9+（修复了 Go 1.25 兼容性问题）
