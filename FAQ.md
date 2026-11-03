# Alibaba Cloud Credentials for Go - 常见问题解答 (FAQ)

本文档汇总了在使用 Alibaba Cloud Credentials for Go 过程中可能遇到的常见问题及其解决方案。

## 目录

- [1. 通用问题](#1-通用问题)
- [2. 环境变量凭证相关问题](#2-环境变量凭证相关问题)
- [3. AccessKey 凭证相关问题](#3-accesskey-凭证相关问题)
- [4. STS 凭证相关问题](#4-sts-凭证相关问题)
- [5. ECS RAM 角色凭证相关问题](#5-ecs-ram-角色凭证相关问题)
- [6. RAM 角色扮演凭证相关问题](#6-ram-角色扮演凭证相关问题)
- [7. OIDC 凭证相关问题](#7-oidc-凭证相关问题)
- [8. 凭证 URI 相关问题](#8-凭证-uri-相关问题)
- [9. Bearer Token 凭证相关问题](#9-bearer-token-凭证相关问题)
- [10. 配置文件相关问题](#10-配置文件相关问题)
- [11. 默认凭证链相关问题](#11-默认凭证链相关问题)
- [12. 网络和超时问题](#12-网络和超时问题)
- [13. RSA 密钥对凭证相关问题](#13-rsa-密钥对凭证相关问题)
- [14. 常见问题排查流程](#14-常见问题排查流程)
- [15. 安全最佳实践](#15-安全最佳实践)
- [16. 获取更多帮助](#16-获取更多帮助)

---

## 1. 通用问题

### Q1.1: 如何选择合适的凭证类型？

**A:** 根据您的使用场景选择：

- **开发测试环境**：使用 `access_key` 类型，直接配置 AccessKeyId 和 AccessKeySecret
- **生产环境**：推荐使用 `ecs_ram_role`（ECS 实例）或 `ram_role_arn`（角色扮演）以提高安全性
- **Kubernetes 环境**：使用 `oidc_role_arn` 配合 RRSA 功能
- **临时访问**：使用 `sts` 类型的临时凭证
- **云呼叫中心（CCC）**：使用 `bearer` 类型
- **自定义凭证服务**：使用 `credentials_uri` 类型

### Q1.2: 出现 "invalid type option" 错误怎么办？

**错误信息**：
```
invalid type option, support: access_key, sts, bearer, ecs_ram_role, ram_role_arn, rsa_key_pair, oidc_role_arn, credentials_uri
```

**原因**：配置的凭证类型不正确或拼写错误。

**解决方案**：
1. 检查 `Type` 字段的值，确保为以下之一：
   - `access_key`
   - `sts`
   - `bearer`
   - `ecs_ram_role`
   - `ram_role_arn`
   - `rsa_key_pair`
   - `oidc_role_arn`
   - `credentials_uri`

2. 注意类型名称区分大小写，必须使用小写字母和下划线。

### Q1.3: 如何获取凭证信息？

**A:** 使用 `GetCredential()` 方法：

```go
provider, err := credentials.NewCredential(config)
if err != nil {
    // 处理错误
}

credential, err := provider.GetCredential()
if err != nil {
    // 处理错误
}

// 访问凭证信息
accessKeyId := credential.AccessKeyId
accessKeySecret := credential.AccessKeySecret
securityToken := credential.SecurityToken
credentialType := credential.Type
```

**注意**：不推荐使用已废弃的方法 `GetAccessKeyId()`、`GetAccessKeySecret()`、`GetSecurityToken()`。

---

## 2. 环境变量凭证相关问题

### Q2.1: 使用环境变量时出现 "cannot be empty" 错误

**错误信息**：
```
ALIBABA_CLOUD_ACCESS_KEY_ID or ALIBABA_CLOUD_ACCESS_KEY_Id cannot be empty
```
或
```
ALIBABA_CLOUD_ACCESS_KEY_SECRET cannot be empty
```

**原因**：环境变量未设置或值为空。

**解决方案**：
1. 确保设置了必需的环境变量：
   ```bash
   export ALIBABA_CLOUD_ACCESS_KEY_ID="your-access-key-id"
   export ALIBABA_CLOUD_ACCESS_KEY_SECRET="your-access-key-secret"
   ```

2. 可选：如果需要使用 STS Token，设置：
   ```bash
   export ALIBABA_CLOUD_SECURITY_TOKEN="your-security-token"
   ```

3. 验证环境变量已正确设置：
   ```bash
   echo $ALIBABA_CLOUD_ACCESS_KEY_ID
   echo $ALIBABA_CLOUD_ACCESS_KEY_SECRET
   ```

### Q2.2: 环境变量名称大小写问题

**A:** SDK 支持两种 AccessKeyId 环境变量名称：
- `ALIBABA_CLOUD_ACCESS_KEY_ID`（推荐，全大写）
- `ALIBABA_CLOUD_ACCESS_KEY_Id`（兼容旧版本）

推荐使用全大写的 `ALIBABA_CLOUD_ACCESS_KEY_ID`。

### Q2.3: 如何禁用环境变量凭证？

**A:** 环境变量凭证在默认凭证链中优先级最高。如果不想使用环境变量凭证，请：
1. 不设置相关环境变量
2. 或显式指定其他凭证类型，不使用默认凭证链（传入 `nil` 给 `NewCredential`）

---

## 3. AccessKey 凭证相关问题

### Q3.1: AccessKey 凭证配置示例

**A:** 
```go
config := new(credentials.Config).
    SetType("access_key").
    SetAccessKeyId("your-access-key-id").
    SetAccessKeySecret("your-access-key-secret")

provider, err := credentials.NewCredential(config)
```

### Q3.2: AccessKey 和 AccessKeySecret 为空时会发生什么？

**A:** 如果在配置文件中使用 AccessKey 类型时：

**错误信息**：
```
access_key_id cannot be empty
```
或
```
access_key_secret cannot be empty
```

**解决方案**：
1. 确保在配置中提供了有效的 AccessKeyId 和 AccessKeySecret
2. 检查配置文件语法是否正确（如使用 INI 格式）
3. 验证密钥值没有被意外删除或覆盖

### Q3.3: 如何安全地管理 AccessKey？

**A:** 
1. **不要**将 AccessKey 硬编码在代码中
2. **不要**将包含 AccessKey 的配置文件提交到版本控制系统
3. 使用环境变量或配置文件存储（确保文件权限安全）
4. 生产环境推荐使用 RAM 角色而非 AccessKey
5. 定期轮换 AccessKey
6. 为不同的应用使用不同的 RAM 子账号和 AccessKey

---

## 4. STS 凭证相关问题

### Q4.1: STS Token 过期问题

**A:** STS Token 是临时凭证，有过期时间。当出现凭证过期错误时：

**解决方案**：
1. 重新获取新的 STS Token
2. 检查 Token 的有效期
3. 如果使用 `ram_role_arn` 或 `oidc_role_arn`，SDK 会自动刷新 Token

### Q4.2: 使用 STS 凭证的必需参数

**A:** 使用 STS 类型凭证需要以下三个参数：
```go
config := new(credentials.Config).
    SetType("sts").
    SetAccessKeyId("sts-access-key-id").      // 必需
    SetAccessKeySecret("sts-access-secret").  // 必需
    SetSecurityToken("security-token")        // 必需
```

**错误信息**（配置文件场景）：
```
security_token cannot be empty
```

### Q4.3: 环境变量中的 STS Token

**A:** 如果同时设置了以下环境变量，SDK 会自动识别为 STS 凭证：
```bash
export ALIBABA_CLOUD_ACCESS_KEY_ID="sts-access-key-id"
export ALIBABA_CLOUD_ACCESS_KEY_SECRET="sts-access-secret"
export ALIBABA_CLOUD_SECURITY_TOKEN="security-token"
```

---

## 5. ECS RAM 角色凭证相关问题

### Q5.1: 在非 ECS 环境使用 ECS RAM 角色凭证

**错误现象**：无法获取凭证或连接超时。

**原因**：ECS RAM 角色凭证仅能在 ECS、ECI 或容器服务 Kubernetes 的 Worker 节点上使用。

**解决方案**：
1. 确认代码运行在 ECS 实例、ECI 实例或 ACK Worker 节点上
2. 如果在本地开发环境，使用其他凭证类型（如 `access_key` 或配置文件）
3. 使用默认凭证链，在不同环境自动适配

### Q5.2: ECS 元数据服务无法访问

**错误信息**：
```
refresh Ecs sts token err: Get "http://100.100.100.200/latest/meta-data/ram/security-credentials/": context deadline exceeded
```

**可能原因**：
1. 不在 ECS 环境中运行
2. 网络配置问题，无法访问 100.100.100.200
3. ECS 实例未绑定 RAM 角色
4. 防火墙或安全组规则阻止了元数据服务访问

**解决方案**：
1. 确认 ECS 实例已绑定 RAM 角色
2. 在 ECS 实例内测试：
   ```bash
   curl http://100.100.100.200/latest/meta-data/ram/security-credentials/
   ```
3. 检查网络配置和防火墙规则
4. 确保没有禁用元数据服务

### Q5.3: 如何指定 RAM 角色名称？

**A:** 推荐显式指定角色名称以减少网络请求：

```go
config := new(credentials.Config).
    SetType("ecs_ram_role").
    SetRoleName("YourRoleName")
```

或通过环境变量：
```bash
export ALIBABA_CLOUD_ECS_METADATA="YourRoleName"
```

**注意**：如果不指定，SDK 会自动获取，但会增加一次网络请求。

### Q5.4: IMDSv1 和 IMDSv2 的区别

**A:** 
- **IMDSv1**：传统的元数据服务访问方式
- **IMDSv2**：增强的元数据服务，需要先获取 Token，更安全

**推荐使用 IMDSv2**：
```go
config := new(credentials.Config).
    SetType("ecs_ram_role").
    SetDisableIMDSv1(true)  // 禁用 IMDSv1，强制使用 IMDSv2
```

或通过环境变量：
```bash
export ALIBABA_CLOUD_IMDSV1_DISABLED="true"
```

### Q5.5: 如何禁用 ECS 元数据服务？

**A:** 通过环境变量：
```bash
export ALIBABA_CLOUD_ECS_METADATA_DISABLED="true"
```

**错误信息**：
```
IMDS credentials is disabled
```

这在某些安全要求严格的场景下有用。

### Q5.6: ECS RAM 角色凭证刷新失败

**错误信息**：
```
refresh Ecs sts token err: Code is not Success
```

**可能原因**：
1. RAM 角色配置错误
2. 角色权限不足
3. 元数据服务返回异常

**解决方案**：
1. 检查 ECS 实例绑定的 RAM 角色配置
2. 验证角色的权限策略
3. 查看元数据服务返回的完整响应

### Q5.7: 获取元数据 Token 失败

**错误信息**：
```
failed to get token from ECS Metadata Service: ...
```

**原因**：使用 IMDSv2 时无法获取元数据 Token。

**解决方案**：
1. 确认 ECS 实例支持 IMDSv2
2. 检查是否有网络策略阻止访问
3. 如果 IMDSv2 不可用，不要设置 `DisableIMDSv1(true)`

---

## 6. RAM 角色扮演凭证相关问题

### Q6.1: 会话持续时间配置错误

**错误信息**：
```
[InvalidParam]:Assume Role session duration should be in the range of 15min - 1Hr
```

**原因**：`RoleSessionExpiration` 参数超出允许范围（900-3600 秒）。

**解决方案**：
```go
config := new(credentials.Config).
    SetType("ram_role_arn").
    SetRoleSessionExpiration(3600)  // 设置为 900-3600 之间的值（单位：秒）
```

**注意**：
- 最小值：900 秒（15 分钟）
- 最大值：3600 秒（1 小时）
- 默认值：3600 秒

### Q6.2: RAM 角色扮演必需参数

**A:** 使用 RAM 角色扮演需要以下参数：

```go
config := new(credentials.Config).
    SetType("ram_role_arn").
    SetAccessKeyId("your-access-key-id").          // 必需
    SetAccessKeySecret("your-access-key-secret").  // 必需
    SetRoleArn("acs:ram::123456:role/role-name").  // 必需，角色 ARN
    SetRoleSessionName("session-name")             // 必需，会话名称
```

**配置文件错误示例**：
```
missing required role_arn option in profile for ram_role_arn
```
或
```
role_session_name cannot be empty
```

### Q6.3: 角色 ARN 格式

**A:** 正确的角色 ARN 格式：
```
acs:ram::账号ID:role/角色名称
```

例如：
```
acs:ram::123456789012****:role/adminrole
```

**常见错误**：
- 缺少 `acs:ram::` 前缀
- 账号 ID 错误
- 角色名称拼写错误

### Q6.4: 使用 Policy 限制权限

**A:** 可以通过 `Policy` 参数进一步限制 STS Token 的权限：

```go
policy := `{"Statement": [{"Action": ["oss:GetObject"],"Effect": "Allow","Resource": ["acs:oss:*:*:mybucket/*"]}],"Version":"1"}`

config := new(credentials.Config).
    SetType("ram_role_arn").
    // ... 其他必需参数
    SetPolicy(policy)  // 可选
```

### Q6.5: STS 服务访问超时

**错误信息**：
```
refresh RoleArn sts token err: context deadline exceeded
```

**可能原因**：
1. 网络问题
2. 默认 STS 端点不可达
3. 超时时间设置过短

**解决方案**：
1. 使用区域化的 STS 端点：
   ```go
   config.SetSTSEndpoint("sts.cn-hangzhou.aliyuncs.com")
   ```

2. 调整超时时间：
   ```go
   config.SetConnectTimeout(10000)  // 连接超时 10 秒（单位：毫秒）
   config.SetTimeout(5000)          // 读取超时 5 秒（单位：毫秒）
   ```

3. 检查网络连接和防火墙规则

### Q6.6: 刷新凭证时返回空响应

**错误信息**：
```
refresh RoleArn sts token err: Credentials is empty
```

**原因**：STS 服务返回的响应中凭证信息为空。

**解决方案**：
1. 检查 RAM 角色的信任策略
2. 验证 AccessKey 是否有权限扮演该角色
3. 查看 STS 服务返回的完整错误信息
4. 确认角色 ARN 正确

### Q6.7: 使用 ExternalId 防止混淆代理问题

**A:** 在跨账号角色扮演场景中，使用 `ExternalId` 增强安全性：

```go
config := new(credentials.Config).
    SetType("ram_role_arn").
    // ... 其他参数
    SetExternalId("unique-external-id")
```

更多信息参考：[使用ExternalId防止混淆代理问题](https://help.aliyun.com/zh/ram/use-cases/use-externalid-to-prevent-the-confused-deputy-problem)

---

## 7. OIDC 凭证相关问题

### Q7.1: OIDC 必需参数缺失

**错误信息**：
```
the OIDCTokenFilePath is empty
```
或
```
the OIDCProviderARN is empty
```
或
```
the RoleArn is empty
```

**原因**：OIDC 凭证需要三个必需参数。

**解决方案**：
```go
config := new(credentials.Config).
    SetType("oidc_role_arn").
    SetOIDCProviderArn("acs:ram::123456:oidc-provider/provider-name").  // 必需
    SetOIDCTokenFilePath("/var/run/secrets/tokens/oidc-token").         // 必需
    SetRoleArn("acs:ram::123456:role/role-name").                       // 必需
    SetRoleSessionName("session-name")                                  // 推荐设置
```

或使用环境变量：
```bash
export ALIBABA_CLOUD_OIDC_PROVIDER_ARN="acs:ram::123456:oidc-provider/provider-name"
export ALIBABA_CLOUD_OIDC_TOKEN_FILE="/var/run/secrets/tokens/oidc-token"
export ALIBABA_CLOUD_ROLE_ARN="acs:ram::123456:role/role-name"
```

### Q7.2: OIDC Token 文件不存在或无法读取

**错误现象**：读取 OIDC Token 文件失败。

**解决方案**：
1. 确认文件路径正确
2. 检查文件是否存在：
   ```bash
   ls -la /var/run/secrets/tokens/oidc-token
   ```
3. 验证文件权限，确保应用有读取权限
4. 在 Kubernetes 环境，确认 ServiceAccount 已正确配置

### Q7.3: OIDC 会话持续时间限制

**错误信息**：
```
the Assume Role session duration should be in the range of 15min - max duration seconds
```

**原因**：`DurationSeconds` 设置小于 900 秒。

**解决方案**：
```go
config.SetRoleSessionExpiration(3600)  // 最小值 900（15分钟），推荐 3600（1小时）
```

### Q7.4: 在 Kubernetes 中使用 OIDC（RRSA）

**A:** 容器服务 Kubernetes（ACK）支持 RRSA 功能：

1. 配置 ServiceAccount 的 OIDC Token
2. ACK 会自动注入环境变量和挂载 Token 文件
3. 使用默认凭证链，SDK 会自动识别

参考：[使用RRSA配置ServiceAccount的RAM权限实现Pod权限隔离](https://help.aliyun.com/zh/ack/ack-managed-and-ack-dedicated/user-guide/use-rrsa-to-authorize-pods-to-access-different-cloud-services)

### Q7.5: STS 端点选择

**A:** 推荐使用区域化的 STS 端点以获得更好的网络性能：

```go
config.SetSTSEndpoint("sts.cn-hangzhou.aliyuncs.com")
```

可用的区域端点参考：https://api.aliyun.com/product/Sts

---

## 8. 凭证 URI 相关问题

### Q8.1: URL 参数为空

**错误信息**：
```
the url is empty
```

**原因**：未设置凭证服务的 URL。

**解决方案**：
```go
config := new(credentials.Config).
    SetType("credentials_uri").
    SetURL("http://your-credentials-service.com/credentials")
```

或使用环境变量：
```bash
export ALIBABA_CLOUD_CREDENTIALS_URI="http://your-credentials-service.com/credentials"
```

### Q8.2: 凭证服务返回非 200 状态码

**错误信息**：
```
get credentials from http://... failed: <response body>
```

**可能原因**：
1. 凭证服务不可用
2. 认证失败
3. 服务内部错误

**解决方案**：
1. 检查凭证服务是否正常运行
2. 验证服务的认证配置
3. 查看服务日志
4. 使用 curl 测试服务：
   ```bash
   curl -v http://your-credentials-service.com/credentials
   ```

### Q8.3: 凭证服务响应格式错误

**错误信息**：
```
get credentials from http://... failed with error, json unmarshal fail: ...
```

**原因**：服务返回的 JSON 格式不正确。

**正确的响应格式**：
```json
{
  "Code": "Success",
  "AccessKeyId": "your-access-key-id",
  "AccessKeySecret": "your-access-key-secret",
  "SecurityToken": "your-security-token",
  "Expiration": "2024-10-26T03:46:38Z"
}
```

**注意**：
- 所有字段都是必需的
- `Expiration` 必须使用 ISO 8601 格式（`2006-01-02T15:04:05Z`）

### Q8.4: 凭证字段缺失

**错误信息**：
```
refresh credentials from http://... failed: <response>
```

**原因**：响应中缺少必需字段（AccessKeyId、AccessKeySecret、SecurityToken、Expiration）。

**解决方案**：
1. 确保凭证服务返回所有必需字段
2. 检查字段名称的大小写（必须完全匹配）
3. 验证字段值不为空字符串或 null

### Q8.5: 网络超时问题

**解决方案**：
```go
config := new(credentials.Config).
    SetType("credentials_uri").
    SetURL("http://your-service.com").
    SetConnectTimeout(10000).  // 连接超时 10 秒
    SetTimeout(5000)           // 读取超时 5 秒
```

---

## 9. Bearer Token 凭证相关问题

### Q9.1: Bearer Token 为空

**错误信息**：
```
BearerToken cannot be empty
```

**解决方案**：
```go
config := new(credentials.Config).
    SetType("bearer").
    SetBearerToken("your-bearer-token")
```

### Q9.2: Bearer Token 适用场景

**A:** Bearer Token 类型主要用于云呼叫中心（CCC）产品。一般业务场景不需要使用此类型。

### Q9.3: Bearer Token 与其他凭证类型的区别

**A:** Bearer Token 凭证：
- 只包含 `BearerToken` 字段
- 没有 AccessKeyId、AccessKeySecret、SecurityToken
- 不需要签名，直接在请求头中使用
- 主要用于特定的 API 认证场景

---

## 10. 配置文件相关问题

### Q10.1: 配置文件路径

**A:** SDK 支持两种配置文件：

1. **Alibaba Cloud CLI 配置文件**：
   - Linux/macOS: `~/.aliyun/config.json`
   - Windows: `C:\Users\<用户名>\.aliyun\config.json`
   - 环境变量：`ALIBABA_CLOUD_CONFIG_FILE`

2. **Credentials 配置文件**：
   - Linux/macOS: `~/.alibabacloud/credentials`
   - Windows: `C:\Users\<用户名>\.alibabacloud\credentials`
   - 环境变量：`ALIBABA_CLOUD_CREDENTIALS_FILE`

### Q10.2: 配置文件不存在

**错误信息**：
```
ERROR: Can not open file ...
```

**解决方案**：
1. 确认配置文件存在
2. 检查文件路径是否正确
3. 验证文件权限
4. 如果使用环境变量指定路径，确保变量设置正确

### Q10.3: 配置文件格式错误（INI 格式）

**配置文件示例** (`~/.alibabacloud/credentials`)：
```ini
[default]
type = access_key
access_key_id = your-access-key-id
access_key_secret = your-access-key-secret

[project1]
type = ecs_ram_role
role_name = EcsRamRoleTest

[project2]
type = ram_role_arn
access_key_id = your-access-key-id
access_key_secret = your-access-key-secret
role_arn = acs:ram::123456:role/role-name
role_session_name = session-name
```

**常见错误**：
- 缺少 section 名称（如 `[default]`）
- 键值对格式错误（应使用 `key = value`）
- 缺少必需的配置项

### Q10.4: 配置文件格式错误（JSON 格式）

**配置文件示例** (`~/.aliyun/config.json`)：
```json
{
  "current": "default",
  "profiles": [
    {
      "name": "default",
      "mode": "AK",
      "access_key_id": "your-access-key-id",
      "access_key_secret": "your-access-key-secret"
    }
  ]
}
```

**错误信息**：
```
unmarshal aliyun cli config from '...' failed: ...
```

**解决方案**：
1. 验证 JSON 格式正确性（使用 JSON 验证工具）
2. 确保所有字符串使用双引号
3. 检查是否有多余的逗号
4. 验证 `profiles` 数组不为空

### Q10.5: 无法加载指定的 profile

**错误信息**：
```
ERROR: Can not load section ...
```

**原因**：配置文件中不存在指定的 profile。

**解决方案**：
1. 检查 profile 名称是否正确
2. 验证配置文件中是否存在该 section
3. 使用 `ALIBABA_CLOUD_PROFILE` 环境变量指定 profile：
   ```bash
   export ALIBABA_CLOUD_PROFILE="project1"
   ```

### Q10.6: 配置文件中 type 字段缺失

**错误信息**：
```
missing required type option ...
```

**解决方案**：
确保每个 profile section 都有 `type` 字段：
```ini
[default]
type = access_key  # 必需
access_key_id = xxx
access_key_secret = xxx
```

### Q10.7: 配置文件中必需字段为空

**常见错误信息**：
```
access_key_id cannot be empty
access_key_secret cannot be empty
role_arn cannot be empty
role_session_name cannot be empty
bearer_token cannot be empty
public_key_id cannot be empty
private_key_file cannot be empty
```

**解决方案**：
根据错误提示，在配置文件中填写相应的必需字段。

### Q10.8: 整数字段类型错误

**错误信息**：
```
session_expiration must be an int
```
或
```
role_session_expiration must be an int
```

**解决方案**：
确保这些字段的值是整数，不要使用引号：
```ini
[default]
type = ram_role_arn
role_session_expiration = 3600  # 正确：整数
# role_session_expiration = "3600"  # 错误：字符串
```

### Q10.9: 超时和代理配置

**A:** 在配置文件中设置超时和代理：
```ini
[default]
type = ram_role_arn
# ... 其他配置
timeout = 5000           # 读取超时（毫秒）
connect_timeout = 10000  # 连接超时（毫秒）
proxy = http://proxy.example.com:8080  # 代理服务器
```

### Q10.10: 禁用 CLI Profile

**A:** 如果不想使用 Aliyun CLI 配置文件：
```bash
export ALIBABA_CLOUD_CLI_PROFILE_DISABLED="true"
```

---

## 11. 默认凭证链相关问题

### Q11.1: 默认凭证链的查找顺序

**A:** 当使用 `credentials.NewCredential(nil)` 时，SDK 按以下顺序查找凭证：

1. **环境变量**：
   - `ALIBABA_CLOUD_ACCESS_KEY_ID` + `ALIBABA_CLOUD_ACCESS_KEY_SECRET`
   - 可选：`ALIBABA_CLOUD_SECURITY_TOKEN`（STS）

2. **OIDC RAM 角色**：
   - `ALIBABA_CLOUD_ROLE_ARN`
   - `ALIBABA_CLOUD_OIDC_PROVIDER_ARN`
   - `ALIBABA_CLOUD_OIDC_TOKEN_FILE`

3. **Aliyun CLI 配置文件**：
   - `~/.aliyun/config.json`

4. **Credentials 配置文件**：
   - `~/.alibabacloud/credentials`

5. **ECS 实例 RAM 角色**：
   - 环境变量 `ALIBABA_CLOUD_ECS_METADATA`
   - 或自动从元数据服务获取

6. **外部凭证 URI**：
   - 环境变量 `ALIBABA_CLOUD_CREDENTIALS_URI`

### Q11.2: 无法从凭证链获取凭证

**错误信息**：
```
unable to get credentials from any of the providers in the chain: ...
```

**原因**：所有凭证提供方式都失败了。

**解决方案**：
1. 查看错误信息中列出的所有失败原因
2. 至少配置一种凭证方式
3. 推荐：在开发环境使用配置文件，在生产环境使用 ECS RAM 角色或环境变量

### Q11.3: 如何调试默认凭证链

**A:** 
1. 启用调试日志（如果 SDK 支持）
2. 逐个检查各个凭证来源：
   ```bash
   # 检查环境变量
   env | grep ALIBABA_CLOUD
   
   # 检查配置文件
   ls -la ~/.aliyun/config.json
   ls -la ~/.alibabacloud/credentials
   
   # 如果在 ECS 上，测试元数据服务
   curl http://100.100.100.200/latest/meta-data/ram/security-credentials/
   ```

### Q11.4: 强制使用特定凭证类型

**A:** 不使用默认凭证链，显式指定凭证类型：
```go
config := new(credentials.Config).
    SetType("access_key").
    SetAccessKeyId("xxx").
    SetAccessKeySecret("xxx")

provider, err := credentials.NewCredential(config)
```

---

## 12. 网络和超时问题

### Q12.1: 连接超时

**错误信息**：
```
context deadline exceeded
```
或
```
dial tcp: i/o timeout
```

**可能原因**：
1. 网络不通
2. 防火墙阻止
3. 超时时间设置过短
4. 服务端响应慢

**解决方案**：
1. 增加超时时间：
   ```go
   config := new(credentials.Config).
       SetConnectTimeout(30000).  // 连接超时 30 秒
       SetTimeout(10000)          // 读取超时 10 秒
   ```

2. 检查网络连接：
   ```bash
   ping sts.aliyuncs.com
   curl -v https://sts.aliyuncs.com
   ```

3. 检查防火墙和安全组规则

### Q12.2: 使用代理服务器

**A:** 
```go
config := new(credentials.Config).
    SetProxy("http://proxy.example.com:8080")
```

或使用环境变量：
```bash
export HTTP_PROXY="http://proxy.example.com:8080"
export HTTPS_PROXY="http://proxy.example.com:8080"
```

**注意**：SDK 配置的代理优先级高于环境变量。

### Q12.3: SSL/TLS 证书验证问题

**错误信息**：
```
x509: certificate signed by unknown authority
```

**可能原因**：
1. 系统证书库不完整
2. 使用了企业自签名证书
3. 中间人代理

**解决方案**：
1. 更新系统证书库
2. 如果使用企业代理，导入代理的根证书
3. 确保系统时间正确

### Q12.4: DNS 解析失败

**错误信息**：
```
no such host
```

**解决方案**：
1. 检查 DNS 配置
2. 验证域名解析：
   ```bash
   nslookup sts.aliyuncs.com
   ```
3. 尝试使用 IP 地址（不推荐用于生产环境）

### Q12.5: 默认超时时间

**A:** 不同凭证类型的默认超时时间：

- **ECS RAM 角色**：
  - 连接超时：1000 毫秒（1 秒）
  - 读取超时：1000 毫秒（1 秒）

- **RAM 角色扮演**：
  - 连接超时：10000 毫秒（10 秒）
  - 读取超时：5000 毫秒（5 秒）

- **OIDC**：
  - 连接超时：10000 毫秒（10 秒）
  - 读取超时：5000 毫秒（5 秒）

- **凭证 URI**：
  - 连接超时：5000 毫秒（5 秒）
  - 读取超时：10000 毫秒（10 秒）

---

## 13. RSA 密钥对凭证相关问题

### Q13.1: RSA 密钥对已废弃

**注意**：RSA 密钥对认证方式已被标记为废弃（Deprecated），不推荐在新项目中使用。

### Q13.2: 私钥文件路径错误

**错误信息**：
```
InvalidPath: Can not open PrivateKeyFile, err is ...
```

**解决方案**：
1. 确认私钥文件路径正确
2. 检查文件是否存在
3. 验证文件权限
4. 使用绝对路径

### Q13.3: 必需参数缺失

**错误信息**：
```
PrivateKeyFile cannot be empty
```
或
```
PublicKeyId cannot be empty
```

**解决方案**：
```go
config := new(credentials.Config).
    SetType("rsa_key_pair").
    SetPublicKeyId("your-public-key-id").
    SetPrivateKeyFile("/path/to/private-key.pem").
    SetSessionExpiration(3600)  // 可选
```

### Q13.4: 私钥文件格式

**A:** 私钥文件应该是标准的 PEM 格式，SDK 会自动：
1. 跳过以 `----` 开头的行（如 `-----BEGIN RSA PRIVATE KEY-----`）
2. 读取密钥内容

确保私钥文件格式正确，没有额外的空格或特殊字符。

---

## 14. 常见问题排查流程

### Q14.1: 系统化排查凭证问题

**步骤 1：确认凭证类型**
- 确定应该使用哪种凭证类型
- 验证配置的 `type` 字段正确

**步骤 2：检查必需参数**
- 根据凭证类型，检查所有必需参数是否提供
- 验证参数值不为空

**步骤 3：验证环境变量**
```bash
env | grep ALIBABA_CLOUD
```

**步骤 4：检查配置文件**
```bash
cat ~/.alibabacloud/credentials
cat ~/.aliyun/config.json
```

**步骤 5：网络连通性**
```bash
# ECS 元数据服务
curl -v http://100.100.100.200/latest/meta-data/

# STS 服务
curl -v https://sts.aliyuncs.com

# 自定义凭证服务
curl -v http://your-credentials-service/
```

**步骤 6：查看详细错误信息**
- 仔细阅读错误消息
- 根据错误类型查找本 FAQ 对应章节

### Q14.2: 开启调试日志

**A:** SDK 使用 `github.com/alibabacloud-go/debug` 包进行调试输出。设置环境变量：

```bash
export DEBUG="credential"
```

这将输出详细的 HTTP 请求和响应信息，帮助定位问题。

---

## 15. 安全最佳实践

### Q15.1: 凭证安全建议

1. **不要硬编码凭证**
   - 使用环境变量或配置文件
   - 配置文件不要提交到版本控制系统

2. **使用最小权限原则**
   - 创建具有特定权限的 RAM 子账号
   - 使用 RAM 角色而非主账号 AccessKey
   - 使用 Policy 限制 STS Token 权限

3. **定期轮换凭证**
   - 定期更新 AccessKey
   - 设置合理的 STS Token 过期时间

4. **使用临时凭证**
   - 生产环境推荐使用 ECS RAM 角色
   - Kubernetes 环境使用 RRSA
   - 避免长期有效的 AccessKey

5. **保护配置文件**
   ```bash
   chmod 600 ~/.alibabacloud/credentials
   ```

6. **使用 IMDSv2**
   ```go
   config.SetDisableIMDSv1(true)
   ```

7. **监控和审计**
   - 使用阿里云的 ActionTrail 审计 API 调用
   - 监控异常的凭证使用

### Q15.2: 不同环境的凭证方案

**开发环境**：
- 使用配置文件或环境变量
- 使用 RAM 子账号，限制权限

**测试环境**：
- 使用 ECS RAM 角色（如果在 ECS 上）
- 或配置文件（限制权限的子账号）

**生产环境**：
- **ECS 实例**：使用 ECS RAM 角色
- **Kubernetes**：使用 RRSA (OIDC)
- **其他环境**：使用 RAM 角色扮演或凭证 URI

---

## 16. 获取更多帮助

### Q16.1: 相关文档链接

- [官方文档](https://github.com/aliyun/credentials-go/blob/master/README-CN.md)
- [RAM 角色管理](https://ram.console.aliyun.com/#/role/list)
- [AccessKey 管理](https://usercenter.console.aliyun.com/#/manage/ak)
- [RAM 权限策略](https://help.aliyun.com/zh/ram/user-guide/permission-policy-overview)
- [STS API 文档](https://api.aliyun.com/product/Sts)

### Q16.2: 问题反馈

如果本 FAQ 未能解决您的问题，请：

1. 查看 [GitHub Issues](https://github.com/aliyun/credentials-go/issues)
2. 提交新的 Issue，包含：
   - 完整的错误信息
   - SDK 版本
   - Go 版本
   - 凭证类型和配置（脱敏后）
   - 复现步骤

### Q16.3: 社区支持

- [阿里云开发者社区](https://developer.aliyun.com/)
- [Stack Overflow - 标签: alibaba-cloud](https://stackoverflow.com/questions/tagged/alibaba-cloud)

---

## 附录：快速参考

### A1. 凭证类型对照表

| 凭证类型 | Type 值 | 主要使用场景 |
|---------|---------|------------|
| AccessKey | `access_key` | 开发测试、简单场景 |
| STS Token | `sts` | 临时访问 |
| ECS RAM 角色 | `ecs_ram_role` | ECS 实例、容器服务 |
| RAM 角色扮演 | `ram_role_arn` | 跨账号访问、权限控制 |
| OIDC | `oidc_role_arn` | Kubernetes (RRSA) |
| 凭证 URI | `credentials_uri` | 自定义凭证服务 |
| Bearer Token | `bearer` | 云呼叫中心 (CCC) |
| RSA 密钥对 | `rsa_key_pair` | 已废弃，不推荐 |

### A2. 环境变量速查

| 环境变量 | 说明 |
|---------|------|
| `ALIBABA_CLOUD_ACCESS_KEY_ID` | AccessKey ID |
| `ALIBABA_CLOUD_ACCESS_KEY_SECRET` | AccessKey Secret |
| `ALIBABA_CLOUD_SECURITY_TOKEN` | Security Token (STS) |
| `ALIBABA_CLOUD_ROLE_ARN` | RAM 角色 ARN |
| `ALIBABA_CLOUD_OIDC_PROVIDER_ARN` | OIDC 提供商 ARN |
| `ALIBABA_CLOUD_OIDC_TOKEN_FILE` | OIDC Token 文件路径 |
| `ALIBABA_CLOUD_ROLE_SESSION_NAME` | 角色会话名称 |
| `ALIBABA_CLOUD_ECS_METADATA` | ECS RAM 角色名称 |
| `ALIBABA_CLOUD_CREDENTIALS_URI` | 凭证服务 URI |
| `ALIBABA_CLOUD_CREDENTIALS_FILE` | Credentials 配置文件路径 |
| `ALIBABA_CLOUD_CONFIG_FILE` | CLI 配置文件路径 |
| `ALIBABA_CLOUD_PROFILE` | 使用的 Profile 名称 |
| `ALIBABA_CLOUD_IMDSV1_DISABLED` | 禁用 IMDSv1 |
| `ALIBABA_CLOUD_ECS_METADATA_DISABLED` | 禁用 ECS 元数据服务 |
| `ALIBABA_CLOUD_CLI_PROFILE_DISABLED` | 禁用 CLI Profile |

### A3. 常用配置示例

**配置文件示例 (INI 格式)**：
```ini
[default]
type = access_key
access_key_id = <YOUR_ACCESS_KEY_ID>
access_key_secret = <YOUR_ACCESS_KEY_SECRET>

[production]
type = ecs_ram_role
role_name = MyEcsRole

[staging]
type = ram_role_arn
access_key_id = <YOUR_ACCESS_KEY_ID>
access_key_secret = <YOUR_ACCESS_KEY_SECRET>
role_arn = acs:ram::123456789:role/MyRole
role_session_name = SessionName
```

**代码配置示例**：
```go
// AccessKey
config := &credentials.Config{
    Type:            tea.String("access_key"),
    AccessKeyId:     tea.String("your-key-id"),
    AccessKeySecret: tea.String("your-key-secret"),
}

// ECS RAM Role
config := &credentials.Config{
    Type:          tea.String("ecs_ram_role"),
    RoleName:      tea.String("MyRole"),
    DisableIMDSv1: tea.Bool(true),
}

// RAM Role ARN
config := &credentials.Config{
    Type:                  tea.String("ram_role_arn"),
    AccessKeyId:           tea.String("your-key-id"),
    AccessKeySecret:       tea.String("your-key-secret"),
    RoleArn:               tea.String("acs:ram::123456789:role/MyRole"),
    RoleSessionName:       tea.String("MySession"),
    RoleSessionExpiration: tea.Int(3600),
}
```

---

**版本**：v1.0  
**更新时间**：2025年12月  
**维护者**：Alibaba Cloud SDK Team

如有任何问题或建议，欢迎提交 [GitHub Issue](https://github.com/aliyun/credentials-go/issues)。
