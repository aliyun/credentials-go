# FAQ 文档说明

本次为 Alibaba Cloud Credentials for Go 项目创建了一份详尽的常见问题解答文档（FAQ.md），主要用于帮助用户快速定位和解决在使用该 SDK 时遇到的问题。

## 文档特点

### 1. 全面覆盖所有凭证类型
文档详细说明了 8 种凭证类型的使用方法和常见问题：
- AccessKey 凭证
- STS 临时凭证
- ECS RAM 角色凭证（包括 IMDSv1/v2）
- RAM 角色扮演凭证
- OIDC 凭证（用于 Kubernetes RRSA）
- 凭证 URI（自定义凭证服务）
- Bearer Token 凭证
- RSA 密钥对凭证（已废弃）

### 2. 基于代码的错误分析
所有错误场景都来源于对源代码的深入分析：
- 检查了所有凭证提供者的实现
- 分析了错误处理逻辑
- 识别了所有可能的异常进入条件
- 记录了所有错误消息和触发场景

### 3. 结构化的问题分类
文档分为 16 个主要章节，共包含 70+ 个具体问题：
1. 通用问题（3 个问题）
2. 环境变量凭证（3 个问题）
3. AccessKey 凭证（3 个问题）
4. STS 凭证（3 个问题）
5. ECS RAM 角色凭证（7 个问题）
6. RAM 角色扮演凭证（7 个问题）
7. OIDC 凭证（5 个问题）
8. 凭证 URI（5 个问题）
9. Bearer Token 凭证（3 个问题）
10. 配置文件（10 个问题）
11. 默认凭证链（4 个问题）
12. 网络和超时（5 个问题）
13. RSA 密钥对凭证（4 个问题）
14. 常见问题排查流程（2 个问题）
15. 安全最佳实践（2 个问题）
16. 获取更多帮助（3 个问题）

### 4. 实用的附录参考
- 凭证类型对照表
- 环境变量速查表
- 常用配置示例（INI 和代码格式）

## 文档内容要点

### 错误诊断
每个问题都包含：
- **错误信息**：准确的错误提示文本
- **原因分析**：导致错误的根本原因
- **解决方案**：具体的修复步骤和代码示例

### 代码示例
提供了大量实际可用的代码示例：
- 配置文件格式（INI 和 JSON）
- Go 代码配置示例
- 环境变量设置示例
- 网络调试命令

### 安全指导
专门的安全最佳实践章节：
- 凭证管理建议
- 不同环境的凭证方案
- IMDSv2 的使用推荐
- 权限最小化原则

## 代码分析范围

为了创建这份文档，分析了以下关键代码文件：

### 核心凭证提供者
- `credentials/credential.go` - 主入口和凭证类型处理
- `credentials/provider_chain.go` - 默认凭证链逻辑
- `credentials/env_provider.go` - 环境变量提供者
- `credentials/profile_provider.go` - 配置文件提供者
- `credentials/instance_provider.go` - ECS 实例提供者
- `credentials/oidc_credential_provider.go` - OIDC 提供者

### 新版提供者实现
- `credentials/providers/default.go` - 默认凭证链实现
- `credentials/providers/env.go` - 环境变量凭证
- `credentials/providers/static_ak.go` - 静态 AccessKey
- `credentials/providers/static_sts.go` - 静态 STS
- `credentials/providers/ecs_ram_role.go` - ECS RAM 角色
- `credentials/providers/ram_role_arn.go` - RAM 角色扮演
- `credentials/providers/oidc.go` - OIDC 凭证
- `credentials/providers/uri.go` - 凭证 URI
- `credentials/providers/profile.go` - 配置文件
- `credentials/providers/cli_profile.go` - CLI 配置文件

### 错误场景分析
分析了以下错误处理场景：
- 参数验证错误（空值、格式错误）
- 网络相关错误（超时、连接失败）
- 认证错误（权限不足、角色配置错误）
- 配置文件错误（格式错误、缺失字段）
- 环境变量错误（未设置、值为空）
- 元数据服务错误（IMDS 访问失败）

## 使用建议

1. **开发者**：在遇到错误时，先查找错误信息对应的章节
2. **运维人员**：参考"常见问题排查流程"进行系统化排查
3. **安全团队**：重点关注"安全最佳实践"章节
4. **新用户**：从"通用问题"开始，了解基本概念和使用方法

## 维护更新

文档将随 SDK 的更新而持续维护：
- 新增凭证类型时添加相应章节
- 发现新的常见问题时及时补充
- 根据用户反馈优化内容

---

**创建日期**：2025年12月7日  
**文档版本**：v1.0  
**代码行数**：1298 行
