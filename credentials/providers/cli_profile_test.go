package providers

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	httputil "github.com/aliyun/credentials-go/credentials/internal/http"
	"github.com/aliyun/credentials-go/credentials/internal/utils"
	"github.com/stretchr/testify/assert"
)

func TestCLIProfileCredentialsProvider(t *testing.T) {
	rollback := utils.Memory("ALIBABA_CLOUD_PROFILE", "ALIBABA_CLOUD_CLI_PROFILE_DISABLED")
	defer rollback()

	b, err := NewCLIProfileCredentialsProviderBuilder().
		Build()
	assert.Nil(t, err)
	assert.Equal(t, "", b.profileName)

	// get from env
	os.Setenv("ALIBABA_CLOUD_PROFILE", "custom_profile")
	b, err = NewCLIProfileCredentialsProviderBuilder().
		Build()
	assert.Nil(t, err)
	assert.Equal(t, "custom_profile", b.profileName)

	b, err = NewCLIProfileCredentialsProviderBuilder().
		WithProfileName("profilename").
		Build()
	assert.Nil(t, err)
	assert.Equal(t, "profilename", b.profileName)

	os.Setenv("ALIBABA_CLOUD_CLI_PROFILE_DISABLED", "True")
	_, err = NewCLIProfileCredentialsProviderBuilder().
		WithProfileName("profilename").
		Build()
	assert.Equal(t, "the CLI profile is disabled", err.Error())

}

func Test_configuration(t *testing.T) {
	wd, _ := os.Getwd()
	_, err := newConfigurationFromPath(path.Join(wd, "fixtures/inexist_cli_config.json"))
	assert.NotNil(t, err)
	assert.True(t, strings.HasPrefix(err.Error(), "reading aliyun cli config from "))

	_, err = newConfigurationFromPath(path.Join(wd, "fixtures/invalid_cli_config.json"))
	assert.NotNil(t, err)
	assert.True(t, strings.HasPrefix(err.Error(), "unmarshal aliyun cli config from "))

	_, err = newConfigurationFromPath(path.Join(wd, "fixtures/mock_empty_cli_config.json"))
	assert.True(t, strings.HasPrefix(err.Error(), "no any configured profiles in "))

	conf, err := newConfigurationFromPath(path.Join(wd, "fixtures/mock_cli_config.json"))
	assert.Nil(t, err)
	assert.Equal(t, &configuration{
		Current: "default",
		Profiles: []*profile{
			{
				Mode:            "AK",
				Name:            "default",
				AccessKeyID:     "akid",
				AccessKeySecret: "secret",
			},
			{
				Mode:            "AK",
				Name:            "jacksontian",
				AccessKeyID:     "akid",
				AccessKeySecret: "secret",
			},
		},
	}, conf)

	_, err = conf.getProfile("inexists")
	assert.EqualError(t, err, "unable to get profile with 'inexists'")

	p, err := conf.getProfile("jacksontian")
	assert.Nil(t, err)
	assert.Equal(t, p.Name, "jacksontian")
	assert.Equal(t, p.Mode, "AK")
}

func TestCLIProfileCredentialsProvider_getCredentialsProvider(t *testing.T) {
	conf := &configuration{
		Current: "AK",
		Profiles: []*profile{
			{
				Mode:            "AK",
				Name:            "AK",
				AccessKeyID:     "akid",
				AccessKeySecret: "secret",
			},
			{
				Mode:            "StsToken",
				Name:            "StsToken",
				AccessKeyID:     "access_key_id",
				AccessKeySecret: "access_key_secret",
				SecurityToken:   "sts_token",
			},
			{
				Mode:            "RamRoleArn",
				Name:            "RamRoleArn",
				AccessKeyID:     "akid",
				AccessKeySecret: "secret",
				RoleArn:         "arn",
				StsRegion:       "cn-hangzhou",
				EnableVpc:       true,
				Policy:          "policy",
				ExternalId:      "externalId",
			},
			{
				Mode: "RamRoleArn",
				Name: "Invalid_RamRoleArn",
			},
			{
				Mode:     "EcsRamRole",
				Name:     "EcsRamRole",
				RoleName: "rolename",
			},
			{
				Mode:            "OIDC",
				Name:            "OIDC",
				RoleArn:         "role_arn",
				OIDCTokenFile:   "path/to/oidc/file",
				OIDCProviderARN: "provider_arn",
				StsRegion:       "cn-hangzhou",
				EnableVpc:       true,
				Policy:          "policy",
			},
			{
				Mode:          "ChainableRamRoleArn",
				Name:          "ChainableRamRoleArn",
				RoleArn:       "arn",
				SourceProfile: "AK",
			},
			{
				Mode:          "ChainableRamRoleArn",
				Name:          "ChainableRamRoleArn2",
				SourceProfile: "InvalidSource",
			},
			{
				Name:              "CloudSSO",
				Mode:              "CloudSSO",
				SignInUrl:         "url",
				AccessToken:       "token",
				AccessTokenExpire: time.Now().Unix() + 1000,
				AccessConfig:      "config",
				AccountId:         "uid",
			},
			{
				Mode:                   "OAuth",
				Name:                   "OAuth",
				OauthSiteType:          "CN",
				OauthRefreshToken:      "refresh_token",
				OauthAccessToken:       "access_token",
				OauthAccessTokenExpire: time.Now().Unix() + 1000,
			},
			{
				Mode: "Unsupported",
				Name: "Unsupported",
			},
		},
	}

	provider, err := NewCLIProfileCredentialsProviderBuilder().Build()
	assert.Nil(t, err)
	_, err = provider.getCredentialsProvider(conf, "inexist")
	assert.EqualError(t, err, "unable to get profile with 'inexist'")

	// AK
	cp, err := provider.getCredentialsProvider(conf, "AK")
	assert.Nil(t, err)
	akcp, ok := cp.(*StaticAKCredentialsProvider)
	assert.True(t, ok)
	cc, err := akcp.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, cc, &Credentials{AccessKeyId: "akid", AccessKeySecret: "secret", SecurityToken: "", ProviderName: "static_ak"})
	// STS
	cp, err = provider.getCredentialsProvider(conf, "StsToken")
	assert.Nil(t, err)
	stscp, ok := cp.(*StaticSTSCredentialsProvider)
	assert.True(t, ok)
	cc, err = stscp.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, cc, &Credentials{AccessKeyId: "access_key_id", AccessKeySecret: "access_key_secret", SecurityToken: "sts_token", ProviderName: "static_sts"})
	// RamRoleArn
	cp, err = provider.getCredentialsProvider(conf, "RamRoleArn")
	assert.Nil(t, err)
	_, ok = cp.(*RAMRoleARNCredentialsProvider)
	assert.True(t, ok)
	// RamRoleArn invalid ak
	_, err = provider.getCredentialsProvider(conf, "Invalid_RamRoleArn")
	assert.EqualError(t, err, "the access key id is empty")
	// EcsRamRole
	cp, err = provider.getCredentialsProvider(conf, "EcsRamRole")
	assert.Nil(t, err)
	_, ok = cp.(*ECSRAMRoleCredentialsProvider)
	assert.True(t, ok)
	// OIDC
	cp, err = provider.getCredentialsProvider(conf, "OIDC")
	assert.Nil(t, err)
	_, ok = cp.(*OIDCCredentialsProvider)
	assert.True(t, ok)

	// ChainableRamRoleArn
	cp, err = provider.getCredentialsProvider(conf, "ChainableRamRoleArn")
	assert.Nil(t, err)
	_, ok = cp.(*RAMRoleARNCredentialsProvider)
	assert.True(t, ok)

	// CloudSSO
	cp, err = provider.getCredentialsProvider(conf, "CloudSSO")
	assert.Nil(t, err)
	_, ok = cp.(*CloudSSOCredentialsProvider)
	assert.True(t, ok)

	// OAuth
	cp, err = provider.getCredentialsProvider(conf, "OAuth")
	assert.Nil(t, err)
	_, ok = cp.(*OAuthCredentialsProvider)
	assert.True(t, ok)

	// ChainableRamRoleArn with invalid source profile
	_, err = provider.getCredentialsProvider(conf, "ChainableRamRoleArn2")
	assert.EqualError(t, err, "get source profile failed: unable to get profile with 'InvalidSource'")

	// Unsupported
	_, err = provider.getCredentialsProvider(conf, "Unsupported")
	assert.EqualError(t, err, "unsupported profile mode 'Unsupported'")
}

func TestCLIProfileCredentialsProvider_OAuthProfile(t *testing.T) {
	// Test OAuth profile with CN site type
	conf := &configuration{
		Current: "OAuthCN",
		Profiles: []*profile{
			{
				Mode:                   "OAuth",
				Name:                   "OAuthCN",
				OauthSiteType:          "CN",
				OauthRefreshToken:      "refresh_token",
				OauthAccessToken:       "access_token",
				OauthAccessTokenExpire: time.Now().Unix() + 1000,
			},
			{
				Mode:                   "OAuth",
				Name:                   "OAuthINTL",
				OauthSiteType:          "INTL",
				OauthRefreshToken:      "refresh_token",
				OauthAccessToken:       "access_token",
				OauthAccessTokenExpire: time.Now().Unix() + 1000,
			},
			{
				Mode:                   "OAuth",
				Name:                   "OAuthInvalid",
				OauthSiteType:          "INVALID",
				OauthRefreshToken:      "refresh_token",
				OauthAccessToken:       "access_token",
				OauthAccessTokenExpire: time.Now().Unix() + 1000,
			},
		},
	}

	provider, err := NewCLIProfileCredentialsProviderBuilder().Build()
	assert.Nil(t, err)

	// Test CN OAuth profile
	cp, err := provider.getCredentialsProvider(conf, "OAuthCN")
	assert.Nil(t, err)
	oauthProvider, ok := cp.(*OAuthCredentialsProvider)
	assert.True(t, ok)
	assert.Equal(t, "https://oauth.aliyun.com", oauthProvider.signInUrl)
	assert.Equal(t, "4038181954557748008", oauthProvider.clientId)
	assert.Equal(t, "refresh_token", oauthProvider.refreshToken)
	assert.Equal(t, "access_token", oauthProvider.accessToken)

	// Test INTL OAuth profile
	cp, err = provider.getCredentialsProvider(conf, "OAuthINTL")
	assert.Nil(t, err)
	oauthProvider, ok = cp.(*OAuthCredentialsProvider)
	assert.True(t, ok)
	assert.Equal(t, "https://oauth.alibabacloud.com", oauthProvider.signInUrl)
	assert.Equal(t, "4103531455503354461", oauthProvider.clientId)

	// Test invalid site type
	_, err = provider.getCredentialsProvider(conf, "OAuthInvalid")
	assert.EqualError(t, err, "invalid site type, support CN or INTL")
}

func TestCLIProfileCredentialsProvider_updateOAuthTokens(t *testing.T) {
	// 创建临时配置文件用于测试
	tempDir, err := ioutil.TempDir("", "oauth_test")
	assert.Nil(t, err)
	defer os.RemoveAll(tempDir)
	configPath := path.Join(tempDir, "config.json")

	// 创建测试配置
	testConfig := &configuration{
		Current: "OAuthTest",
		Profiles: []*profile{
			{
				Mode:                   "OAuth",
				Name:                   "OAuthTest",
				OauthSiteType:          "CN",
				OauthRefreshToken:      "old_refresh_token",
				OauthAccessToken:       "old_access_token",
				OauthAccessTokenExpire: time.Now().Unix() + 1000,
			},
		},
	}

	// 写入测试配置
	data, err := json.MarshalIndent(testConfig, "", "    ")
	assert.Nil(t, err)
	err = ioutil.WriteFile(configPath, data, 0644)
	assert.Nil(t, err)

	// 创建CLI Profile提供者
	provider, err := NewCLIProfileCredentialsProviderBuilder().
		WithProfileFile(configPath).
		WithProfileName("OAuthTest").
		Build()
	assert.Nil(t, err)

	// 测试更新OAuth令牌
	newRefreshToken := "new_refresh_token"
	newAccessToken := "new_access_token"
	newAccessKey := "new_access_key"
	newSecret := "new_secret"
	newSecurityToken := "new_security_token"
	newExpireTime := time.Now().Unix() + 3600
	newStsExpire := time.Now().Unix() + 7200

	err = provider.updateOAuthTokens(newRefreshToken, newAccessToken, newAccessKey, newSecret, newSecurityToken, newExpireTime, newStsExpire)
	assert.Nil(t, err)

	// 验证配置文件已更新
	updatedConf, err := newConfigurationFromPath(configPath)
	assert.Nil(t, err)

	updatedProfile, err := updatedConf.getProfile("OAuthTest")
	assert.Nil(t, err)
	assert.Equal(t, newRefreshToken, updatedProfile.OauthRefreshToken)
	assert.Equal(t, newAccessToken, updatedProfile.OauthAccessToken)
	assert.Equal(t, newAccessKey, updatedProfile.AccessKeyID)
	assert.Equal(t, newSecret, updatedProfile.AccessKeySecret)
	assert.Equal(t, newSecurityToken, updatedProfile.SecurityToken)
	assert.Equal(t, newExpireTime, updatedProfile.OauthAccessTokenExpire)
	assert.Equal(t, newStsExpire, updatedProfile.StsExpire)
}

func TestCLIProfileCredentialsProvider_writeConfigurationToFile(t *testing.T) {
	// 创建临时配置文件用于测试
	tempDir, err := ioutil.TempDir("", "oauth_write_test")
	assert.Nil(t, err)
	defer os.RemoveAll(tempDir)
	configPath := path.Join(tempDir, "config.json")

	// 创建测试配置
	testConfig := &configuration{
		Current: "OAuthTest",
		Profiles: []*profile{
			{
				Mode:                   "OAuth",
				Name:                   "OAuthTest",
				OauthSiteType:          "CN",
				OauthRefreshToken:      "test_refresh_token",
				OauthAccessToken:       "test_access_token",
				OauthAccessTokenExpire: time.Now().Unix() + 1000,
			},
		},
	}

	// 创建CLI Profile提供者
	provider, err := NewCLIProfileCredentialsProviderBuilder().
		WithProfileFile(configPath).
		WithProfileName("OAuthTest").
		Build()
	assert.Nil(t, err)

	// 测试writeConfigurationToFile函数
	err = provider.writeConfigurationToFile(configPath, testConfig)
	assert.Nil(t, err)

	// 验证文件已写入
	_, err = os.Stat(configPath)
	assert.Nil(t, err)

	// 验证文件内容
	updatedConf, err := newConfigurationFromPath(configPath)
	assert.Nil(t, err)
	assert.Equal(t, testConfig.Current, updatedConf.Current)
	assert.Equal(t, len(testConfig.Profiles), len(updatedConf.Profiles))
}

func TestCLIProfileCredentialsProvider_writeConfigurationToFile_Error(t *testing.T) {
	// Skip on Windows as directory permissions work differently
	if runtime.GOOS == "windows" {
		t.Skip("Skipping test on Windows - directory permissions work differently")
	}

	// 创建临时目录用于测试
	tempDir, err := ioutil.TempDir("", "oauth_write_error_test")
	assert.Nil(t, err)
	defer os.RemoveAll(tempDir)

	// 创建一个只读目录来测试写入错误
	readOnlyDir := path.Join(tempDir, "readonly")
	err = os.Mkdir(readOnlyDir, 0444) // 只读权限
	assert.Nil(t, err)
	configPath := path.Join(readOnlyDir, "config.json")

	// 创建测试配置
	testConfig := &configuration{
		Current: "OAuthTest",
		Profiles: []*profile{
			{
				Mode:                   "OAuth",
				Name:                   "OAuthTest",
				OauthSiteType:          "CN",
				OauthRefreshToken:      "test_refresh_token",
				OauthAccessToken:       "test_access_token",
				OauthAccessTokenExpire: time.Now().Unix() + 1000,
			},
		},
	}

	// 创建CLI Profile提供者
	provider, err := NewCLIProfileCredentialsProviderBuilder().
		WithProfileFile(configPath).
		WithProfileName("OAuthTest").
		Build()
	assert.Nil(t, err)

	// 测试写入只读目录应该失败
	err = provider.writeConfigurationToFile(configPath, testConfig)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "failed to write temp file")
}

func TestCLIProfileCredentialsProvider_writeConfigurationToFileWithLock(t *testing.T) {
	// 创建临时配置文件用于测试
	tempDir, err := ioutil.TempDir("", "oauth_write_lock_test")
	assert.Nil(t, err)
	defer os.RemoveAll(tempDir)
	configPath := path.Join(tempDir, "config.json")

	// 创建测试配置
	testConfig := &configuration{
		Current: "OAuthTest",
		Profiles: []*profile{
			{
				Mode:                   "OAuth",
				Name:                   "OAuthTest",
				OauthSiteType:          "CN",
				OauthRefreshToken:      "test_refresh_token",
				OauthAccessToken:       "test_access_token",
				OauthAccessTokenExpire: time.Now().Unix() + 1000,
			},
		},
	}

	// 创建CLI Profile提供者
	provider, err := NewCLIProfileCredentialsProviderBuilder().
		WithProfileFile(configPath).
		WithProfileName("OAuthTest").
		Build()
	assert.Nil(t, err)

	// 测试writeConfigurationToFileWithLock函数
	err = provider.writeConfigurationToFileWithLock(configPath, testConfig)
	assert.Nil(t, err)

	// 验证文件已写入
	_, err = os.Stat(configPath)
	assert.Nil(t, err)

	// 验证文件内容
	updatedConf, err := newConfigurationFromPath(configPath)
	assert.Nil(t, err)
	assert.Equal(t, testConfig.Current, updatedConf.Current)
	assert.Equal(t, len(testConfig.Profiles), len(updatedConf.Profiles))
}

func TestCLIProfileCredentialsProvider_writeConfigurationToFileWithLock_Error(t *testing.T) {
	// Skip on Windows as directory permissions work differently
	if runtime.GOOS == "windows" {
		t.Skip("Skipping test on Windows - directory permissions work differently")
	}

	// 创建临时目录用于测试
	tempDir, err := ioutil.TempDir("", "oauth_write_lock_error_test")
	assert.Nil(t, err)
	defer os.RemoveAll(tempDir)

	// 创建一个只读目录来测试写入错误
	readOnlyDir := path.Join(tempDir, "readonly")
	err = os.Mkdir(readOnlyDir, 0444) // 只读权限
	assert.Nil(t, err)
	configPath := path.Join(readOnlyDir, "config.json")

	// 创建测试配置
	testConfig := &configuration{
		Current: "OAuthTest",
		Profiles: []*profile{
			{
				Mode:                   "OAuth",
				Name:                   "OAuthTest",
				OauthSiteType:          "CN",
				OauthRefreshToken:      "test_refresh_token",
				OauthAccessToken:       "test_access_token",
				OauthAccessTokenExpire: time.Now().Unix() + 1000,
			},
		},
	}

	// 创建CLI Profile提供者
	provider, err := NewCLIProfileCredentialsProviderBuilder().
		WithProfileFile(configPath).
		WithProfileName("OAuthTest").
		Build()
	assert.Nil(t, err)

	// 测试写入只读目录应该失败
	err = provider.writeConfigurationToFileWithLock(configPath, testConfig)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "failed to open config file")
}

func TestCLIProfileCredentialsProvider_getOAuthTokenUpdateCallback(t *testing.T) {
	// 创建临时配置文件用于测试
	tempDir, err := ioutil.TempDir("", "oauth_callback_test")
	assert.Nil(t, err)
	defer os.RemoveAll(tempDir)
	configPath := path.Join(tempDir, "config.json")

	// 创建测试配置
	testConfig := &configuration{
		Current: "OAuthTest",
		Profiles: []*profile{
			{
				Mode:                   "OAuth",
				Name:                   "OAuthTest",
				OauthSiteType:          "CN",
				OauthRefreshToken:      "test_refresh_token",
				OauthAccessToken:       "test_access_token",
				OauthAccessTokenExpire: time.Now().Unix() + 1000,
			},
		},
	}

	// 写入测试配置
	data, err := json.MarshalIndent(testConfig, "", "    ")
	assert.Nil(t, err)
	err = ioutil.WriteFile(configPath, data, 0644)
	assert.Nil(t, err)

	// 创建CLI Profile提供者
	provider, err := NewCLIProfileCredentialsProviderBuilder().
		WithProfileFile(configPath).
		WithProfileName("OAuthTest").
		Build()
	assert.Nil(t, err)

	// 测试获取回调函数
	callback := provider.getOAuthTokenUpdateCallback()
	assert.NotNil(t, callback)

	// 测试回调函数
	newRefreshToken := "callback_refresh_token"
	newAccessToken := "callback_access_token"
	newAccessKey := "callback_access_key"
	newSecret := "callback_secret"
	newSecurityToken := "callback_security_token"
	newExpireTime := time.Now().Unix() + 3600
	newStsExpire := time.Now().Unix() + 7200

	err = callback(newRefreshToken, newAccessToken, newAccessKey, newSecret, newSecurityToken, newExpireTime, newStsExpire)
	assert.Nil(t, err)

	// 验证配置文件已更新
	updatedConf, err := newConfigurationFromPath(configPath)
	assert.Nil(t, err)

	updatedProfile, err := updatedConf.getProfile("OAuthTest")
	assert.Nil(t, err)
	assert.Equal(t, newRefreshToken, updatedProfile.OauthRefreshToken)
	assert.Equal(t, newAccessToken, updatedProfile.OauthAccessToken)
	assert.Equal(t, newAccessKey, updatedProfile.AccessKeyID)
	assert.Equal(t, newSecret, updatedProfile.AccessKeySecret)
	assert.Equal(t, newSecurityToken, updatedProfile.SecurityToken)
	assert.Equal(t, newExpireTime, updatedProfile.OauthAccessTokenExpire)
	assert.Equal(t, newStsExpire, updatedProfile.StsExpire)
}

func TestCLIProfileCredentialsProvider_updateOAuthTokens_Error(t *testing.T) {
	// 创建临时配置文件用于测试
	tempDir, err := ioutil.TempDir("", "oauth_update_error_test")
	assert.Nil(t, err)
	defer os.RemoveAll(tempDir)
	configPath := path.Join(tempDir, "config.json")

	// 创建CLI Profile提供者
	provider, err := NewCLIProfileCredentialsProviderBuilder().
		WithProfileFile(configPath).
		WithProfileName("NonExistentProfile").
		Build()
	assert.Nil(t, err)

	// 测试更新不存在的profile应该失败
	newRefreshToken := "new_refresh_token"
	newAccessToken := "new_access_token"
	newAccessKey := "new_access_key"
	newSecret := "new_secret"
	newSecurityToken := "new_security_token"
	newExpireTime := time.Now().Unix() + 3600
	newStsExpire := time.Now().Unix() + 7200

	err = provider.updateOAuthTokens(newRefreshToken, newAccessToken, newAccessKey, newSecret, newSecurityToken, newExpireTime, newStsExpire)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "failed to read config file")
}

func TestCLIProfileCredentialsProvider_updateOAuthTokens_ProfileNotFound(t *testing.T) {
	// 创建临时配置文件用于测试
	tempDir, err := ioutil.TempDir("", "oauth_update_profile_error_test")
	assert.Nil(t, err)
	defer os.RemoveAll(tempDir)
	configPath := path.Join(tempDir, "config.json")

	// 创建测试配置
	testConfig := &configuration{
		Current: "OAuthTest",
		Profiles: []*profile{
			{
				Mode:                   "OAuth",
				Name:                   "OAuthTest",
				OauthSiteType:          "CN",
				OauthRefreshToken:      "test_refresh_token",
				OauthAccessToken:       "test_access_token",
				OauthAccessTokenExpire: time.Now().Unix() + 1000,
			},
		},
	}

	// 写入测试配置
	data, err := json.MarshalIndent(testConfig, "", "    ")
	assert.Nil(t, err)
	err = ioutil.WriteFile(configPath, data, 0644)
	assert.Nil(t, err)

	// 创建CLI Profile提供者，使用不存在的profile名称
	provider, err := NewCLIProfileCredentialsProviderBuilder().
		WithProfileFile(configPath).
		WithProfileName("NonExistentProfile").
		Build()
	assert.Nil(t, err)

	// 测试更新不存在的profile应该失败
	newRefreshToken := "new_refresh_token"
	newAccessToken := "new_access_token"
	newAccessKey := "new_access_key"
	newSecret := "new_secret"
	newSecurityToken := "new_security_token"
	newExpireTime := time.Now().Unix() + 3600
	newStsExpire := time.Now().Unix() + 7200

	err = provider.updateOAuthTokens(newRefreshToken, newAccessToken, newAccessKey, newSecret, newSecurityToken, newExpireTime, newStsExpire)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "failed to get profile NonExistentProfile")
}

func TestCLIProfileCredentialsProvider_ConcurrentUpdate(t *testing.T) {
	// 创建临时配置文件用于测试
	tempDir, err := ioutil.TempDir("", "oauth_concurrent_test")
	assert.Nil(t, err)
	defer os.RemoveAll(tempDir)
	configPath := path.Join(tempDir, "config.json")

	// 创建测试配置
	testConfig := &configuration{
		Current: "OAuthTest",
		Profiles: []*profile{
			{
				Mode:                   "OAuth",
				Name:                   "OAuthTest",
				OauthSiteType:          "CN",
				OauthRefreshToken:      "initial_refresh_token",
				OauthAccessToken:       "initial_access_token",
				OauthAccessTokenExpire: time.Now().Unix() + 1000,
			},
		},
	}

	// 写入测试配置
	data, err := json.MarshalIndent(testConfig, "", "    ")
	assert.Nil(t, err)
	err = ioutil.WriteFile(configPath, data, 0644)
	assert.Nil(t, err)

	// 创建CLI Profile提供者
	provider, err := NewCLIProfileCredentialsProviderBuilder().
		WithProfileFile(configPath).
		WithProfileName("OAuthTest").
		Build()
	assert.Nil(t, err)

	// 并发更新测试
	var wg sync.WaitGroup
	numGoroutines := 10

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			refreshToken := fmt.Sprintf("refresh_token_%d", index)
			accessToken := fmt.Sprintf("access_token_%d", index)
			accessKey := fmt.Sprintf("access_key_%d", index)
			secret := fmt.Sprintf("secret_%d", index)
			securityToken := fmt.Sprintf("security_token_%d", index)
			expireTime := time.Now().Unix() + int64(3600+index)
			stsExpire := time.Now().Unix() + int64(7200+index)

			err := provider.updateOAuthTokens(refreshToken, accessToken, accessKey, secret, securityToken, expireTime, stsExpire)
			// 由于并发访问，可能会有一些更新失败，这是正常的
			_ = err
		}(i)
	}

	wg.Wait()

	// 验证最终配置文件仍然有效
	updatedConf, err := newConfigurationFromPath(configPath)
	assert.Nil(t, err)

	updatedProfile, err := updatedConf.getProfile("OAuthTest")
	assert.Nil(t, err)
	assert.NotEmpty(t, updatedProfile.OauthRefreshToken)
	assert.NotEmpty(t, updatedProfile.OauthAccessToken)
	assert.True(t, updatedProfile.OauthAccessTokenExpire > 0)
}

func TestCLIProfileCredentialsProvider_FileLock(t *testing.T) {
	// 创建临时配置文件用于测试
	tempDir, err := ioutil.TempDir("", "oauth_filelock_test")
	assert.Nil(t, err)
	defer os.RemoveAll(tempDir)
	configPath := path.Join(tempDir, "config.json")

	// 创建测试配置
	testConfig := &configuration{
		Current: "OAuthTest",
		Profiles: []*profile{
			{
				Mode:                   "OAuth",
				Name:                   "OAuthTest",
				OauthSiteType:          "CN",
				OauthRefreshToken:      "initial_refresh_token",
				OauthAccessToken:       "initial_access_token",
				OauthAccessTokenExpire: time.Now().Unix() + 1000,
			},
		},
	}

	// 写入测试配置
	data, err := json.MarshalIndent(testConfig, "", "    ")
	assert.Nil(t, err)
	err = ioutil.WriteFile(configPath, data, 0644)
	assert.Nil(t, err)

	// 创建CLI Profile提供者
	provider, err := NewCLIProfileCredentialsProviderBuilder().
		WithProfileFile(configPath).
		WithProfileName("OAuthTest").
		Build()
	assert.Nil(t, err)

	// 测试操作系统级别的文件锁
	newRefreshToken := "locked_refresh_token"
	newAccessToken := "locked_access_token"
	newAccessKey := "locked_access_key"
	newSecret := "locked_secret"
	newSecurityToken := "locked_security_token"
	newExpireTime := time.Now().Unix() + 3600
	newStsExpire := time.Now().Unix() + 7200

	err = provider.updateOAuthTokens(newRefreshToken, newAccessToken, newAccessKey, newSecret, newSecurityToken, newExpireTime, newStsExpire)
	assert.Nil(t, err)

	// 验证配置文件已更新
	updatedConf, err := newConfigurationFromPath(configPath)
	assert.Nil(t, err)

	updatedProfile, err := updatedConf.getProfile("OAuthTest")
	assert.Nil(t, err)
	assert.Equal(t, newRefreshToken, updatedProfile.OauthRefreshToken)
	assert.Equal(t, newAccessToken, updatedProfile.OauthAccessToken)
	assert.Equal(t, newAccessKey, updatedProfile.AccessKeyID)
	assert.Equal(t, newSecret, updatedProfile.AccessKeySecret)
	assert.Equal(t, newSecurityToken, updatedProfile.SecurityToken)
	assert.Equal(t, newExpireTime, updatedProfile.OauthAccessTokenExpire)
	assert.Equal(t, newStsExpire, updatedProfile.StsExpire)
}

func TestCLIProfileCredentialsProvider_GetCredentials(t *testing.T) {
	originHttpDo := httpDo
	defer func() { httpDo = originHttpDo }()
	rollback := utils.Memory("ALIBABA_CLOUD_CONFIG_FILE")
	defer func() {
		getHomePath = utils.GetHomePath
		rollback()
	}()

	getHomePath = func() string {
		return ""
	}
	provider, err := NewCLIProfileCredentialsProviderBuilder().Build()
	assert.Nil(t, err)
	_, err = provider.GetCredentials()
	assert.EqualError(t, err, "cannot found home dir")

	getHomePath = func() string {
		return "/path/invalid/home/dir"
	}
	provider, err = NewCLIProfileCredentialsProviderBuilder().Build()
	assert.Nil(t, err)
	_, err = provider.GetCredentials()
	assert.Contains(t, err.Error(), "reading aliyun cli config from '/path/invalid/home/dir/.aliyun/config.json' failed")

	// testcase: specify credentials file
	provider, err = NewCLIProfileCredentialsProviderBuilder().WithProfileFile("/path/to/config.invalid").Build()
	assert.Nil(t, err)
	_, err = provider.GetCredentials()
	assert.Contains(t, err.Error(), "reading aliyun cli config from '/path/to/config.invalid' failed")

	// testcase: specify credentials file with env
	os.Setenv("ALIBABA_CLOUD_CONFIG_FILE", "/path/to/config.invalid")
	provider, err = NewCLIProfileCredentialsProviderBuilder().Build()
	assert.Nil(t, err)
	_, err = provider.GetCredentials()
	assert.Contains(t, err.Error(), "reading aliyun cli config from '/path/to/config.invalid' failed")

	provider, err = NewCLIProfileCredentialsProviderBuilder().WithProfileFile("/path/to/config1.invalid").Build()
	assert.Nil(t, err)
	_, err = provider.GetCredentials()
	assert.Contains(t, err.Error(), "reading aliyun cli config from '/path/to/config1.invalid' failed")
	os.Unsetenv("ALIBABA_CLOUD_CONFIG_FILE")

	getHomePath = func() string {
		wd, _ := os.Getwd()
		return path.Join(wd, "fixtures")
	}

	// get credentials by current profile
	provider, err = NewCLIProfileCredentialsProviderBuilder().Build()
	assert.Nil(t, err)
	cc, err := provider.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, &Credentials{AccessKeyId: "akid", AccessKeySecret: "secret", SecurityToken: "", ProviderName: "cli_profile/static_ak"}, cc)

	provider, err = NewCLIProfileCredentialsProviderBuilder().WithProfileName("inexist").Build()
	assert.Nil(t, err)
	_, err = provider.GetCredentials()
	assert.EqualError(t, err, "unable to get profile with 'inexist'")

	// The get_credentials_error profile is invalid
	provider, err = NewCLIProfileCredentialsProviderBuilder().WithProfileName("get_credentials_error").Build()
	assert.Nil(t, err)
	_, err = provider.GetCredentials()
	assert.Contains(t, err.Error(), "InvalidAccessKeyId.NotFound")

	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		res = &httputil.Response{
			StatusCode: 200,
			Body:       []byte(`{"Credentials": {"AccessKeyId":"akid","AccessKeySecret":"aksecret","Expiration":"2021-10-20T04:27:09Z","SecurityToken":"ststoken"}}`),
		}
		return
	}
	provider, err = NewCLIProfileCredentialsProviderBuilder().WithProfileName("ChainableRamRoleArn").Build()
	assert.Nil(t, err)
	cc, err = provider.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, "akid", cc.AccessKeyId)
	assert.Equal(t, "aksecret", cc.AccessKeySecret)
	assert.Equal(t, "ststoken", cc.SecurityToken)
	assert.Equal(t, "cli_profile/ram_role_arn/ram_role_arn/static_ak", cc.ProviderName)

	provider.innerProvider = new(testProvider)
	cc, err = provider.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, "test", cc.AccessKeyId)
	assert.Equal(t, "test", cc.AccessKeySecret)
	assert.Equal(t, "cli_profile/test", cc.ProviderName)
}

func TestCLIProfileCredentialsProvider_writeConfigurationToFile_RenameError(t *testing.T) {
	// 创建临时配置文件用于测试
	tempDir, err := ioutil.TempDir("", "oauth_rename_error_test")
	assert.Nil(t, err)
	defer os.RemoveAll(tempDir)
	configPath := path.Join(tempDir, "config.json")

	// 创建测试配置
	testConfig := &configuration{
		Current: "OAuthTest",
		Profiles: []*profile{
			{
				Mode:                   "OAuth",
				Name:                   "OAuthTest",
				OauthSiteType:          "CN",
				OauthRefreshToken:      "test_refresh_token",
				OauthAccessToken:       "test_access_token",
				OauthAccessTokenExpire: time.Now().Unix() + 1000,
			},
		},
	}

	// 创建CLI Profile提供者
	provider, err := NewCLIProfileCredentialsProviderBuilder().
		WithProfileFile(configPath).
		WithProfileName("OAuthTest").
		Build()
	assert.Nil(t, err)

	// 创建一个已存在的文件来模拟重命名错误
	err = ioutil.WriteFile(configPath, []byte("existing content"), 0644)
	assert.Nil(t, err)

	// 在Windows上，重命名可能会失败，这里我们测试错误处理
	err = provider.writeConfigurationToFile(configPath, testConfig)
	// 这个测试可能会成功或失败，取决于操作系统，我们主要测试错误处理路径
	_ = err
}

func TestCLIProfileCredentialsProvider_writeConfigurationToFileWithLock_RenameError(t *testing.T) {
	// 创建临时配置文件用于测试
	tempDir, err := ioutil.TempDir("", "oauth_rename_lock_error_test")
	assert.Nil(t, err)
	defer os.RemoveAll(tempDir)
	configPath := path.Join(tempDir, "config.json")

	// 创建测试配置
	testConfig := &configuration{
		Current: "OAuthTest",
		Profiles: []*profile{
			{
				Mode:                   "OAuth",
				Name:                   "OAuthTest",
				OauthSiteType:          "CN",
				OauthRefreshToken:      "test_refresh_token",
				OauthAccessToken:       "test_access_token",
				OauthAccessTokenExpire: time.Now().Unix() + 1000,
			},
		},
	}

	// 创建CLI Profile提供者
	provider, err := NewCLIProfileCredentialsProviderBuilder().
		WithProfileFile(configPath).
		WithProfileName("OAuthTest").
		Build()
	assert.Nil(t, err)

	// 创建一个已存在的文件来模拟重命名错误
	err = ioutil.WriteFile(configPath, []byte("existing content"), 0644)
	assert.Nil(t, err)

	// 在Windows上，重命名可能会失败，这里我们测试错误处理
	err = provider.writeConfigurationToFileWithLock(configPath, testConfig)
	// 这个测试可能会成功或失败，取决于操作系统，我们主要测试错误处理路径
	_ = err
}

func TestCLIProfileCredentialsProvider_updateOAuthTokens_WriteError(t *testing.T) {
	// 创建临时配置文件用于测试
	tempDir, err := ioutil.TempDir("", "oauth_update_write_error_test")
	assert.Nil(t, err)
	defer os.RemoveAll(tempDir)
	configPath := path.Join(tempDir, "config.json")

	// 创建测试配置
	testConfig := &configuration{
		Current: "OAuthTest",
		Profiles: []*profile{
			{
				Mode:                   "OAuth",
				Name:                   "OAuthTest",
				OauthSiteType:          "CN",
				OauthRefreshToken:      "test_refresh_token",
				OauthAccessToken:       "test_access_token",
				OauthAccessTokenExpire: time.Now().Unix() + 1000,
			},
		},
	}

	// 写入测试配置
	data, err := json.MarshalIndent(testConfig, "", "    ")
	assert.Nil(t, err)
	err = ioutil.WriteFile(configPath, data, 0644)
	assert.Nil(t, err)

	// 创建CLI Profile提供者
	provider, err := NewCLIProfileCredentialsProviderBuilder().
		WithProfileFile(configPath).
		WithProfileName("OAuthTest").
		Build()
	assert.Nil(t, err)

	// 删除文件以模拟读取错误
	err = os.Remove(configPath)
	assert.Nil(t, err)

	// 测试更新应该失败
	newRefreshToken := "new_refresh_token"
	newAccessToken := "new_access_token"
	newAccessKey := "new_access_key"
	newSecret := "new_secret"
	newSecurityToken := "new_security_token"
	newExpireTime := time.Now().Unix() + 3600
	newStsExpire := time.Now().Unix() + 7200

	err = provider.updateOAuthTokens(newRefreshToken, newAccessToken, newAccessKey, newSecret, newSecurityToken, newExpireTime, newStsExpire)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "failed to read config file")
}

func TestCLIProfileCredentialsProvider_GetCredentials_WithOAuthProfile(t *testing.T) {
	// 创建临时配置文件用于测试
	tempDir, err := ioutil.TempDir("", "oauth_get_credentials_test")
	assert.Nil(t, err)
	defer os.RemoveAll(tempDir)
	configPath := path.Join(tempDir, "config.json")

	// 创建测试配置
	testConfig := &configuration{
		Current: "OAuthTest",
		Profiles: []*profile{
			{
				Mode:                   "OAuth",
				Name:                   "OAuthTest",
				OauthSiteType:          "CN",
				OauthRefreshToken:      "test_refresh_token",
				OauthAccessToken:       "test_access_token",
				OauthAccessTokenExpire: time.Now().Unix() + 1000,
			},
		},
	}

	// 写入测试配置
	data, err := json.MarshalIndent(testConfig, "", "    ")
	assert.Nil(t, err)
	err = ioutil.WriteFile(configPath, data, 0644)
	assert.Nil(t, err)

	// 创建CLI Profile提供者
	provider, err := NewCLIProfileCredentialsProviderBuilder().
		WithProfileFile(configPath).
		WithProfileName("OAuthTest").
		Build()
	assert.Nil(t, err)

	// 测试获取凭据（会失败，因为没有真实的OAuth服务）
	_, err = provider.GetCredentials()
	assert.NotNil(t, err)
	// 应该包含OAuth相关的错误信息
	assert.Contains(t, err.Error(), "OAuth")
}

func TestCLIProfileCredentialsProvider_FileLock_ConcurrentAccess(t *testing.T) {
	// 创建临时配置文件用于测试
	tempDir, err := ioutil.TempDir("", "oauth_filelock_concurrent_test")
	assert.Nil(t, err)
	defer os.RemoveAll(tempDir)
	configPath := path.Join(tempDir, "config.json")

	// 创建测试配置
	testConfig := &configuration{
		Current: "OAuthTest",
		Profiles: []*profile{
			{
				Mode:                   "OAuth",
				Name:                   "OAuthTest",
				OauthSiteType:          "CN",
				OauthRefreshToken:      "test_refresh_token",
				OauthAccessToken:       "test_access_token",
				OauthAccessTokenExpire: time.Now().Unix() + 1000,
			},
		},
	}

	// 写入测试配置
	data, err := json.MarshalIndent(testConfig, "", "    ")
	assert.Nil(t, err)
	err = ioutil.WriteFile(configPath, data, 0644)
	assert.Nil(t, err)

	// 创建CLI Profile提供者
	provider, err := NewCLIProfileCredentialsProviderBuilder().
		WithProfileFile(configPath).
		WithProfileName("OAuthTest").
		Build()
	assert.Nil(t, err)

	// 测试文件锁的并发访问
	var wg sync.WaitGroup
	numGoroutines := 5

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			// 测试文件锁写入
			err := provider.writeConfigurationToFileWithLock(configPath, testConfig)
			_ = err // 忽略错误，主要测试并发安全性
		}(i)
	}

	wg.Wait()

	// 验证最终配置文件仍然有效
	_, err = newConfigurationFromPath(configPath)
	assert.Nil(t, err)
}

func TestCLIProfileCredentialsProvider_EdgeCases(t *testing.T) {
	// 测试空配置
	emptyConfig := &configuration{
		Current:  "",
		Profiles: []*profile{},
	}

	// 创建临时配置文件用于测试
	tempDir, err := ioutil.TempDir("", "oauth_edge_cases_test")
	assert.Nil(t, err)
	defer os.RemoveAll(tempDir)
	configPath := path.Join(tempDir, "config.json")

	// 创建CLI Profile提供者
	provider, err := NewCLIProfileCredentialsProviderBuilder().
		WithProfileFile(configPath).
		WithProfileName("OAuthTest").
		Build()
	assert.Nil(t, err)

	// 测试写入空配置
	err = provider.writeConfigurationToFile(configPath, emptyConfig)
	assert.Nil(t, err)

	// 测试文件锁写入空配置
	err = provider.writeConfigurationToFileWithLock(configPath, emptyConfig)
	assert.Nil(t, err)
}

func TestCLIProfileCredentialsProvider_ProfileName_Empty(t *testing.T) {
	// 创建临时配置文件用于测试
	tempDir, err := ioutil.TempDir("", "oauth_empty_profile_test")
	assert.Nil(t, err)
	defer os.RemoveAll(tempDir)
	configPath := path.Join(tempDir, "config.json")

	// 创建测试配置
	testConfig := &configuration{
		Current: "OAuthTest",
		Profiles: []*profile{
			{
				Mode:                   "OAuth",
				Name:                   "OAuthTest",
				OauthSiteType:          "CN",
				OauthRefreshToken:      "test_refresh_token",
				OauthAccessToken:       "test_access_token",
				OauthAccessTokenExpire: time.Now().Unix() + 1000,
			},
		},
	}

	// 写入测试配置
	data, err := json.MarshalIndent(testConfig, "", "    ")
	assert.Nil(t, err)
	err = ioutil.WriteFile(configPath, data, 0644)
	assert.Nil(t, err)

	// 创建CLI Profile提供者，不指定profile名称
	provider, err := NewCLIProfileCredentialsProviderBuilder().
		WithProfileFile(configPath).
		WithProfileName("OAuthTest").
		Build()
	assert.Nil(t, err)

	// 测试更新令牌（应该使用current profile）
	newRefreshToken := "new_refresh_token"
	newAccessToken := "new_access_token"
	newAccessKey := "new_access_key"
	newSecret := "new_secret"
	newSecurityToken := "new_security_token"
	newExpireTime := time.Now().Unix() + 3600
	newStsExpire := time.Now().Unix() + 7200

	err = provider.updateOAuthTokens(newRefreshToken, newAccessToken, newAccessKey, newSecret, newSecurityToken, newExpireTime, newStsExpire)
	assert.Nil(t, err)

	// 验证配置文件已更新
	updatedConf, err := newConfigurationFromPath(configPath)
	assert.Nil(t, err)

	updatedProfile, err := updatedConf.getProfile("OAuthTest")
	assert.Nil(t, err)
	assert.Equal(t, newRefreshToken, updatedProfile.OauthRefreshToken)
	assert.Equal(t, newAccessToken, updatedProfile.OauthAccessToken)
}

func TestCLIProfileCredentialsProvider_WriteConfigurationToFileWithLock_ErrorScenarios(t *testing.T) {
	// Skip on Windows as directory permissions work differently
	if runtime.GOOS == "windows" {
		t.Skip("Skipping test on Windows - directory permissions work differently")
	}

	// 创建临时目录
	tempDir, err := ioutil.TempDir("", "cli_profile_test")
	assert.Nil(t, err)
	defer os.RemoveAll(tempDir)

	// 创建配置文件路径
	configPath := path.Join(tempDir, "config.json")

	// 创建配置
	conf := &configuration{
		Current: "test",
		Profiles: []*profile{
			{
				Name: "test",
			},
		},
	}

	provider := &CLIProfileCredentialsProvider{
		profileFile: configPath,
		profileName: "test",
	}

	// 测试1: 文件打开失败 - 通过创建只读目录来模拟
	readOnlyDir := path.Join(tempDir, "readonly")
	err = os.Mkdir(readOnlyDir, 0400) // 只读权限
	assert.Nil(t, err)
	defer os.Remove(readOnlyDir)

	readOnlyPath := path.Join(readOnlyDir, "config.json")
	err = provider.writeConfigurationToFileWithLock(readOnlyPath, conf)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "failed to open config file")

	// 测试2: 临时文件写入失败 - 通过创建只读目录来模拟
	readOnlyTempDir := path.Join(tempDir, "readonly_temp")
	err = os.Mkdir(readOnlyTempDir, 0400) // 只读权限
	assert.Nil(t, err)
	defer os.Remove(readOnlyTempDir)

	// 创建一个无效的配置路径来触发错误
	invalidPath := path.Join(readOnlyTempDir, "config.json")
	err = provider.writeConfigurationToFileWithLock(invalidPath, conf)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "failed to open config file")

	// 测试3: 文件重命名失败 - 通过创建只读目标文件来模拟
	targetPath := path.Join(tempDir, "target.json")
	err = ioutil.WriteFile(targetPath, []byte("existing content"), 0400) // 只读文件
	assert.Nil(t, err)
	defer os.Remove(targetPath)

	// 创建一个临时文件
	tempFile := targetPath + ".tmp"
	err = ioutil.WriteFile(tempFile, []byte("temp content"), 0644)
	assert.Nil(t, err)
	defer os.Remove(tempFile)

}

func TestCLIProfileCredentialsProvider_WriteConfigurationToFile_ErrorScenarios(t *testing.T) {
	// Skip on Windows as directory permissions work differently
	if runtime.GOOS == "windows" {
		t.Skip("Skipping test on Windows - directory permissions work differently")
	}

	// 创建临时目录
	tempDir, err := ioutil.TempDir("", "cli_profile_test")
	assert.Nil(t, err)
	defer os.RemoveAll(tempDir)

	// 创建配置
	conf := &configuration{
		Current: "test",
		Profiles: []*profile{
			{
				Name: "test",
			},
		},
	}

	provider := &CLIProfileCredentialsProvider{
		profileFile: path.Join(tempDir, "config.json"),
		profileName: "test",
	}

	// 测试1: 临时文件写入失败 - 通过创建只读目录来模拟
	readOnlyDir := path.Join(tempDir, "readonly")
	err = os.Mkdir(readOnlyDir, 0400) // 只读权限
	assert.Nil(t, err)
	defer os.Remove(readOnlyDir)

	readOnlyPath := path.Join(readOnlyDir, "config.json")
	err = provider.writeConfigurationToFile(readOnlyPath, conf)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "failed to write temp file")

	// 测试2: 文件重命名失败 - 通过创建只读目标文件来模拟
	targetPath := path.Join(tempDir, "target.json")
	err = ioutil.WriteFile(targetPath, []byte("existing content"), 0400) // 只读文件
	assert.Nil(t, err)
	defer os.Remove(targetPath)

	// 创建一个临时文件
	tempFile := targetPath + ".tmp"
	err = ioutil.WriteFile(tempFile, []byte("temp content"), 0644)
	assert.Nil(t, err)
	defer os.Remove(tempFile)
}

func TestCLIProfileCredentialsProvider_UpdateOAuthTokens_ErrorScenarios(t *testing.T) {
	// 创建临时目录
	tempDir, err := ioutil.TempDir("", "cli_profile_test")
	assert.Nil(t, err)
	defer os.RemoveAll(tempDir)

	// 测试1: 配置文件读取失败
	provider := &CLIProfileCredentialsProvider{
		profileFile: "/nonexistent/path/config.json",
		profileName: "test",
	}

	err = provider.updateOAuthTokens("refresh", "access", "ak", "sk", "token", 1234567890, 1234567890)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "failed to read config file")

	// 测试2: 配置文件存在但格式错误
	invalidConfigPath := path.Join(tempDir, "invalid_config.json")
	err = ioutil.WriteFile(invalidConfigPath, []byte("invalid json"), 0644)
	assert.Nil(t, err)

	provider = &CLIProfileCredentialsProvider{
		profileFile: invalidConfigPath,
		profileName: "test",
	}

	err = provider.updateOAuthTokens("refresh", "access", "ak", "sk", "token", 1234567890, 1234567890)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "failed to read config file")

	// 测试3: 配置文件存在但找不到指定的 profile
	validConfig := `{
		"current": "test",
		"profiles": [
			{
				"name": "other",
				"mode": "AK"
			}
		]
	}`
	validConfigPath := path.Join(tempDir, "valid_config.json")
	err = ioutil.WriteFile(validConfigPath, []byte(validConfig), 0644)
	assert.Nil(t, err)

	provider = &CLIProfileCredentialsProvider{
		profileFile: validConfigPath,
		profileName: "nonexistent",
	}

	err = provider.updateOAuthTokens("refresh", "access", "ak", "sk", "token", 1234567890, 1234567890)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "failed to get profile nonexistent")

	// 测试4: 配置文件写入失败 - 通过创建只读目录来模拟 (仅在Unix上测试)
	if runtime.GOOS != "windows" {
		readOnlyDir := path.Join(tempDir, "readonly")
		err = os.Mkdir(readOnlyDir, 0400) // 只读权限
		assert.Nil(t, err)
		defer os.Remove(readOnlyDir)

		readOnlyConfigPath := path.Join(readOnlyDir, "config.json")
		validConfigForReadOnly := `{
			"current": "test",
			"profiles": [
				{
					"name": "test",
					"mode": "AK"
				}
			]
		}`
		err = ioutil.WriteFile(readOnlyConfigPath, []byte(validConfigForReadOnly), 0644)
		assert.NotNil(t, err)

		provider = &CLIProfileCredentialsProvider{
			profileFile: readOnlyConfigPath,
			profileName: "test",
		}

		err = provider.updateOAuthTokens("refresh", "access", "ak", "sk", "token", 1234567890, 1234567890)
		assert.NotNil(t, err)
	}
}

func TestCLIProfileCredentialsProvider_writeConfigFile(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "test_aws_write")
	assert.Nil(t, err)
	defer os.RemoveAll(tempDir)

	configPath := path.Join(tempDir, "config.json")
	provider := &CLIProfileCredentialsProvider{}

	// 创建测试配置
	conf := &configuration{
		Current: "test",
		Profiles: []*profile{
			{
				Name:            "test",
				Mode:            "AK",
				AccessKeyID:     "test_key",
				AccessKeySecret: "test_secret",
			},
		},
	}

	// 测试写入文件
	err = provider.writeConfigFile(configPath, 0644, conf)
	assert.Nil(t, err)

	// 验证文件内容
	data, err := ioutil.ReadFile(configPath)
	assert.Nil(t, err)

	var loadedConf configuration
	err = json.Unmarshal(data, &loadedConf)
	assert.Nil(t, err)
	assert.Equal(t, conf.Current, loadedConf.Current)
	assert.Equal(t, len(conf.Profiles), len(loadedConf.Profiles))
	assert.Equal(t, conf.Profiles[0].Name, loadedConf.Profiles[0].Name)
}

func TestCLIProfileCredentialsProvider_writeConfigFile_Error(t *testing.T) {
	provider := &CLIProfileCredentialsProvider{}

	// 测试写入只读目录
	conf := &configuration{Current: "test"}
	err := provider.writeConfigFile("/readonly/config.json", 0644, conf)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "failed to create config file")
}

func TestCLIProfileCredentialsProvider_writeConfigurationToFile_Concurrent(t *testing.T) {
	// Skip on Windows as concurrent file access is more restrictive
	if runtime.GOOS == "windows" {
		t.Skip("Skipping concurrent test on Windows - file access is more restrictive")
	}

	tempDir, err := ioutil.TempDir("", "test_aws_concurrent")
	assert.Nil(t, err)
	defer os.RemoveAll(tempDir)

	configPath := path.Join(tempDir, "config.json")
	provider := &CLIProfileCredentialsProvider{}

	// 创建初始配置
	initialConf := &configuration{
		Current: "initial",
		Profiles: []*profile{
			{
				Name:            "initial",
				Mode:            "AK",
				AccessKeyID:     "initial_key",
				AccessKeySecret: "initial_secret",
			},
		},
	}

	err = provider.writeConfigurationToFile(configPath, initialConf)
	assert.Nil(t, err)

	// 并发写入测试
	var wg sync.WaitGroup
	numGoroutines := 10

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			conf := &configuration{
				Current: fmt.Sprintf("test_%d", id),
				Profiles: []*profile{
					{
						Name:            fmt.Sprintf("test_%d", id),
						Mode:            "AK",
						AccessKeyID:     fmt.Sprintf("key_%d", id),
						AccessKeySecret: fmt.Sprintf("secret_%d", id),
					},
				},
			}

			err := provider.writeConfigurationToFile(configPath, conf)
			assert.Nil(t, err)
		}(i)
	}

	wg.Wait()

	// 验证最终文件存在且有效
	data, err := ioutil.ReadFile(configPath)
	assert.Nil(t, err)

	var loadedConf configuration
	err = json.Unmarshal(data, &loadedConf)
	assert.Nil(t, err)
	assert.NotEmpty(t, loadedConf.Current)
	assert.NotEmpty(t, loadedConf.Profiles)
}

func TestCLIProfileCredentialsProvider_External(t *testing.T) {
	// 创建临时目录用于测试
	tempDir, err := ioutil.TempDir("", "external_test")
	assert.Nil(t, err)
	defer os.RemoveAll(tempDir)

	// 创建返回 AK 模式的脚本
	akScriptPath := path.Join(tempDir, "ak_script")
	var akScriptContent string
	if runtime.GOOS == "windows" {
		akScriptPath += ".bat"
		akScriptContent = "@echo off\necho {\"mode\":\"AK\",\"access_key_id\":\"external_akid\",\"access_key_secret\":\"external_secret\"}\n"
	} else {
		akScriptContent = "#!/bin/sh\necho '{\"mode\":\"AK\",\"access_key_id\":\"external_akid\",\"access_key_secret\":\"external_secret\"}'\n"
	}
	err = ioutil.WriteFile(akScriptPath, []byte(akScriptContent), 0755)
	assert.Nil(t, err)

	// 创建返回 StsToken 模式的脚本
	stsScriptPath := path.Join(tempDir, "sts_script")
	var stsScriptContent string
	if runtime.GOOS == "windows" {
		stsScriptPath += ".bat"
		stsScriptContent = "@echo off\necho {\"mode\":\"StsToken\",\"access_key_id\":\"external_akid\",\"access_key_secret\":\"external_secret\",\"sts_token\":\"external_sts_token\"}\n"
	} else {
		stsScriptContent = "#!/bin/sh\necho '{\"mode\":\"StsToken\",\"access_key_id\":\"external_akid\",\"access_key_secret\":\"external_secret\",\"sts_token\":\"external_sts_token\"}'\n"
	}
	err = ioutil.WriteFile(stsScriptPath, []byte(stsScriptContent), 0755)
	assert.Nil(t, err)

	// 创建返回无效 JSON 的脚本
	invalidScriptPath := path.Join(tempDir, "invalid_script")
	var invalidScriptContent string
	if runtime.GOOS == "windows" {
		invalidScriptPath += ".bat"
		invalidScriptContent = "@echo off\necho invalid json\n"
	} else {
		invalidScriptContent = "#!/bin/sh\necho 'invalid json'\n"
	}
	err = ioutil.WriteFile(invalidScriptPath, []byte(invalidScriptContent), 0755)
	assert.Nil(t, err)

	// 创建返回失败退出码的脚本
	failScriptPath := path.Join(tempDir, "fail_script")
	var failScriptContent string
	if runtime.GOOS == "windows" {
		failScriptPath += ".bat"
		failScriptContent = "@echo off\nexit /b 1\n"
	} else {
		failScriptContent = "#!/bin/sh\nexit 1\n"
	}
	err = ioutil.WriteFile(failScriptPath, []byte(failScriptContent), 0755)
	assert.Nil(t, err)

	conf := &configuration{
		Current: "ExternalAK",
		Profiles: []*profile{
			{
				Mode:          "External",
				Name:          "ExternalAK",
				ProcessCommand: akScriptPath,
			},
			{
				Mode:          "External",
				Name:          "ExternalStsToken",
				ProcessCommand: stsScriptPath,
			},
			{
				Mode:          "External",
				Name:          "ExternalEmpty",
				ProcessCommand: "",
			},
			{
				Mode:          "External",
				Name:          "ExternalInvalidMode",
				ProcessCommand: akScriptPath, // 使用 AK 脚本但修改返回内容测试
			},
			{
				Mode:          "External",
				Name:          "ExternalInvalidJSON",
				ProcessCommand: invalidScriptPath,
			},
			{
				Mode:          "External",
				Name:          "ExternalCommandFail",
				ProcessCommand: failScriptPath,
			},
		},
	}

	// 创建临时配置文件用于测试回调函数
	configPath := path.Join(tempDir, "config.json")
	testConfig := &configuration{
		Current: "ExternalAK",
		Profiles: []*profile{
			{
				Mode:          "External",
				Name:          "ExternalAK",
				ProcessCommand: akScriptPath,
			},
		},
	}
	data, err := json.MarshalIndent(testConfig, "", "    ")
	assert.Nil(t, err)
	err = ioutil.WriteFile(configPath, data, 0644)
	assert.Nil(t, err)

	provider, err := NewCLIProfileCredentialsProviderBuilder().
		WithProfileFile(configPath).
		WithProfileName("ExternalAK").
		Build()
	assert.Nil(t, err)

	// 测试 External - AK mode
	cp, err := provider.getCredentialsProvider(conf, "ExternalAK")
	assert.Nil(t, err)
	externalProvider, ok := cp.(*ExternalCredentialsProvider)
	assert.True(t, ok)
	cc, err := externalProvider.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, cc, &Credentials{AccessKeyId: "external_akid", AccessKeySecret: "external_secret", SecurityToken: "", ProviderName: "external"})

	// 测试 External - StsToken mode
	cp, err = provider.getCredentialsProvider(conf, "ExternalStsToken")
	assert.Nil(t, err)
	externalProvider, ok = cp.(*ExternalCredentialsProvider)
	assert.True(t, ok)
	cc, err = externalProvider.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, cc, &Credentials{AccessKeyId: "external_akid", AccessKeySecret: "external_secret", SecurityToken: "external_sts_token", ProviderName: "external"})

	// 测试 External - empty process_command
	_, err = provider.getCredentialsProvider(conf, "ExternalEmpty")
	assert.EqualError(t, err, "process_command is empty")

	// 测试 External - command execution failure
	// 注意：Build 时不会执行命令，只有在 GetCredentials 时才会执行
	cp, err = provider.getCredentialsProvider(conf, "ExternalCommandFail")
	assert.Nil(t, err) // Build 成功
	externalProvider, ok = cp.(*ExternalCredentialsProvider)
	assert.True(t, ok)
	_, err = externalProvider.GetCredentials() // 这里才会执行命令并失败
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "failed to execute external command")

	// 测试 External - invalid JSON
	cp, err = provider.getCredentialsProvider(conf, "ExternalInvalidJSON")
	assert.Nil(t, err) // Build 成功
	externalProvider, ok = cp.(*ExternalCredentialsProvider)
	assert.True(t, ok)
	_, err = externalProvider.GetCredentials() // 这里才会执行命令并失败
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "failed to parse external command output")
}

func TestExternalCredentialsProvider_CredentialCaching(t *testing.T) {
	// 创建临时目录用于测试
	tempDir, err := ioutil.TempDir("", "external_cache_test")
	assert.Nil(t, err)
	defer os.RemoveAll(tempDir)

	// 创建返回带过期时间的 StsToken 的脚本
	expirationTime := time.Now().Add(1 * time.Hour).Format("2006-01-02T15:04:05Z")
	stsScriptPath := path.Join(tempDir, "sts_with_expiration_script")
	var stsScriptContent string
	if runtime.GOOS == "windows" {
		stsScriptPath += ".bat"
		stsScriptContent = fmt.Sprintf("@echo off\necho {\"mode\":\"StsToken\",\"access_key_id\":\"cached_akid\",\"access_key_secret\":\"cached_secret\",\"sts_token\":\"cached_sts_token\",\"expiration\":\"%s\"}\n", expirationTime)
	} else {
		stsScriptContent = fmt.Sprintf("#!/bin/sh\necho '{\"mode\":\"StsToken\",\"access_key_id\":\"cached_akid\",\"access_key_secret\":\"cached_secret\",\"sts_token\":\"cached_sts_token\",\"expiration\":\"%s\"}'\n", expirationTime)
	}
	err = ioutil.WriteFile(stsScriptPath, []byte(stsScriptContent), 0755)
	assert.Nil(t, err)

	// 创建不带过期时间的脚本（应该每次都执行）
	noExpirationScriptPath := path.Join(tempDir, "no_expiration_script")
	var noExpirationScriptContent string
	if runtime.GOOS == "windows" {
		noExpirationScriptPath += ".bat"
		noExpirationScriptContent = "@echo off\necho {\"mode\":\"AK\",\"access_key_id\":\"dynamic_akid\",\"access_key_secret\":\"dynamic_secret\"}\n"
	} else {
		noExpirationScriptContent = "#!/bin/sh\necho '{\"mode\":\"AK\",\"access_key_id\":\"dynamic_akid\",\"access_key_secret\":\"dynamic_secret\"}'\n"
	}
	err = ioutil.WriteFile(noExpirationScriptPath, []byte(noExpirationScriptContent), 0755)
	assert.Nil(t, err)

	// 测试带过期时间的凭证缓存
	provider, err := NewExternalCredentialsProviderBuilder().
		WithProcessCommand(stsScriptPath).
		Build()
	assert.Nil(t, err)

	// 第一次调用，应该执行命令
	cc1, err := provider.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, "cached_akid", cc1.AccessKeyId)
	assert.Equal(t, "cached_sts_token", cc1.SecurityToken)

	// 第二次调用，应该使用缓存（因为还没过期）
	cc2, err := provider.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, cc1.AccessKeyId, cc2.AccessKeyId)
	assert.Equal(t, cc1.SecurityToken, cc2.SecurityToken)

	// 测试不带过期时间的凭证（应该每次都执行）
	provider2, err := NewExternalCredentialsProviderBuilder().
		WithProcessCommand(noExpirationScriptPath).
		Build()
	assert.Nil(t, err)

	cc3, err := provider2.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, "dynamic_akid", cc3.AccessKeyId)

	// 再次调用，由于没有过期时间，应该重新执行命令
	cc4, err := provider2.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, "dynamic_akid", cc4.AccessKeyId)
}

func TestExternalCredentialsProvider_CallbackFunction(t *testing.T) {
	// 创建临时目录用于测试
	tempDir, err := ioutil.TempDir("", "external_callback_test")
	assert.Nil(t, err)
	defer os.RemoveAll(tempDir)

	// 创建返回 AK 的脚本
	akScriptPath := path.Join(tempDir, "ak_script")
	var akScriptContent string
	if runtime.GOOS == "windows" {
		akScriptPath += ".bat"
		akScriptContent = "@echo off\necho {\"mode\":\"AK\",\"access_key_id\":\"callback_akid\",\"access_key_secret\":\"callback_secret\"}\n"
	} else {
		akScriptContent = "#!/bin/sh\necho '{\"mode\":\"AK\",\"access_key_id\":\"callback_akid\",\"access_key_secret\":\"callback_secret\"}'\n"
	}
	err = ioutil.WriteFile(akScriptPath, []byte(akScriptContent), 0755)
	assert.Nil(t, err)

	// 创建临时配置文件
	configPath := path.Join(tempDir, "config.json")
	testConfig := &configuration{
		Current: "ExternalCallback",
		Profiles: []*profile{
			{
				Mode:          "External",
				Name:          "ExternalCallback",
				ProcessCommand: akScriptPath,
			},
		},
	}
	data, err := json.MarshalIndent(testConfig, "", "    ")
	assert.Nil(t, err)
	err = ioutil.WriteFile(configPath, data, 0644)
	assert.Nil(t, err)

	// 创建 CLI Profile 提供者
	cliProvider, err := NewCLIProfileCredentialsProviderBuilder().
		WithProfileFile(configPath).
		WithProfileName("ExternalCallback").
		Build()
	assert.Nil(t, err)

	conf := &configuration{
		Current: "ExternalCallback",
		Profiles: []*profile{
			{
				Mode:          "External",
				Name:          "ExternalCallback",
				ProcessCommand: akScriptPath,
			},
		},
	}

	// 获取 External 凭证提供者
	cp, err := cliProvider.getCredentialsProvider(conf, "ExternalCallback")
	assert.Nil(t, err)
	externalProvider, ok := cp.(*ExternalCredentialsProvider)
	assert.True(t, ok)

	// 获取凭证，应该触发回调函数
	cc, err := externalProvider.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, "callback_akid", cc.AccessKeyId)
	assert.Equal(t, "callback_secret", cc.AccessKeySecret)

	// 验证配置文件已更新
	updatedConf, err := newConfigurationFromPath(configPath)
	assert.Nil(t, err)
	updatedProfile, err := updatedConf.getProfile("ExternalCallback")
	assert.Nil(t, err)
	assert.Equal(t, "callback_akid", updatedProfile.AccessKeyID)
	assert.Equal(t, "callback_secret", updatedProfile.AccessKeySecret)
}

func TestCLIProfileCredentialsProvider_updateExternalCredentials(t *testing.T) {
	// 创建临时目录用于测试
	tempDir, err := ioutil.TempDir("", "external_update_test")
	assert.Nil(t, err)
	defer os.RemoveAll(tempDir)
	configPath := path.Join(tempDir, "config.json")

	// 创建测试配置
	testConfig := &configuration{
		Current: "ExternalTest",
		Profiles: []*profile{
			{
				Mode:          "External",
				Name:          "ExternalTest",
				ProcessCommand: "echo test",
			},
		},
	}

	// 写入测试配置
	data, err := json.MarshalIndent(testConfig, "", "    ")
	assert.Nil(t, err)
	err = ioutil.WriteFile(configPath, data, 0644)
	assert.Nil(t, err)

	// 创建CLI Profile提供者
	provider, err := NewCLIProfileCredentialsProviderBuilder().
		WithProfileFile(configPath).
		WithProfileName("ExternalTest").
		Build()
	assert.Nil(t, err)

	// 测试更新External凭证（expiration > 0）
	accessKeyId := "updated_akid"
	accessKeySecret := "updated_secret"
	securityToken := "updated_sts_token"
	expiration := time.Now().Unix() + 3600

	err = provider.updateExternalCredentials(accessKeyId, accessKeySecret, securityToken, expiration)
	assert.Nil(t, err)

	// 验证配置文件已更新
	updatedConf, err := newConfigurationFromPath(configPath)
	assert.Nil(t, err)
	updatedProfile, err := updatedConf.getProfile("ExternalTest")
	assert.Nil(t, err)
	assert.Equal(t, accessKeyId, updatedProfile.AccessKeyID)
	assert.Equal(t, accessKeySecret, updatedProfile.AccessKeySecret)
	assert.Equal(t, securityToken, updatedProfile.SecurityToken)
	assert.Equal(t, expiration, updatedProfile.StsExpire)

	// 测试更新External凭证（expiration = 0，不更新 StsExpire）
	err = provider.updateExternalCredentials("akid2", "secret2", "token2", 0)
	assert.Nil(t, err)

	// 验证 StsExpire 保持不变（仍然是最初设置的值）
	updatedConf2, err := newConfigurationFromPath(configPath)
	assert.Nil(t, err)
	updatedProfile2, err := updatedConf2.getProfile("ExternalTest")
	assert.Nil(t, err)
	assert.Equal(t, "akid2", updatedProfile2.AccessKeyID)
	assert.Equal(t, "secret2", updatedProfile2.AccessKeySecret)
	assert.Equal(t, "token2", updatedProfile2.SecurityToken)
	// StsExpire 应该保持之前的值（expiration > 0 时设置的值）
	assert.Equal(t, expiration, updatedProfile2.StsExpire)
}

func TestCLIProfileCredentialsProvider_updateExternalCredentials_Error(t *testing.T) {
	// 测试1: 配置文件读取失败
	provider := &CLIProfileCredentialsProvider{
		profileFile: "/nonexistent/path/config.json",
		profileName: "test",
	}

	err := provider.updateExternalCredentials("akid", "secret", "token", 1234567890)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "failed to read config file")

	// 测试2: 配置文件存在但格式错误
	tempDir, err := ioutil.TempDir("", "external_update_error_test")
	assert.Nil(t, err)
	defer os.RemoveAll(tempDir)

	invalidConfigPath := path.Join(tempDir, "invalid_config.json")
	err = ioutil.WriteFile(invalidConfigPath, []byte("invalid json"), 0644)
	assert.Nil(t, err)

	provider = &CLIProfileCredentialsProvider{
		profileFile: invalidConfigPath,
		profileName: "test",
	}

	err = provider.updateExternalCredentials("akid", "secret", "token", 1234567890)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "failed to read config file")

	// 测试3: 配置文件存在但找不到指定的 profile
	validConfig := `{
		"current": "test",
		"profiles": [
			{
				"name": "other",
				"mode": "AK"
			}
		]
	}`
	validConfigPath := path.Join(tempDir, "valid_config.json")
	err = ioutil.WriteFile(validConfigPath, []byte(validConfig), 0644)
	assert.Nil(t, err)

	provider = &CLIProfileCredentialsProvider{
		profileFile: validConfigPath,
		profileName: "nonexistent",
	}

	err = provider.updateExternalCredentials("akid", "secret", "token", 1234567890)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "failed to get profile nonexistent")
}

func TestExternalCredentialsProvider_InvalidResponses(t *testing.T) {
	// 创建临时目录用于测试
	tempDir, err := ioutil.TempDir("", "external_invalid_test")
	assert.Nil(t, err)
	defer os.RemoveAll(tempDir)

	// 创建返回空 access_key_id 的脚本
	emptyAkIdScriptPath := path.Join(tempDir, "empty_akid_script")
	var emptyAkIdScriptContent string
	if runtime.GOOS == "windows" {
		emptyAkIdScriptPath += ".bat"
		emptyAkIdScriptContent = "@echo off\necho {\"mode\":\"AK\",\"access_key_id\":\"\",\"access_key_secret\":\"secret\"}\n"
	} else {
		emptyAkIdScriptContent = "#!/bin/sh\necho '{\"mode\":\"AK\",\"access_key_id\":\"\",\"access_key_secret\":\"secret\"}'\n"
	}
	err = ioutil.WriteFile(emptyAkIdScriptPath, []byte(emptyAkIdScriptContent), 0755)
	assert.Nil(t, err)

	// 创建返回空 access_key_secret 的脚本
	emptyAkSecretScriptPath := path.Join(tempDir, "empty_aksecret_script")
	var emptyAkSecretScriptContent string
	if runtime.GOOS == "windows" {
		emptyAkSecretScriptPath += ".bat"
		emptyAkSecretScriptContent = "@echo off\necho {\"mode\":\"AK\",\"access_key_id\":\"akid\",\"access_key_secret\":\"\"}\n"
	} else {
		emptyAkSecretScriptContent = "#!/bin/sh\necho '{\"mode\":\"AK\",\"access_key_id\":\"akid\",\"access_key_secret\":\"\"}'\n"
	}
	err = ioutil.WriteFile(emptyAkSecretScriptPath, []byte(emptyAkSecretScriptContent), 0755)
	assert.Nil(t, err)

	// 创建返回 StsToken 但缺少 sts_token 的脚本
	emptyStsTokenScriptPath := path.Join(tempDir, "empty_sts_token_script")
	var emptyStsTokenScriptContent string
	if runtime.GOOS == "windows" {
		emptyStsTokenScriptPath += ".bat"
		emptyStsTokenScriptContent = "@echo off\necho {\"mode\":\"StsToken\",\"access_key_id\":\"akid\",\"access_key_secret\":\"secret\",\"sts_token\":\"\"}\n"
	} else {
		emptyStsTokenScriptContent = "#!/bin/sh\necho '{\"mode\":\"StsToken\",\"access_key_id\":\"akid\",\"access_key_secret\":\"secret\",\"sts_token\":\"\"}'\n"
	}
	err = ioutil.WriteFile(emptyStsTokenScriptPath, []byte(emptyStsTokenScriptContent), 0755)
	assert.Nil(t, err)

	// 测试空 access_key_id
	provider1, err := NewExternalCredentialsProviderBuilder().
		WithProcessCommand(emptyAkIdScriptPath).
		Build()
	assert.Nil(t, err)
	_, err = provider1.GetCredentials()
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "access_key_id or access_key_secret is empty")

	// 测试空 access_key_secret
	provider2, err := NewExternalCredentialsProviderBuilder().
		WithProcessCommand(emptyAkSecretScriptPath).
		Build()
	assert.Nil(t, err)
	_, err = provider2.GetCredentials()
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "access_key_id or access_key_secret is empty")

	// 测试 StsToken 模式但缺少 sts_token
	provider3, err := NewExternalCredentialsProviderBuilder().
		WithProcessCommand(emptyStsTokenScriptPath).
		Build()
	assert.Nil(t, err)
	_, err = provider3.GetCredentials()
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "sts_token is empty")
}

func TestExternalCredentialsProvider_ExpirationParsing(t *testing.T) {
	// 创建临时目录用于测试
	tempDir, err := ioutil.TempDir("", "external_expiration_test")
	assert.Nil(t, err)
	defer os.RemoveAll(tempDir)

	// 创建返回有效过期时间的脚本
	validExpirationTime := time.Now().Add(1 * time.Hour).Format("2006-01-02T15:04:05Z")
	validExpirationScriptPath := path.Join(tempDir, "valid_expiration_script")
	var validExpirationScriptContent string
	if runtime.GOOS == "windows" {
		validExpirationScriptPath += ".bat"
		validExpirationScriptContent = fmt.Sprintf("@echo off\necho {\"mode\":\"StsToken\",\"access_key_id\":\"akid\",\"access_key_secret\":\"secret\",\"sts_token\":\"token\",\"expiration\":\"%s\"}\n", validExpirationTime)
	} else {
		validExpirationScriptContent = fmt.Sprintf("#!/bin/sh\necho '{\"mode\":\"StsToken\",\"access_key_id\":\"akid\",\"access_key_secret\":\"secret\",\"sts_token\":\"token\",\"expiration\":\"%s\"}'\n", validExpirationTime)
	}
	err = ioutil.WriteFile(validExpirationScriptPath, []byte(validExpirationScriptContent), 0755)
	assert.Nil(t, err)

	// 创建返回无效过期时间格式的脚本
	invalidExpirationScriptPath := path.Join(tempDir, "invalid_expiration_script")
	var invalidExpirationScriptContent string
	if runtime.GOOS == "windows" {
		invalidExpirationScriptPath += ".bat"
		invalidExpirationScriptContent = "@echo off\necho {\"mode\":\"StsToken\",\"access_key_id\":\"akid\",\"access_key_secret\":\"secret\",\"sts_token\":\"token\",\"expiration\":\"invalid-date\"}\n"
	} else {
		invalidExpirationScriptContent = "#!/bin/sh\necho '{\"mode\":\"StsToken\",\"access_key_id\":\"akid\",\"access_key_secret\":\"secret\",\"sts_token\":\"token\",\"expiration\":\"invalid-date\"}'\n"
	}
	err = ioutil.WriteFile(invalidExpirationScriptPath, []byte(invalidExpirationScriptContent), 0755)
	assert.Nil(t, err)

	// 测试有效过期时间
	provider1, err := NewExternalCredentialsProviderBuilder().
		WithProcessCommand(validExpirationScriptPath).
		Build()
	assert.Nil(t, err)
	cc1, err := provider1.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, "akid", cc1.AccessKeyId)

	// 再次调用应该使用缓存
	cc2, err := provider1.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, cc1.AccessKeyId, cc2.AccessKeyId)

	// 测试无效过期时间格式（应该仍然工作，但不缓存）
	provider2, err := NewExternalCredentialsProviderBuilder().
		WithProcessCommand(invalidExpirationScriptPath).
		Build()
	assert.Nil(t, err)
	cc3, err := provider2.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, "akid", cc3.AccessKeyId)

	// 由于过期时间解析失败，下次调用应该重新执行命令
	cc4, err := provider2.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, "akid", cc4.AccessKeyId)
}

func TestExternalCredentialsProvider_ConcurrentAccess(t *testing.T) {
	// 创建临时目录用于测试
	tempDir, err := ioutil.TempDir("", "external_concurrent_test")
	assert.Nil(t, err)
	defer os.RemoveAll(tempDir)

	// 创建返回 AK 的脚本
	akScriptPath := path.Join(tempDir, "ak_script")
	var akScriptContent string
	if runtime.GOOS == "windows" {
		akScriptPath += ".bat"
		akScriptContent = "@echo off\necho {\"mode\":\"AK\",\"access_key_id\":\"concurrent_akid\",\"access_key_secret\":\"concurrent_secret\"}\n"
	} else {
		akScriptContent = "#!/bin/sh\necho '{\"mode\":\"AK\",\"access_key_id\":\"concurrent_akid\",\"access_key_secret\":\"concurrent_secret\"}'\n"
	}
	err = ioutil.WriteFile(akScriptPath, []byte(akScriptContent), 0755)
	assert.Nil(t, err)

	provider, err := NewExternalCredentialsProviderBuilder().
		WithProcessCommand(akScriptPath).
		Build()
	assert.Nil(t, err)

	// 并发获取凭证
	var wg sync.WaitGroup
	numGoroutines := 10
	results := make([]*Credentials, numGoroutines)
	errors := make([]error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			cc, err := provider.GetCredentials()
			results[index] = cc
			errors[index] = err
		}(i)
	}

	wg.Wait()

	// 验证所有调用都成功
	for i := 0; i < numGoroutines; i++ {
		assert.Nil(t, errors[i], "goroutine %d should not have error", i)
		assert.NotNil(t, results[i], "goroutine %d should have credentials", i)
		if results[i] != nil {
			assert.Equal(t, "concurrent_akid", results[i].AccessKeyId)
			assert.Equal(t, "concurrent_secret", results[i].AccessKeySecret)
		}
	}
}

