package providers

import (
	"errors"
	"io/ioutil"
	"os"
	"path"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewExternalCredentialsProviderBuilder(t *testing.T) {
	// 测试空 process_command
	_, err := NewExternalCredentialsProviderBuilder().Build()
	assert.NotNil(t, err)
	assert.EqualError(t, err, "process_command is empty")

	// 测试正常构建
	tempDir, err := ioutil.TempDir("", "external_builder_test")
	assert.Nil(t, err)
	defer os.RemoveAll(tempDir)

	scriptPath := path.Join(tempDir, "test_script")
	var scriptContent string
	if runtime.GOOS == "windows" {
		scriptPath += ".bat"
		scriptContent = "@echo off\necho {\"mode\":\"AK\",\"access_key_id\":\"akid\",\"access_key_secret\":\"secret\"}\n"
	} else {
		scriptContent = "#!/bin/sh\necho '{\"mode\":\"AK\",\"access_key_id\":\"akid\",\"access_key_secret\":\"secret\"}'\n"
	}
	err = ioutil.WriteFile(scriptPath, []byte(scriptContent), 0755)
	assert.Nil(t, err)

	provider, err := NewExternalCredentialsProviderBuilder().
		WithProcessCommand(scriptPath).
		Build()
	assert.Nil(t, err)
	assert.NotNil(t, provider)
	assert.Equal(t, scriptPath, provider.processCommand)
}

func TestExternalCredentialsProvider_WithProcessCommand(t *testing.T) {
	builder := NewExternalCredentialsProviderBuilder()
	builder.WithProcessCommand("test_command")
	assert.Equal(t, "test_command", builder.provider.processCommand)
}

func TestExternalCredentialsProvider_WithCredentialUpdateCallback(t *testing.T) {
	builder := NewExternalCredentialsProviderBuilder()
	callbackCalled := false
	callback := func(accessKeyId, accessKeySecret, securityToken string, expiration int64) error {
		callbackCalled = true
		return nil
	}
	builder.WithCredentialUpdateCallback(callback)
	assert.NotNil(t, builder.provider.credentialUpdateCallback)
	
	// 测试回调函数被调用
	err := builder.provider.credentialUpdateCallback("akid", "secret", "token", 1234567890)
	assert.Nil(t, err)
	assert.True(t, callbackCalled)
}

func TestExternalCredentialsProvider_getCredentials(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "external_get_credentials_test")
	assert.Nil(t, err)
	defer os.RemoveAll(tempDir)

	// 测试成功获取 AK 凭证
	akScriptPath := path.Join(tempDir, "ak_script")
	var akScriptContent string
	if runtime.GOOS == "windows" {
		akScriptPath += ".bat"
		akScriptContent = "@echo off\necho {\"mode\":\"AK\",\"access_key_id\":\"akid\",\"access_key_secret\":\"secret\"}\n"
	} else {
		akScriptContent = "#!/bin/sh\necho '{\"mode\":\"AK\",\"access_key_id\":\"akid\",\"access_key_secret\":\"secret\"}'\n"
	}
	err = ioutil.WriteFile(akScriptPath, []byte(akScriptContent), 0755)
	assert.Nil(t, err)

	provider := &ExternalCredentialsProvider{
		processCommand: akScriptPath,
	}

	session, err := provider.getCredentials()
	assert.Nil(t, err)
	assert.NotNil(t, session)
	assert.Equal(t, "akid", session.AccessKeyId)
	assert.Equal(t, "secret", session.AccessKeySecret)
	assert.Equal(t, "", session.SecurityToken)
	assert.Equal(t, "", session.Expiration)

	// 测试成功获取 StsToken 凭证
	stsScriptPath := path.Join(tempDir, "sts_script")
	var stsScriptContent string
	if runtime.GOOS == "windows" {
		stsScriptPath += ".bat"
		stsScriptContent = "@echo off\necho {\"mode\":\"StsToken\",\"access_key_id\":\"akid\",\"access_key_secret\":\"secret\",\"sts_token\":\"stoken\"}\n"
	} else {
		stsScriptContent = "#!/bin/sh\necho '{\"mode\":\"StsToken\",\"access_key_id\":\"akid\",\"access_key_secret\":\"secret\",\"sts_token\":\"stoken\"}'\n"
	}
	err = ioutil.WriteFile(stsScriptPath, []byte(stsScriptContent), 0755)
	assert.Nil(t, err)

	provider.processCommand = stsScriptPath
	session, err = provider.getCredentials()
	assert.Nil(t, err)
	assert.NotNil(t, session)
	assert.Equal(t, "akid", session.AccessKeyId)
	assert.Equal(t, "secret", session.AccessKeySecret)
	assert.Equal(t, "stoken", session.SecurityToken)

	// 测试带过期时间的凭证
	expirationTime := time.Now().Add(1 * time.Hour).Format("2006-01-02T15:04:05Z")
	expirationScriptPath := path.Join(tempDir, "expiration_script")
	var expirationScriptContent string
	if runtime.GOOS == "windows" {
		expirationScriptPath += ".bat"
		expirationScriptContent = "@echo off\necho {\"mode\":\"StsToken\",\"access_key_id\":\"akid\",\"access_key_secret\":\"secret\",\"sts_token\":\"stoken\",\"expiration\":\"" + expirationTime + "\"}\n"
	} else {
		expirationScriptContent = "#!/bin/sh\necho '{\"mode\":\"StsToken\",\"access_key_id\":\"akid\",\"access_key_secret\":\"secret\",\"sts_token\":\"stoken\",\"expiration\":\"" + expirationTime + "\"}'\n"
	}
	err = ioutil.WriteFile(expirationScriptPath, []byte(expirationScriptContent), 0755)
	assert.Nil(t, err)

	provider.processCommand = expirationScriptPath
	session, err = provider.getCredentials()
	assert.Nil(t, err)
	assert.NotNil(t, session)
	assert.Equal(t, expirationTime, session.Expiration)
}

func TestExternalCredentialsProvider_getCredentials_Errors(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "external_get_credentials_errors_test")
	assert.Nil(t, err)
	defer os.RemoveAll(tempDir)

	provider := &ExternalCredentialsProvider{}

	// 测试空 process_command
	provider.processCommand = ""
	_, err = provider.getCredentials()
	assert.NotNil(t, err)
	assert.EqualError(t, err, "process_command is empty")

	// 测试命令执行失败
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

	provider.processCommand = failScriptPath
	_, err = provider.getCredentials()
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "failed to execute external command")

	// 测试无效 JSON
	invalidJsonScriptPath := path.Join(tempDir, "invalid_json_script")
	var invalidJsonScriptContent string
	if runtime.GOOS == "windows" {
		invalidJsonScriptPath += ".bat"
		invalidJsonScriptContent = "@echo off\necho invalid json\n"
	} else {
		invalidJsonScriptContent = "#!/bin/sh\necho 'invalid json'\n"
	}
	err = ioutil.WriteFile(invalidJsonScriptPath, []byte(invalidJsonScriptContent), 0755)
	assert.Nil(t, err)

	provider.processCommand = invalidJsonScriptPath
	_, err = provider.getCredentials()
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "failed to parse external command output")

	// 测试空 access_key_id
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

	provider.processCommand = emptyAkIdScriptPath
	_, err = provider.getCredentials()
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "access_key_id or access_key_secret is empty")

	// 测试空 access_key_secret
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

	provider.processCommand = emptyAkSecretScriptPath
	_, err = provider.getCredentials()
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "access_key_id or access_key_secret is empty")

	// 测试 StsToken 模式但缺少 sts_token
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

	provider.processCommand = emptyStsTokenScriptPath
	_, err = provider.getCredentials()
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "sts_token is empty")
}

func TestExternalCredentialsProvider_needUpdateCredential(t *testing.T) {
	provider := &ExternalCredentialsProvider{}

	// 测试没有缓存凭证
	assert.True(t, provider.needUpdateCredential())

	// 测试有缓存凭证但没有过期时间
	provider.sessionCredentials = &sessionCredentials{
		AccessKeyId:     "akid",
		AccessKeySecret: "secret",
	}
	provider.expirationTimestamp = 0
	assert.True(t, provider.needUpdateCredential())

	// 测试有缓存凭证且未过期
	provider.expirationTimestamp = time.Now().Unix() + 300 // 5分钟后过期
	assert.False(t, provider.needUpdateCredential())

	// 测试有缓存凭证但即将过期（提前180秒）
	provider.expirationTimestamp = time.Now().Unix() + 100 // 100秒后过期
	assert.True(t, provider.needUpdateCredential())

	// 测试有缓存凭证但已过期
	provider.expirationTimestamp = time.Now().Unix() - 100 // 100秒前已过期
	assert.True(t, provider.needUpdateCredential())
}

func TestExternalCredentialsProvider_GetCredentials(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "external_get_credentials_test")
	assert.Nil(t, err)
	defer os.RemoveAll(tempDir)

	// 测试获取 AK 凭证
	akScriptPath := path.Join(tempDir, "ak_script")
	var akScriptContent string
	if runtime.GOOS == "windows" {
		akScriptPath += ".bat"
		akScriptContent = "@echo off\necho {\"mode\":\"AK\",\"access_key_id\":\"akid\",\"access_key_secret\":\"secret\"}\n"
	} else {
		akScriptContent = "#!/bin/sh\necho '{\"mode\":\"AK\",\"access_key_id\":\"akid\",\"access_key_secret\":\"secret\"}'\n"
	}
	err = ioutil.WriteFile(akScriptPath, []byte(akScriptContent), 0755)
	assert.Nil(t, err)

	provider, err := NewExternalCredentialsProviderBuilder().
		WithProcessCommand(akScriptPath).
		Build()
	assert.Nil(t, err)

	cc, err := provider.GetCredentials()
	assert.Nil(t, err)
	assert.NotNil(t, cc)
	assert.Equal(t, "akid", cc.AccessKeyId)
	assert.Equal(t, "secret", cc.AccessKeySecret)
	assert.Equal(t, "", cc.SecurityToken)
	assert.Equal(t, "external", cc.ProviderName)

	// 测试获取 StsToken 凭证
	stsScriptPath := path.Join(tempDir, "sts_script")
	var stsScriptContent string
	if runtime.GOOS == "windows" {
		stsScriptPath += ".bat"
		stsScriptContent = "@echo off\necho {\"mode\":\"StsToken\",\"access_key_id\":\"akid\",\"access_key_secret\":\"secret\",\"sts_token\":\"stoken\"}\n"
	} else {
		stsScriptContent = "#!/bin/sh\necho '{\"mode\":\"StsToken\",\"access_key_id\":\"akid\",\"access_key_secret\":\"secret\",\"sts_token\":\"stoken\"}'\n"
	}
	err = ioutil.WriteFile(stsScriptPath, []byte(stsScriptContent), 0755)
	assert.Nil(t, err)

	provider2, err := NewExternalCredentialsProviderBuilder().
		WithProcessCommand(stsScriptPath).
		Build()
	assert.Nil(t, err)

	cc2, err := provider2.GetCredentials()
	assert.Nil(t, err)
	assert.NotNil(t, cc2)
	assert.Equal(t, "akid", cc2.AccessKeyId)
	assert.Equal(t, "secret", cc2.AccessKeySecret)
	assert.Equal(t, "stoken", cc2.SecurityToken)
	assert.Equal(t, "external", cc2.ProviderName)
}

func TestExternalCredentialsProvider_GetCredentials_WithExpiration(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "external_expiration_test")
	assert.Nil(t, err)
	defer os.RemoveAll(tempDir)

	// 测试带过期时间的凭证缓存
	expirationTime := time.Now().Add(1 * time.Hour).Format("2006-01-02T15:04:05Z")
	expirationScriptPath := path.Join(tempDir, "expiration_script")
	var expirationScriptContent string
	if runtime.GOOS == "windows" {
		expirationScriptPath += ".bat"
		expirationScriptContent = "@echo off\necho {\"mode\":\"StsToken\",\"access_key_id\":\"akid\",\"access_key_secret\":\"secret\",\"sts_token\":\"stoken\",\"expiration\":\"" + expirationTime + "\"}\n"
	} else {
		expirationScriptContent = "#!/bin/sh\necho '{\"mode\":\"StsToken\",\"access_key_id\":\"akid\",\"access_key_secret\":\"secret\",\"sts_token\":\"stoken\",\"expiration\":\"" + expirationTime + "\"}'\n"
	}
	err = ioutil.WriteFile(expirationScriptPath, []byte(expirationScriptContent), 0755)
	assert.Nil(t, err)

	provider, err := NewExternalCredentialsProviderBuilder().
		WithProcessCommand(expirationScriptPath).
		Build()
	assert.Nil(t, err)

	// 第一次调用，应该执行命令
	cc1, err := provider.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, "akid", cc1.AccessKeyId)

	// 第二次调用，应该使用缓存（因为还没过期）
	cc2, err := provider.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, cc1.AccessKeyId, cc2.AccessKeyId)
	assert.Equal(t, cc1.SecurityToken, cc2.SecurityToken)

	// 验证过期时间被正确设置
	assert.True(t, provider.expirationTimestamp > 0)
	assert.True(t, provider.lastUpdateTimestamp > 0)
}

func TestExternalCredentialsProvider_GetCredentials_WithInvalidExpiration(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "external_invalid_expiration_test")
	assert.Nil(t, err)
	defer os.RemoveAll(tempDir)

	// 测试无效过期时间格式（应该仍然工作，但不缓存）
	invalidExpirationScriptPath := path.Join(tempDir, "invalid_expiration_script")
	var invalidExpirationScriptContent string
	if runtime.GOOS == "windows" {
		invalidExpirationScriptPath += ".bat"
		invalidExpirationScriptContent = "@echo off\necho {\"mode\":\"AK\",\"access_key_id\":\"akid\",\"access_key_secret\":\"secret\",\"expiration\":\"invalid-date\"}\n"
	} else {
		invalidExpirationScriptContent = "#!/bin/sh\necho '{\"mode\":\"AK\",\"access_key_id\":\"akid\",\"access_key_secret\":\"secret\",\"expiration\":\"invalid-date\"}'\n"
	}
	err = ioutil.WriteFile(invalidExpirationScriptPath, []byte(invalidExpirationScriptContent), 0755)
	assert.Nil(t, err)

	provider, err := NewExternalCredentialsProviderBuilder().
		WithProcessCommand(invalidExpirationScriptPath).
		Build()
	assert.Nil(t, err)

	// 第一次调用，应该执行命令
	cc1, err := provider.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, "akid", cc1.AccessKeyId)

	// 由于过期时间解析失败，过期时间应该为0
	assert.Equal(t, int64(0), provider.expirationTimestamp)

	// 第二次调用，由于没有过期时间，应该重新执行命令
	cc2, err := provider.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, "akid", cc2.AccessKeyId)
}

func TestExternalCredentialsProvider_GetCredentials_WithCallback(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "external_callback_test")
	assert.Nil(t, err)
	defer os.RemoveAll(tempDir)

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

	callbackCalled := false
	var callbackAccessKeyId, callbackAccessKeySecret, callbackSecurityToken string
	var callbackExpiration int64

	callback := func(accessKeyId, accessKeySecret, securityToken string, expiration int64) error {
		callbackCalled = true
		callbackAccessKeyId = accessKeyId
		callbackAccessKeySecret = accessKeySecret
		callbackSecurityToken = securityToken
		callbackExpiration = expiration
		return nil
	}

	provider, err := NewExternalCredentialsProviderBuilder().
		WithProcessCommand(akScriptPath).
		WithCredentialUpdateCallback(callback).
		Build()
	assert.Nil(t, err)

	cc, err := provider.GetCredentials()
	assert.Nil(t, err)
	assert.NotNil(t, cc)

	// 验证回调函数被调用
	assert.True(t, callbackCalled)
	assert.Equal(t, "callback_akid", callbackAccessKeyId)
	assert.Equal(t, "callback_secret", callbackAccessKeySecret)
	assert.Equal(t, "", callbackSecurityToken)
	assert.Equal(t, int64(0), callbackExpiration)
}

func TestExternalCredentialsProvider_GetCredentials_WithCallbackError(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "external_callback_error_test")
	assert.Nil(t, err)
	defer os.RemoveAll(tempDir)

	akScriptPath := path.Join(tempDir, "ak_script")
	var akScriptContent string
	if runtime.GOOS == "windows" {
		akScriptPath += ".bat"
		akScriptContent = "@echo off\necho {\"mode\":\"AK\",\"access_key_id\":\"akid\",\"access_key_secret\":\"secret\"}\n"
	} else {
		akScriptContent = "#!/bin/sh\necho '{\"mode\":\"AK\",\"access_key_id\":\"akid\",\"access_key_secret\":\"secret\"}'\n"
	}
	err = ioutil.WriteFile(akScriptPath, []byte(akScriptContent), 0755)
	assert.Nil(t, err)

	callbackError := errors.New("callback error")
	callback := func(accessKeyId, accessKeySecret, securityToken string, expiration int64) error {
		return callbackError
	}

	provider, err := NewExternalCredentialsProviderBuilder().
		WithProcessCommand(akScriptPath).
		WithCredentialUpdateCallback(callback).
		Build()
	assert.Nil(t, err)

	// 即使回调函数返回错误，GetCredentials 仍然应该成功
	cc, err := provider.GetCredentials()
	assert.Nil(t, err)
	assert.NotNil(t, cc)
	assert.Equal(t, "akid", cc.AccessKeyId)
}

func TestExternalCredentialsProvider_GetCredentials_NoExpiration(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "external_no_expiration_test")
	assert.Nil(t, err)
	defer os.RemoveAll(tempDir)

	// 测试不带过期时间的凭证（应该每次都执行）
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

	provider, err := NewExternalCredentialsProviderBuilder().
		WithProcessCommand(noExpirationScriptPath).
		Build()
	assert.Nil(t, err)

	// 第一次调用
	cc1, err := provider.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, "dynamic_akid", cc1.AccessKeyId)

	// 验证过期时间为0
	assert.Equal(t, int64(0), provider.expirationTimestamp)

	// 第二次调用，由于没有过期时间，应该重新执行命令
	cc2, err := provider.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, "dynamic_akid", cc2.AccessKeyId)
}

func TestExternalCredentialsProvider_GetCredentials_Concurrent(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "external_concurrent_test")
	assert.Nil(t, err)
	defer os.RemoveAll(tempDir)

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

func TestExternalCredentialsProvider_GetProviderName(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "external_provider_name_test")
	assert.Nil(t, err)
	defer os.RemoveAll(tempDir)

	akScriptPath := path.Join(tempDir, "ak_script")
	var akScriptContent string
	if runtime.GOOS == "windows" {
		akScriptPath += ".bat"
		akScriptContent = "@echo off\necho {\"mode\":\"AK\",\"access_key_id\":\"akid\",\"access_key_secret\":\"secret\"}\n"
	} else {
		akScriptContent = "#!/bin/sh\necho '{\"mode\":\"AK\",\"access_key_id\":\"akid\",\"access_key_secret\":\"secret\"}'\n"
	}
	err = ioutil.WriteFile(akScriptPath, []byte(akScriptContent), 0755)
	assert.Nil(t, err)

	provider, err := NewExternalCredentialsProviderBuilder().
		WithProcessCommand(akScriptPath).
		Build()
	assert.Nil(t, err)

	assert.Equal(t, "external", provider.GetProviderName())

	cc, err := provider.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, "external", cc.ProviderName)
}

func TestExternalCredentialsProvider_CommandWithArguments(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "external_args_test")
	assert.Nil(t, err)
	defer os.RemoveAll(tempDir)

	// 测试带参数的命令
	scriptPath := path.Join(tempDir, "script_with_args")
	var scriptContent string
	if runtime.GOOS == "windows" {
		scriptPath += ".bat"
		scriptContent = "@echo off\necho {\"mode\":\"AK\",\"access_key_id\":\"akid\",\"access_key_secret\":\"secret\"}\n"
	} else {
		scriptContent = "#!/bin/sh\necho '{\"mode\":\"AK\",\"access_key_id\":\"akid\",\"access_key_secret\":\"secret\"}'\n"
	}
	err = ioutil.WriteFile(scriptPath, []byte(scriptContent), 0755)
	assert.Nil(t, err)

	// 测试带参数的命令（虽然这个脚本不需要参数，但可以测试参数传递）
	provider, err := NewExternalCredentialsProviderBuilder().
		WithProcessCommand(scriptPath + " arg1 arg2").
		Build()
	assert.Nil(t, err)

	cc, err := provider.GetCredentials()
	assert.Nil(t, err)
	assert.NotNil(t, cc)
	assert.Equal(t, "akid", cc.AccessKeyId)
}

func TestExternalCredentialsProvider_EmptyCommand(t *testing.T) {
	provider := &ExternalCredentialsProvider{
		processCommand: "",
	}

	_, err := provider.getCredentials()
	assert.NotNil(t, err)
	assert.EqualError(t, err, "process_command is empty")
}

