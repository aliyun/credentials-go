package integeration

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/alibabacloud-go/tea/tea"
	"github.com/aliyun/credentials-go/credentials"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	EnvVarSubAccessKeyId        = "SUB_ALICLOUD_ACCESS_KEY"
	EnvVarSubAccessKeySecret    = "SUB_ALICLOUD_SECRET_KEY"
	EnvVarRoleArn               = "ALICLOUD_ROLE_ARN"
	EnvVarRoleSessionName       = "ALICLOUD_ROLE_SESSION_NAME"
	EnvVarRoleSessionExpiration = "ALICLOUD_ROLE_SESSION_EXPIRATION"
)

func TestRAMRoleArn(t *testing.T) {
	rawexpiration := os.Getenv(EnvVarRoleSessionExpiration)
	expiration := 0
	if rawexpiration != "" {
		expiration, _ = strconv.Atoi(rawexpiration)
	}
	// assume role fisrt time
	config := &credentials.Config{
		Type:                  tea.String("ram_role_arn"),
		AccessKeyId:           tea.String(os.Getenv(EnvVarSubAccessKeyId)),
		AccessKeySecret:       tea.String(os.Getenv(EnvVarSubAccessKeySecret)),
		RoleArn:               tea.String(os.Getenv(EnvVarRoleArn)),
		RoleSessionName:       tea.String(os.Getenv(EnvVarRoleSessionName)),
		RoleSessionExpiration: tea.Int(expiration),
	}
	cred, err := credentials.NewCredential(config)
	assert.Nil(t, err)
	assert.NotNil(t, cred)
	c, err := cred.GetCredential()
	assert.Nil(t, err)
	assert.NotNil(t, c.AccessKeyId)
	assert.NotNil(t, c.AccessKeySecret)
	assert.NotNil(t, c.SecurityToken)

	// asume role second time with pre sts
	config2 := &credentials.Config{
		Type:                  tea.String("ram_role_arn"),
		AccessKeyId:           c.AccessKeyId,
		AccessKeySecret:       c.AccessKeySecret,
		SecurityToken:         c.SecurityToken,
		RoleArn:               tea.String(os.Getenv(EnvVarRoleArn)),
		RoleSessionName:       tea.String(os.Getenv(EnvVarRoleSessionName)),
		RoleSessionExpiration: tea.Int(expiration),
	}
	cred2, err := credentials.NewCredential(config2)
	assert.Nil(t, err)
	assert.NotNil(t, cred2)
	c2, err := cred.GetCredential()
	assert.Nil(t, err)
	assert.NotNil(t, c2.AccessKeyId)
	assert.NotNil(t, c2.AccessKeySecret)
	assert.NotNil(t, c2.SecurityToken)
}

func TestOidc(t *testing.T) {
	requireOIDCIntegration(t)

	config := &credentials.Config{
		Type:              tea.String("oidc_role_arn"),
		RoleArn:           tea.String(os.Getenv("ALIBABA_CLOUD_ROLE_ARN")),
		OIDCProviderArn:   tea.String(os.Getenv("ALIBABA_CLOUD_OIDC_PROVIDER_ARN")),
		OIDCTokenFilePath: tea.String(os.Getenv("ALIBABA_CLOUD_OIDC_TOKEN_FILE")),
		RoleSessionName:   tea.String("credentials-go-test"),
	}
	cred, err := credentials.NewCredential(config)
	require.NoError(t, err)
	require.NotNil(t, cred)
	c, err := cred.GetCredential()
	skipIfOIDCProviderFingerprintMismatch(t, err)
	require.NoError(t, err)
	require.NotNil(t, c)
	assert.NotNil(t, c.AccessKeyId)
	assert.NotNil(t, c.AccessKeySecret)
	assert.NotNil(t, c.SecurityToken)
	assert.Equal(t, "oidc_role_arn", *c.Type)
	assert.Equal(t, "oidc_role_arn", *c.ProviderName)
}

func TestDefaultProvider(t *testing.T) {
	requireOIDCIntegration(t)

	restoreEnv := setEnvForTest(map[string]string{
		"ALIBABA_CLOUD_ACCESS_KEY_ID":         "",
		"ALIBABA_CLOUD_ACCESS_KEY_SECRET":     "",
		"ALIBABA_CLOUD_SECURITY_TOKEN":        "",
		"ALIBABA_CLOUD_CLI_PROFILE_DISABLED":  "true",
		"ALIBABA_CLOUD_CONFIG_FILE":           filepath.Join(os.TempDir(), "credentials-go-missing-cli-config.json"),
		"ALIBABA_CLOUD_CREDENTIALS_FILE":      filepath.Join(os.TempDir(), "credentials-go-missing-shared-credentials"),
		"ALIBABA_CLOUD_ECS_METADATA_DISABLED": "true",
	})
	defer restoreEnv()

	cred, err := credentials.NewCredential(nil)
	require.NoError(t, err)
	require.NotNil(t, cred)
	c, err := cred.GetCredential()
	skipIfOIDCProviderFingerprintMismatch(t, err)
	require.NoError(t, err)
	require.NotNil(t, c)
	assert.NotNil(t, c.AccessKeyId)
	assert.NotNil(t, c.AccessKeySecret)
	assert.NotNil(t, c.SecurityToken)
	assert.Equal(t, "default", *c.Type)
	assert.Equal(t, "default/oidc_role_arn", *c.ProviderName)
}

func requireOIDCIntegration(t *testing.T) {
	t.Helper()

	required := []string{
		"ALIBABA_CLOUD_ROLE_ARN",
		"ALIBABA_CLOUD_OIDC_PROVIDER_ARN",
		"ALIBABA_CLOUD_OIDC_TOKEN_FILE",
	}
	for _, env := range required {
		if os.Getenv(env) == "" {
			t.Skipf("skip OIDC integration test: %s is not set", env)
		}
	}

	if _, err := os.Stat(os.Getenv("ALIBABA_CLOUD_OIDC_TOKEN_FILE")); err != nil {
		t.Skipf("skip OIDC integration test: OIDC token file is not available: %v", err)
	}
}

func skipIfOIDCProviderFingerprintMismatch(t *testing.T, err error) {
	t.Helper()

	if err != nil && strings.Contains(err.Error(), "AuthenticationFail.OIDCToken.PublicKeyFingerprintMismatch") {
		t.Skipf("skip OIDC integration test: configured OIDC provider discovery fingerprint is invalid: %v", err)
	}
}

func setEnvForTest(envs map[string]string) func() {
	type envValue struct {
		value string
		ok    bool
	}

	original := make(map[string]envValue, len(envs))
	for key, value := range envs {
		oldValue, ok := os.LookupEnv(key)
		original[key] = envValue{
			value: oldValue,
			ok:    ok,
		}
		os.Setenv(key, value)
	}

	return func() {
		for key, old := range original {
			if old.ok {
				os.Setenv(key, old.value)
			} else {
				os.Unsetenv(key)
			}
		}
	}
}
