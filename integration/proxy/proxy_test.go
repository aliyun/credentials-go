package proxy

import (
	"os"
	"testing"

	"github.com/alibabacloud-go/tea/tea"
	"github.com/aliyun/credentials-go/credentials"
	"github.com/stretchr/testify/assert"
)

func TestRAMRoleARNWithInvalidProxy(t *testing.T) {
	config := &credentials.Config{
		Type:                  tea.String("ram_role_arn"),
		AccessKeyId:           tea.String("akid"),
		AccessKeySecret:       tea.String("aksecret"),
		RoleArn:               tea.String("rolearn"),
		RoleSessionName:       tea.String("rolesessionname"),
		RoleSessionExpiration: tea.Int(3600),
		Proxy:                 tea.String("https://localhost:3600/"),
	}
	cred, err := credentials.NewCredential(config)
	assert.Nil(t, err)
	_, err = cred.GetCredential()
	assert.Contains(t, err.Error(), "proxyconnect tcp: dial tcp")
	assert.Contains(t, err.Error(), ":3600: connect: connection refused")
}

func TestOIDCWithInvalidProxy(t *testing.T) {
	config := &credentials.Config{
		Type:              tea.String("oidc_role_arn"),
		RoleArn:           tea.String(os.Getenv("ALIBABA_CLOUD_ROLE_ARN")),
		OIDCProviderArn:   tea.String(os.Getenv("ALIBABA_CLOUD_OIDC_PROVIDER_ARN")),
		OIDCTokenFilePath: tea.String(os.Getenv("ALIBABA_CLOUD_OIDC_TOKEN_FILE")),
		RoleSessionName:   tea.String("credentials-go-test"),
		Proxy:             tea.String("https://localhost:3600/"),
	}
	cred, err := credentials.NewCredential(config)
	assert.Nil(t, err)
	_, err = cred.GetCredential()
	assert.Contains(t, err.Error(), "proxyconnect tcp: dial tcp")
	assert.Contains(t, err.Error(), ":3600: connect: connection refused")
}
