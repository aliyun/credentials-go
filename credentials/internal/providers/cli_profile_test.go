package providers

import (
	"os"
	"path"
	"strings"
	"testing"

	"github.com/aliyun/credentials-go/credentials/internal/utils"
	"github.com/stretchr/testify/assert"
)

func TestCLIProfileCredentialsProvider(t *testing.T) {
	rollback := utils.Memory("ALIBABA_CLOUD_PROFILE")
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
				Mode:            "RamRoleArn",
				Name:            "RamRoleArn",
				AccessKeyID:     "akid",
				AccessKeySecret: "secret",
				RoleArn:         "arn",
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

	// ChainableRamRoleArn with invalid source profile
	_, err = provider.getCredentialsProvider(conf, "ChainableRamRoleArn2")
	assert.EqualError(t, err, "get source profile failed: unable to get profile with 'InvalidSource'")

	// Unsupported
	_, err = provider.getCredentialsProvider(conf, "Unsupported")
	assert.EqualError(t, err, "unsupported profile mode 'Unsupported'")
}

func TestCLIProfileCredentialsProvider_GetCredentials(t *testing.T) {
	defer func() {
		getHomePath = utils.GetHomePath
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
	assert.EqualError(t, err, "reading aliyun cli config from '/path/invalid/home/dir/.aliyun/config.json' failed open /path/invalid/home/dir/.aliyun/config.json: no such file or directory")

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
}