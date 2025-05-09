package providers

import (
	"os"
	"path"
	"strings"
	"testing"

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

	// ChainableRamRoleArn with invalid source profile
	_, err = provider.getCredentialsProvider(conf, "ChainableRamRoleArn2")
	assert.EqualError(t, err, "get source profile failed: unable to get profile with 'InvalidSource'")

	// Unsupported
	_, err = provider.getCredentialsProvider(conf, "Unsupported")
	assert.EqualError(t, err, "unsupported profile mode 'Unsupported'")
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
	assert.EqualError(t, err, "reading aliyun cli config from '/path/invalid/home/dir/.aliyun/config.json' failed open /path/invalid/home/dir/.aliyun/config.json: no such file or directory")

	// testcase: specify credentials file
	provider, err = NewCLIProfileCredentialsProviderBuilder().WithProfileFile("/path/to/config.invalid").Build()
	assert.Nil(t, err)
	_, err = provider.GetCredentials()
	assert.EqualError(t, err, "reading aliyun cli config from '/path/to/config.invalid' failed open /path/to/config.invalid: no such file or directory")

	// testcase: specify credentials file with env
	os.Setenv("ALIBABA_CLOUD_CONFIG_FILE", "/path/to/config.invalid")
	provider, err = NewCLIProfileCredentialsProviderBuilder().Build()
	assert.Nil(t, err)
	_, err = provider.GetCredentials()
	assert.EqualError(t, err, "reading aliyun cli config from '/path/to/config.invalid' failed open /path/to/config.invalid: no such file or directory")

	provider, err = NewCLIProfileCredentialsProviderBuilder().WithProfileFile("/path/to/config1.invalid").Build()
	assert.Nil(t, err)
	_, err = provider.GetCredentials()
	assert.EqualError(t, err, "reading aliyun cli config from '/path/to/config1.invalid' failed open /path/to/config1.invalid: no such file or directory")
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
