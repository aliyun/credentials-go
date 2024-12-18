package providers

import (
	"os"
	"path"
	"testing"

	httputil "github.com/aliyun/credentials-go/credentials/internal/http"
	"github.com/aliyun/credentials-go/credentials/internal/utils"
	"github.com/stretchr/testify/assert"
	"gopkg.in/ini.v1"
)

var inistr = `
[default]
enable = true
type = access_key
access_key_id = foo
access_key_secret = bar

[notype]
access_key_id = foo
access_key_secret = bar

[noak]
type = access_key
access_key_secret = bar

[emptyak]
type = access_key
access_key_id =
access_key_secret = bar

[ecs]
type = ecs_ram_role
role_name = EcsRamRoleTest

[noecs]
type = ecs_ram_role

[emptyecs]
type = ecs_ram_role
role_name =

[ram]
type = ram_role_arn
access_key_id = foo
access_key_secret = bar
role_arn = role_arn
role_session_name = session_name
policy = {"Statement": [{"Action": ["*"],"Effect": "Allow","Resource": ["*"]}],"Version":"1"}

[noram]
type = ram_role_arn
access_key_secret = bar
role_arn = role_arn
role_session_name = session_name

[emptyram]
type = ram_role_arn
access_key_id =
access_key_secret = bar
role_arn = role_arn
role_session_name = session_name

[rsa]
type = rsa_key_pair
public_key_id = publicKeyId
private_key_file = ./pk.pem

[norsa]
type = rsa_key_pair
public_key_id = publicKeyId

[emptyrsa]
type = rsa_key_pair
public_key_id = publicKeyId
private_key_file =

[error_rsa]
type = rsa_key_pair
public_key_id = publicKeyId
private_key_file = ./pk_error.pem

[error_type]
type = error_type
public_key_id = publicKeyId
private_key_file = ./pk_error.pem
`

func TestProfileCredentialsProviderBuilder(t *testing.T) {
	rollback := utils.Memory("ALIBABA_CLOUD_PROFILE")
	defer rollback()

	// profile name from specified
	provider, err := NewProfileCredentialsProviderBuilder().WithProfileName("custom").Build()
	assert.Nil(t, err)
	assert.Equal(t, "custom", provider.profileName)

	// profile name from env
	os.Setenv("ALIBABA_CLOUD_PROFILE", "profile_from_env")
	provider, err = NewProfileCredentialsProviderBuilder().Build()
	assert.Nil(t, err)

	assert.Equal(t, "profile_from_env", provider.profileName)

	// profile name from default
	os.Setenv("ALIBABA_CLOUD_PROFILE", "")
	provider, err = NewProfileCredentialsProviderBuilder().Build()
	assert.Nil(t, err)
	assert.Equal(t, "default", provider.profileName)
}

func TestProfileCredentialsProvider_getCredentialsProvider(t *testing.T) {
	provider, err := NewProfileCredentialsProviderBuilder().WithProfileName("custom").Build()
	assert.Nil(t, err)
	_, err = provider.getCredentialsProvider(ini.Empty())
	assert.NotNil(t, err)
	assert.EqualError(t, err, "ERROR: Can not load sectionsection \"custom\" does not exist")

	file, err := ini.Load([]byte(inistr))
	assert.Nil(t, err)
	assert.NotNil(t, file)

	// no type
	provider, err = NewProfileCredentialsProviderBuilder().WithProfileName("notype").Build()
	assert.Nil(t, err)
	_, err = provider.getCredentialsProvider(file)
	assert.NotNil(t, err)
	assert.EqualError(t, err, "ERROR: Can not find credential typeerror when getting key of section \"notype\": key \"type\" not exists")

	// no ak
	provider, err = NewProfileCredentialsProviderBuilder().WithProfileName("noak").Build()
	assert.Nil(t, err)
	_, err = provider.getCredentialsProvider(file)
	assert.NotNil(t, err)
	assert.EqualError(t, err, "ERROR: Failed to get value")

	// value is empty
	provider, err = NewProfileCredentialsProviderBuilder().WithProfileName("emptyak").Build()
	assert.Nil(t, err)
	_, err = provider.getCredentialsProvider(file)
	assert.NotNil(t, err)
	assert.EqualError(t, err, "ERROR: Value can't be empty")

	// static ak provider
	provider, err = NewProfileCredentialsProviderBuilder().Build()
	assert.Nil(t, err)
	cp, err := provider.getCredentialsProvider(file)
	assert.Nil(t, err)
	akcp, ok := cp.(*StaticAKCredentialsProvider)
	assert.True(t, ok)
	cc, err := akcp.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, &Credentials{AccessKeyId: "foo", AccessKeySecret: "bar", SecurityToken: "", ProviderName: "static_ak"}, cc)

	// ecs_ram_role without rolename
	provider, err = NewProfileCredentialsProviderBuilder().WithProfileName("noecs").Build()
	assert.Nil(t, err)
	_, err = provider.getCredentialsProvider(file)
	assert.EqualError(t, err, "ERROR: Failed to get value")

	// ecs_ram_role with rolename
	provider, err = NewProfileCredentialsProviderBuilder().WithProfileName("ecs").Build()
	assert.Nil(t, err)
	cp, err = provider.getCredentialsProvider(file)
	assert.Nil(t, err)
	_, ok = cp.(*ECSRAMRoleCredentialsProvider)
	assert.True(t, ok)

	// ram role arn without keys
	provider, err = NewProfileCredentialsProviderBuilder().WithProfileName("noram").Build()
	assert.Nil(t, err)
	_, err = provider.getCredentialsProvider(file)
	assert.EqualError(t, err, "ERROR: Failed to get value")

	// ram role arn without values
	provider, err = NewProfileCredentialsProviderBuilder().WithProfileName("emptyram").Build()
	assert.Nil(t, err)
	_, err = provider.getCredentialsProvider(file)
	assert.EqualError(t, err, "ERROR: Value can't be empty")

	// normal ram role arn
	provider, err = NewProfileCredentialsProviderBuilder().WithProfileName("ram").Build()
	assert.Nil(t, err)
	cp, err = provider.getCredentialsProvider(file)
	assert.Nil(t, err)
	_, ok = cp.(*RAMRoleARNCredentialsProvider)
	assert.True(t, ok)

	// unsupported type
	provider, err = NewProfileCredentialsProviderBuilder().WithProfileName("error_type").Build()
	assert.Nil(t, err)
	_, err = provider.getCredentialsProvider(file)
	assert.EqualError(t, err, "ERROR: Failed to get credential")
}

func TestProfileCredentialsProviderGetCredentials(t *testing.T) {
	originHttpDo := httpDo
	defer func() { httpDo = originHttpDo }()
	rollback := utils.Memory("ALIBABA_CLOUD_CREDENTIALS_FILE")
	defer func() {
		getHomePath = utils.GetHomePath
		rollback()
	}()

	// testcase: empty home
	getHomePath = func() string {
		return ""
	}
	provider, err := NewProfileCredentialsProviderBuilder().WithProfileName("custom").Build()
	assert.Nil(t, err)
	_, err = provider.GetCredentials()
	assert.EqualError(t, err, "cannot found home dir")

	// testcase: invalid home
	getHomePath = func() string {
		return "/path/invalid/home/dir"
	}

	provider, err = NewProfileCredentialsProviderBuilder().WithProfileName("custom").Build()
	assert.Nil(t, err)
	_, err = provider.GetCredentials()
	assert.EqualError(t, err, "ERROR: Can not open fileopen /path/invalid/home/dir/.alibabacloud/credentials: no such file or directory")

	// testcase: specify credentials file with env
	os.Setenv("ALIBABA_CLOUD_CREDENTIALS_FILE", "/path/to/credentials.invalid")
	provider, err = NewProfileCredentialsProviderBuilder().WithProfileName("custom").Build()
	assert.Nil(t, err)
	_, err = provider.GetCredentials()
	assert.EqualError(t, err, "ERROR: Can not open fileopen /path/to/credentials.invalid: no such file or directory")
	os.Unsetenv("ALIBABA_CLOUD_CREDENTIALS_FILE")

	// get from credentials file
	getHomePath = func() string {
		wd, _ := os.Getwd()
		return path.Join(wd, "fixtures")
	}

	provider, err = NewProfileCredentialsProviderBuilder().WithProfileName("custom").Build()
	assert.Nil(t, err)
	_, err = provider.GetCredentials()
	assert.EqualError(t, err, "ERROR: Can not load sectionsection \"custom\" does not exist")

	provider, err = NewProfileCredentialsProviderBuilder().Build()
	assert.Nil(t, err)
	cc, err := provider.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, &Credentials{AccessKeyId: "foo", AccessKeySecret: "bar", SecurityToken: "", ProviderName: "profile/static_ak"}, cc)

	// get credentials again
	cc, err = provider.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, &Credentials{AccessKeyId: "foo", AccessKeySecret: "bar", SecurityToken: "", ProviderName: "profile/static_ak"}, cc)

	httpDo = func(req *httputil.Request) (res *httputil.Response, err error) {
		res = &httputil.Response{
			StatusCode: 200,
			Body:       []byte(`{"Credentials": {"AccessKeyId":"akid","AccessKeySecret":"aksecret","Expiration":"2021-10-20T04:27:09Z","SecurityToken":"ststoken"}}`),
		}
		return
	}
	provider, err = NewProfileCredentialsProviderBuilder().WithProfileName("ram").Build()
	assert.Nil(t, err)
	cc, err = provider.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, "akid", cc.AccessKeyId)
	assert.Equal(t, "aksecret", cc.AccessKeySecret)
	assert.Equal(t, "ststoken", cc.SecurityToken)
	assert.Equal(t, "profile/ram_role_arn/static_ak", cc.ProviderName)

	provider.innerProvider = new(testProvider)
	cc, err = provider.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, "test", cc.AccessKeyId)
	assert.Equal(t, "test", cc.AccessKeySecret)
	assert.Equal(t, "profile/test", cc.ProviderName)

	provider.innerProvider = new(testErrorProvider)
	_, err = provider.GetCredentials()
	assert.Equal(t, "error", err.Error())
}
