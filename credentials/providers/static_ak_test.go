package providers

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStaticAKCredentialsProvider(t *testing.T) {
	_, err := NewStaticAKCredentialsProviderBuilder().
		Build()
	assert.EqualError(t, err, "the access key id is empty")

	_, err = NewStaticAKCredentialsProviderBuilder().
		WithAccessKeyId("akid").
		Build()
	assert.EqualError(t, err, "the access key secret is empty")

	provider, err := NewStaticAKCredentialsProviderBuilder().
		WithAccessKeyId("accessKeyId").
		WithAccessKeySecret("accessKeySecret").
		Build()
	assert.Nil(t, err)
	assert.Equal(t, "static_ak", provider.GetProviderName())

	cred, err := provider.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, "accessKeyId", cred.AccessKeyId)
	assert.Equal(t, "accessKeySecret", cred.AccessKeySecret)
	assert.Equal(t, "", cred.SecurityToken)
	assert.Equal(t, "static_ak", cred.ProviderName)
}

func TestStaticAKCredentialsProviderWithEnv(t *testing.T) {
	originAKID := os.Getenv("ALIBABA_CLOUD_ACCESS_KEY_ID")
	originAKSecret := os.Getenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET")
	defer func() {
		os.Setenv("ALIBABA_CLOUD_ACCESS_KEY_ID", originAKID)
		os.Setenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET", originAKSecret)
	}()

	os.Setenv("ALIBABA_CLOUD_ACCESS_KEY_ID", "akid_from_env")
	os.Setenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET", "aksecret_from_env")
	provider, err := NewStaticAKCredentialsProviderBuilder().
		Build()
	assert.Nil(t, err)
	assert.Equal(t, "static_ak", provider.GetProviderName())

	cred, err := provider.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, "akid_from_env", cred.AccessKeyId)
	assert.Equal(t, "aksecret_from_env", cred.AccessKeySecret)
	assert.Equal(t, "", cred.SecurityToken)
	assert.Equal(t, "static_ak", cred.ProviderName)
}
