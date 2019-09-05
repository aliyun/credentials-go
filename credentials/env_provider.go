package credentials

import (
	"errors"
	"os"
)

type EnvProvider struct{}

var ProviderEnv = new(EnvProvider)

const (
	EnvVarAccessKeyID     = "ALIBABA_CLOUD_ACCESS_KEY_ID"
	EnvVarAccessKeySecret = "ALIBABA_CLOUD_ACCESS_KEY_SECRET"
)

func NewEnvProvider() Provider {
	return &EnvProvider{}
}

func (p *EnvProvider) Resolve() (*Configuration, error) {
	accessKeyID, ok1 := os.LookupEnv(EnvVarAccessKeyID)
	accessKeySecret, ok2 := os.LookupEnv(EnvVarAccessKeySecret)
	if !ok1 || !ok2 {
		return nil, nil
	}
	if accessKeyID == "" {
		return nil, errors.New(EnvVarAccessKeyID + " cannot be empty")
	}
	if accessKeySecret == "" {
		return nil, errors.New(EnvVarAccessKeySecret + " cannot be empty")
	}
	config := &Configuration{
		Type:            "access_key",
		AccessKeyID:     accessKeyID,
		AccessKeySecret: accessKeySecret,
	}
	return config, nil
}
