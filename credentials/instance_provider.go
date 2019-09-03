package credentials

import (
	"errors"
	"os"
)

type InstanceCredentialsProvider struct{}

var ProviderInstance = new(InstanceCredentialsProvider)

func NewInstanceCredentialsProvider() Provider {
	return &InstanceCredentialsProvider{}
}

func (p *InstanceCredentialsProvider) Resolve() (*Configuration, error) {
	roleName, ok := os.LookupEnv(ENVEcsMetadata)
	if !ok {
		return nil, nil
	}
	if roleName == "" {
		return nil, errors.New(ENVEcsMetadata + " cannot be empty.")
	}

	config := &Configuration{
		Type:     "ecs_ram_role",
		RoleName: roleName,
	}
	return config, nil
}
