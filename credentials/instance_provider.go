package credentials

import (
	"os"
)

type instanceCredentialsProvider struct{}

var providerInstance = new(instanceCredentialsProvider)

func newInstanceCredentialsProvider() Provider {
	return &instanceCredentialsProvider{}
}

func (p *instanceCredentialsProvider) resolve() (*Configuration, error) {
	roleName, ok := os.LookupEnv(ENVEcsMetadata)
	if !ok {
		return nil, nil
	}

	config := &Configuration{
		Type:     "ecs_ram_role",
		RoleName: roleName,
	}
	return config, nil
}
