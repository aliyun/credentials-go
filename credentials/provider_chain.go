package credentials

import (
	"errors"
)

type ProviderChain struct {
	Providers []Provider
}

var defaultproviders = []Provider{ProviderEnv, ProviderProfile, ProviderInstance}
var DefaultChain = NewProviderChain(defaultproviders)

func NewProviderChain(providers []Provider) Provider {
	return &ProviderChain{
		Providers: providers,
	}
}

func (p *ProviderChain) Resolve() (*Configuration, error) {
	for _, provider := range p.Providers {
		config, err := provider.Resolve()
		if err != nil {
			return nil, err
		} else if config == nil {
			continue
		}
		return config, err
	}
	return nil, errors.New("No credential found")

}
