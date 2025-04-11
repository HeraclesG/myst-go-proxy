package proxy

import (
	"math/rand"
	"strings"
)

type Orchestra struct {
	Providers map[string]Provider
}

func NewOrchestra(providers []Provider) *Orchestra {
	providerPool := make(map[string]Provider, len(providers))

	for _, provider := range providers {
		providerPool[provider.Name()] = provider
	}

	return &Orchestra{
		Providers: providerPool,
	}
}

func (p *Orchestra) GetIdle(request *Request) (Provider, bool) {

	var matchingProviders []Provider

	for _, provider := range p.Providers {
		if provider.Idle() && (request.Country == nil || strings.EqualFold(provider.Country(), string(request.Country))) {
			matchingProviders = append(matchingProviders, provider)
		}
	}

	if len(matchingProviders) == 0 {
		return nil, false
	}

	// Randomly select from matching providers
	randomIndex := rand.Intn(len(matchingProviders))
	return matchingProviders[randomIndex], true
}

func (p *Orchestra) AddProvider(provider Provider) {
	p.Providers[provider.Name()] = provider
}

func (p *Orchestra) RemoveProvider(provider Provider) {
	delete(p.Providers, provider.Name())
}

func (p *Orchestra) GetProvider(providerName string) (Provider, bool) {
	provider, ok := p.Providers[providerName]
	return provider, ok
}
