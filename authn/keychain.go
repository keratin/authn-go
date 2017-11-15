package authn

import (
	"github.com/patrickmn/go-cache"
	"time"

	jose "gopkg.in/square/go-jose.v2"
)

type keychain struct {
	key_cache *cache.Cache
	client    *internalClient
}

func newKeychain(config Config, internal_client *internalClient) *keychain {
	ttl := config.Keychain_ttl
	return &keychain{
		key_cache: cache.New(time.Duration(ttl)*time.Minute, time.Duration(2*ttl)*time.Minute),
		client:    internal_client,
	}
}

func (k *keychain) get(kid string) (jose.JSONWebKey, error) {
	jwk, ok := k.key_cache.Get(kid)
	if ok {
		return jwk.(jose.JSONWebKey), nil
	}
	newjwk, err := k.client.get_signing_key(kid)
	if err != nil {
		return jose.JSONWebKey{}, err
	}
	k.key_cache.Set(kid, newjwk, cache.DefaultExpiration)
	return newjwk, nil
}
