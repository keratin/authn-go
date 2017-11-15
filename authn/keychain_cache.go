package authn

import (
	"github.com/patrickmn/go-cache"
	"time"

	jose "gopkg.in/square/go-jose.v2"
)

// keychainCache is a jwkProvider which wraps around another jwkProvider
// and adds a caching layer in between
type keychainCache struct {
	key_cache         *cache.Cache //local in-memory cache to store keys
	base_key_provider jwkProvider  //base jwkProvider for backup after cache miss
}

// Creates a new keychainCache which wraps around base_key_provider
func newKeychainCache(config Config, base_key_provider jwkProvider) *keychainCache {
	ttl := config.Keychain_ttl
	return &keychainCache{
		key_cache:         cache.New(time.Duration(ttl)*time.Minute, time.Duration(2*ttl)*time.Minute),
		base_key_provider: base_key_provider,
	}
}

// Tries to get signing key from cache. On cache miss it tries to get and cache
// the signing key from the base_key_provider
func (k *keychainCache) Key(kid string) []jose.JSONWebKey {
	// TODO: Log critical errors
	jwks, ok := k.key_cache.Get(kid)
	if ok {
		return jwks.([]jose.JSONWebKey)
	}
	newjwks := k.base_key_provider.Key(kid)
	if len(newjwks) > 0 {
		// Only cache if the base provider has keys
		k.key_cache.Set(kid, newjwks, cache.DefaultExpiration)
	}
	return newjwks
}
