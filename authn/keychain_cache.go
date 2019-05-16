package authn

import (
	"time"

	"github.com/patrickmn/go-cache"

	jose "gopkg.in/square/go-jose.v2"
)

// keychainCache is a JWKProvider which wraps around another JWKProvider
// and adds a caching layer in between
type keychainCache struct {
	keyCache    *cache.Cache //local in-memory cache to store keys
	keyProvider JWKProvider  //base JWKProvider for backup after cache miss
}

// Creates a new keychainCache which wraps around keyProvider
func newKeychainCache(ttl time.Duration, keyProvider JWKProvider) *keychainCache {
	return &keychainCache{
		keyCache:    cache.New(ttl, 2*ttl),
		keyProvider: keyProvider,
	}
}

// Key tries to get signing key from cache. On cache miss it tries to get and cache
// the signing key from the keyProvider
func (k *keychainCache) Key(kid string) ([]jose.JSONWebKey, error) {
	// TODO: Log critical errors
	if jwks, ok := k.keyCache.Get(kid); ok {
		return jwks.([]jose.JSONWebKey), nil
	}

	newjwks, err := k.keyProvider.Key(kid)
	if err != nil {
		return []jose.JSONWebKey{}, err
	}

	if len(newjwks) > 0 {
		// Only cache if the base provider has keys
		k.keyCache.Set(kid, newjwks, cache.DefaultExpiration)
	}
	return newjwks, nil
}
