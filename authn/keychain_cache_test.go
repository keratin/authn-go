package authn

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	jose "gopkg.in/square/go-jose.v2"

	"time"

	"github.com/patrickmn/go-cache"
)

// Mock jwkProvider for tests
// Stores keys locally
type mockJwkProvider struct {
	key_map   map[string]jose.JSONWebKey
	hit_count int
}

func newMockJwkProvider() *mockJwkProvider {
	return &mockJwkProvider{
		key_map: map[string]jose.JSONWebKey{
			"kid1": jose.JSONWebKey{
				KeyID: "kid1",
				Key:   "test_key1",
			},
			"kid2": jose.JSONWebKey{
				KeyID: "kid2",
				Key:   "test_key2",
			},
		},
	}
}

func (m *mockJwkProvider) Key(kid string) ([]jose.JSONWebKey, error) {
	m.hit_count = m.hit_count + 1

	if kid == "kidError" {
		return []jose.JSONWebKey{}, errors.New("testing error")
	}

	if jwk, ok := m.key_map[kid]; ok {
		return []jose.JSONWebKey{jwk}, nil
	}
	return []jose.JSONWebKey{}, nil
}

func TestKeychainCacheHit(t *testing.T) {
	mock_provider := newMockJwkProvider()
	keychain_cache := newKeychainCache(time.Minute, mock_provider)

	keys1, err := keychain_cache.Key("kid1")
	assert.NoError(t, err)
	assert.Len(t, keys1, 1)
	assert.Equal(t, "kid1", keys1[0].KeyID)
	assert.Equal(t, "test_key1", keys1[0].Key)
	assert.Equal(t, 1, mock_provider.hit_count)

	keys1_again, err := keychain_cache.Key("kid1")
	assert.NoError(t, err)
	assert.Len(t, keys1_again, 1)
	assert.Equal(t, "kid1", keys1_again[0].KeyID)
	assert.Equal(t, "test_key1", keys1_again[0].Key)
	assert.Equal(t, 1, mock_provider.hit_count) //Because we cached it

	keys2, err := keychain_cache.Key("kid2")
	assert.NoError(t, err)
	assert.Len(t, keys2, 1)
	assert.Equal(t, "kid2", keys2[0].KeyID)
	assert.Equal(t, "test_key2", keys2[0].Key)
	assert.Equal(t, 2, mock_provider.hit_count) //Because key2 wasnt cached
}

func TestKeychainCacheMissing(t *testing.T) {
	mock_provider := newMockJwkProvider()
	keychain_cache := newKeychainCache(time.Minute, mock_provider)

	keysNone, err := keychain_cache.Key("kidNone")
	assert.NoError(t, err)
	assert.Len(t, keysNone, 0)
	assert.Equal(t, 1, mock_provider.hit_count)

	keysNone_again, err := keychain_cache.Key("kidNone")
	assert.NoError(t, err)
	assert.Len(t, keysNone_again, 0)
	assert.Equal(t, 2, mock_provider.hit_count) //Because missing keys are not cached
}

func TestKeychainCacheTTL(t *testing.T) {
	mock_provider := newMockJwkProvider()
	keychain_cache := newKeychainCache(time.Minute, mock_provider)
	// Minimum TTL is 1 min. But we cant wait that long to test.
	// TODO: Go is not flexible enough to accept both decimal and integer ttl. Consider using seconds?
	// Hacky test because we are screwing with internals
	keychain_cache.keyCache = cache.New(time.Second, time.Second)

	keychain_cache.Key("kid1")
	assert.Equal(t, 1, mock_provider.hit_count)
	keychain_cache.Key("kid1")
	assert.Equal(t, 1, mock_provider.hit_count) //Because we cached itached

	// Wait for cache to expire
	time.Sleep(time.Second)
	keys1, err := keychain_cache.Key("kid1")
	assert.NoError(t, err)
	// Assert values post-expiry
	assert.Len(t, keys1, 1)
	assert.Equal(t, "kid1", keys1[0].KeyID)
	assert.Equal(t, "test_key1", keys1[0].Key)
	assert.Equal(t, 2, mock_provider.hit_count) //Because cache expired
}

func TestKeychainCacheError(t *testing.T) {
	mock_provider := newMockJwkProvider()
	keychain_cache := newKeychainCache(time.Minute, mock_provider)

	keysError, err := keychain_cache.Key("kidError")
	assert.EqualError(t, err, "testing error")
	assert.Len(t, keysError, 0)
	assert.Equal(t, 1, mock_provider.hit_count)

	keysError_again, err := keychain_cache.Key("kidError")
	assert.EqualError(t, err, "testing error")
	assert.Len(t, keysError_again, 0)
	assert.Equal(t, 2, mock_provider.hit_count) //Because keys are not cached in case of error
}
