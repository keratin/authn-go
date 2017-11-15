package authn

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestConfigDefaults(t *testing.T) {
	c := Config{
		Issuer:   "test_issuer",
		Audience: "test_audience",
		Username: "test_username",
		Password: "test_password",
	}
	c.setDefaults()
	assert.Equal(t, c.Issuer, "test_issuer")
	assert.Equal(t, c.PrivateBaseUrl, "test_issuer")
	assert.Equal(t, c.Audience, "test_audience")
	assert.Equal(t, c.Username, "test_username")
	assert.Equal(t, c.Password, "test_password")
	assert.Equal(t, c.Keychain_ttl, DefaultKeychainTTL)
}

func TestConfigDefaultsOverride(t *testing.T) {
	c := Config{
		Issuer:         "test_issuer",
		Audience:       "test_audience",
		Username:       "test_username",
		Password:       "test_password",
		PrivateBaseUrl: "test_private_url",
		Keychain_ttl:   500,
	}
	c.setDefaults()
	assert.Equal(t, c.Issuer, "test_issuer")
	assert.Equal(t, c.PrivateBaseUrl, "test_private_url")
	assert.Equal(t, c.Audience, "test_audience")
	assert.Equal(t, c.Username, "test_username")
	assert.Equal(t, c.Password, "test_password")
	assert.Equal(t, c.Keychain_ttl, 500)
}
