package authn

import ()

type Config struct {
	Issuer         string //the base url of the service handling authentication
	PrivateBaseUrl string //overrides the base url for private endpoints
	Audience       string //the domain (host) of the main application
	Username       string //the http basic auth username for accessing private endpoints of the authn issuer
	Password       string //the http basic auth password for accessing private endpoints of the authn issuer
	Keychain_ttl   int
}

func (c *Config) setDefaults() {
	if c.Keychain_ttl == 0 {
		c.Keychain_ttl = 3600
	}
	if c.PrivateBaseUrl == "" {
		c.PrivateBaseUrl = c.Issuer
	}
}
