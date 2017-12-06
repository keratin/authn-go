package authn

const (
	DefaultKeychainTTL = 60
)

// Config is a configuration struct for Client
type Config struct {
	Issuer         string //the base url of the service handling authentication
	PrivateBaseURL string //overrides the base url for private endpoints
	Audience       string //the domain (host) of the main application
	Username       string //the http basic auth username for accessing private endpoints of the authn issuer
	Password       string //the http basic auth password for accessing private endpoints of the authn issuer
	KeychainTTL    int    //TTL for a key in keychain in minutes
}

func (c *Config) setDefaults() {
	if c.KeychainTTL == 0 {
		c.KeychainTTL = DefaultKeychainTTL
	}
	if c.PrivateBaseURL == "" {
		c.PrivateBaseURL = c.Issuer
	}
}
