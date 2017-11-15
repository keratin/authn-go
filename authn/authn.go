package authn

// TODO: jose/jwt references are all over the place. Refactor possible?

type AuthnClient struct {
	config   Config
	iclient  *internalClient
	verifier *idTokenVerifier
}

func NewAuthnClient(config Config) (*AuthnClient, error) {
	var err error
	config.setDefaults()

	ac := AuthnClient{}

	ac.config = config

	ac.iclient, err = newInternalClient(config)
	if err != nil {
		return nil, err
	}

	kchain := newKeychainCache(config, ac.iclient)
	ac.verifier = newIdTokenVerifier(config, kchain)

	return &ac, nil
}

func (ac *AuthnClient) SubjectFrom(id_token string) (string, bool) {
	if claims, ok := ac.verifier.get_verified_claims(id_token); ok {
		return claims.Subject, true
	} else {
		return "", false
	}
}

var Authn *AuthnClient

func get_global_authn() *AuthnClient {
	if Authn == nil {
		panic("Please initialize Authn using InitWithConfig")
	}
	return Authn
}

func InitWithConfig(config Config) error {
	tAuthn, err := NewAuthnClient(config)
	if err != nil {
		return err
	}
	Authn = tAuthn
	return nil
}

func SubjectFrom(id_token string) (string, bool) {
	return get_global_authn().SubjectFrom(id_token)
}
