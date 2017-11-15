package authn

// TODO: jose/jwt references are all over the place. Refactor possible?

type AuthnClient struct {
	config   Config
	iclient  *internalClient
	verifier jwtClaimsExtractor
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
	ac.verifier, err = newIdTokenVerifier(config, kchain)
	if err != nil {
		return nil, err
	}

	return &ac, nil
}

func (ac *AuthnClient) SubjectFrom(id_token string) (string, error) {
	if claims, err := ac.verifier.GetVerifiedClaims(id_token); err != nil {
		return "", err
	} else {
		return claims.Subject, nil
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

func SubjectFrom(id_token string) (string, error) {
	return get_global_authn().SubjectFrom(id_token)
}
