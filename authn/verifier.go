package authn

import (
	"errors"
	jwt "gopkg.in/square/go-jose.v2/jwt"
	"net/url"
	"time"
)

// A JWT Claims extractor (jwtClaimsExtractor) implementation
// which extracts claims from Authn id_token
type idTokenVerifier struct {
	config          Config
	kchain          jwkProvider
	conf_issuer_url *url.URL
}

// Creates a new idTokenVerifier object by using kchain as the JWK provider
// Claims are verified against the values specified in config
func newIdTokenVerifier(config Config, kchain jwkProvider) (*idTokenVerifier, error) {
	conf_issuer, err := url.Parse(config.Issuer)
	if err != nil {
		return nil, err
	}

	return &idTokenVerifier{
		config:          config,
		kchain:          kchain,
		conf_issuer_url: conf_issuer,
	}, nil
}

// Gets verified claims from an Authn id_token
func (verifier *idTokenVerifier) GetVerifiedClaims(id_token string) (*jwt.Claims, error) {
	var err error

	claims, err := verifier.get_claims(id_token)
	if err != nil {
		return nil, err
	}

	err = verifier.verify(claims)
	if err != nil {
		return nil, err
	}

	return claims, nil
}

// Gets claims object from an id_token using the key from keychain
// Key from keychain is fetched using KeyID found in id_token's header
func (verifier *idTokenVerifier) get_claims(id_token string) (*jwt.Claims, error) {
	var err error

	id_jwt, err := jwt.ParseSigned(id_token)
	if err != nil {
		return nil, err
	}

	headers := id_jwt.Headers
	if len(headers) != 1 {
		return nil, errors.New("Multi-signature JWT not supported or missing headers information")
	}
	key_id := headers[0].KeyID
	keys, err := verifier.kchain.Key(key_id)
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, errors.New("No keys found")
	}
	key := keys[0]

	claims := &jwt.Claims{}
	err = id_jwt.Claims(key, claims)
	if err != nil {
		return nil, err
	}

	return claims, nil
}

// Verify the claims against the configured values
func (verifier *idTokenVerifier) verify(claims *jwt.Claims) error {
	var err error

	// Standard validator uses exact matching instead of URL matching
	err = verifier.verify_token_from_us(claims)
	if err != nil {
		return err
	}

	// Validate rest of the claims
	// TODO: Does Audience need URL matching too?
	err = claims.Validate(jwt.Expected{
		Time:     time.Now(),
		Audience: jwt.Audience{verifier.config.Audience},
	})
	if err != nil {
		return err
	}

	return nil
}

// Verify the issuer claim against the configured issuer by using url comparison
func (verifier *idTokenVerifier) verify_token_from_us(claims *jwt.Claims) error {
	token_issuer, err := url.Parse(claims.Issuer)
	if err != nil {
		return err
	}
	if verifier.conf_issuer_url.String() != token_issuer.String() {
		return jwt.ErrInvalidIssuer
	}
	return nil
}
