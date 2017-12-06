package authn

import (
	"errors"
	"net/url"
	"time"

	jwt "gopkg.in/square/go-jose.v2/jwt"
)

// A JWT Claims extractor (jwtClaimsExtractor) implementation
// which extracts claims from Authn idToken
type idTokenVerifier struct {
	config    Config
	keychain  jwkProvider
	issuerURL *url.URL
}

// Creates a new idTokenVerifier object by using keychain as the JWK provider
// Claims are verified against the values specified in config
func newIDTokenVerifier(config Config, keychain jwkProvider) (*idTokenVerifier, error) {
	issuer, err := url.Parse(config.Issuer)
	if err != nil {
		return nil, err
	}

	return &idTokenVerifier{
		config:    config,
		keychain:  keychain,
		issuerURL: issuer,
	}, nil
}

// Gets verified claims from an Authn idToken
func (verifier *idTokenVerifier) GetVerifiedClaims(idToken string) (*jwt.Claims, error) {
	var err error

	claims, err := verifier.claims(idToken)
	if err != nil {
		return nil, err
	}

	err = verifier.verify(claims)
	if err != nil {
		return nil, err
	}

	return claims, nil
}

// Gets claims object from an idToken using the key from keychain
// Key from keychain is fetched using KeyID found in idToken's header
func (verifier *idTokenVerifier) claims(idToken string) (*jwt.Claims, error) {
	var err error

	idJwt, err := jwt.ParseSigned(idToken)
	if err != nil {
		return nil, err
	}

	headers := idJwt.Headers
	if len(headers) != 1 {
		return nil, errors.New("Multi-signature JWT not supported or missing headers information")
	}
	keyID := headers[0].KeyID
	keys, err := verifier.keychain.Key(keyID)
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, errors.New("No keys found")
	}
	key := keys[0]

	claims := &jwt.Claims{}
	err = idJwt.Claims(key, claims)
	if err != nil {
		return nil, err
	}

	return claims, nil
}

// Verify the claims against the configured values
func (verifier *idTokenVerifier) verify(claims *jwt.Claims) error {
	var err error

	// Standard validator uses exact matching instead of URL matching
	err = verifier.verifyTokenFromUs(claims)
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
func (verifier *idTokenVerifier) verifyTokenFromUs(claims *jwt.Claims) error {
	issuer, err := url.Parse(claims.Issuer)
	if err != nil {
		return err
	}
	if verifier.issuerURL.String() != issuer.String() {
		return jwt.ErrInvalidIssuer
	}
	return nil
}
