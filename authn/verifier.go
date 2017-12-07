package authn

import (
	"errors"
	"net/url"
	"time"

	jwt "gopkg.in/square/go-jose.v2/jwt"
)

var (
	ErrNoKey = errors.New("No keys found")
)

// A JWT Claims extractor (jwtClaimsExtractor) implementation
// which extracts claims from Authn idToken
type idTokenVerifier struct {
	audience  string
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
		audience:  config.Audience,
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
		return nil, ErrNoKey
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

	// Validate rest of the claims
	err = claims.Validate(jwt.Expected{
		Issuer:   verifier.issuerURL.String(),
		Time:     time.Now(),
		Audience: jwt.Audience{verifier.audience},
	})
	if err != nil {
		return err
	}

	return nil
}
