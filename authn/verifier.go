package authn

import (
	"errors"
	jwt "gopkg.in/square/go-jose.v2/jwt"
	"log"
	"net/url"
	"time"
)

type idTokenVerifier struct {
	config    Config
	kchain    jwkProvider
	init_time time.Time
}

func newIdTokenVerifier(config Config, kchain jwkProvider) *idTokenVerifier {
	return &idTokenVerifier{
		config:    config,
		kchain:    kchain,
		init_time: time.Now(),
	}
}

func (verifier *idTokenVerifier) get_verified_claims(id_token string) (*jwt.Claims, bool) {
	claims, err := verifier.get_claims(id_token)
	if err != nil {
		log.Println(err)
		return nil, false
	}

	if ok := verifier.verify(claims); ok {
		return claims, true
	} else {
		return nil, false
	}
}

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

func (verifier *idTokenVerifier) verify(claims *jwt.Claims) bool {
	// Standard validator uses exact matching instead of URL matching
	if !verifier.verify_token_from_us(claims) {
		return false
	}

	// Validate rest of the claims
	err := claims.Validate(jwt.Expected{
		Time:     verifier.init_time,
		Audience: jwt.Audience{verifier.config.Audience},
	})
	if err != nil {
		return false
	}

	return true
}

func (verifier *idTokenVerifier) verify_token_from_us(claims *jwt.Claims) bool {
	conf_issuer, err := url.Parse(verifier.config.Issuer)
	if err != nil {
		return false
	}
	token_issuer, err := url.Parse(claims.Issuer)
	if err != nil {
		return false
	}
	if conf_issuer.String() != token_issuer.String() {
		return false
	}
	return true
}
