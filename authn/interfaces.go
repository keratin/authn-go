package authn

import (
	jose "gopkg.in/square/go-jose.v2"
	jwt "gopkg.in/square/go-jose.v2/jwt"
)

// Provides a JSON Web Key from a Key ID
// Wanted to use function signature from go-jose.v2
// but that would make us lose error information
type jwkProvider interface {
	Key(kid string) ([]jose.JSONWebKey, error)
}

// Extracts verified in-built claims from a jwt idToken
type jwtClaimsExtractor interface {
	GetVerifiedClaims(idToken string) (*jwt.Claims, error)
}
