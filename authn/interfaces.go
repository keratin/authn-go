package authn

import (
	jose "github.com/go-jose/go-jose/v3"
)

// Provides a JSON Web Key from a Key ID
// Wanted to use function signature from go-jose.v2
// but that would make us lose error information
type JWKProvider interface {
	Key(kid string) ([]jose.JSONWebKey, error)
}

// Extracts verified in-built claims from a jwt idToken
type JWTClaimsExtractor interface {
	GetVerifiedClaims(idToken string) (*Claims, error)
}
