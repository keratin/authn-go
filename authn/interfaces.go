package authn

import (
	jose "gopkg.in/square/go-jose.v2"
)

// Provides a JSON Web Key from a Key ID
// Wanted to use function signature from go-jose.v2
// but that would make use lose error information
type jwkProvider interface {
	Key(kid string) ([]jose.JSONWebKey, error)
}
