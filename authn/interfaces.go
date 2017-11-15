package authn

import (
	jose "gopkg.in/square/go-jose.v2"
)

// Provides a JSON Web Key from a Key ID
// Function signature taken from go-jose.v2 library
type jwkProvider interface {
	Key(kid string) []jose.JSONWebKey
}
