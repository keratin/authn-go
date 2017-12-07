package authn

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	jose "gopkg.in/square/go-jose.v2"
	jwt "gopkg.in/square/go-jose.v2/jwt"
)

func TestIDTokenVerifier(t *testing.T) {
	// the good test key
	defaultKey, err := rsa.GenerateKey(rand.Reader, 512)
	require.NoError(t, err)
	defaultJWK := jose.JSONWebKey{Key: defaultKey, KeyID: "defaultKey"}

	// build a verifier
	jwks := &mockJwkProvider{key_map: map[string]jose.JSONWebKey{}}
	jwks.key_map[defaultJWK.KeyID] = jose.JSONWebKey{Key: defaultKey.Public(), KeyID: "defaultKey"}
	config := Config{
		Issuer:   "https://authn.example.com",
		Audience: "app.example.com",
	}
	verifier, err := newIDTokenVerifier(config, jwks)
	require.NoError(t, err)

	// factory defaults
	randInt, err := rand.Int(rand.Reader, big.NewInt(99999))
	require.NoError(t, err)
	defaultClaims := jwt.Claims{
		Issuer:   config.Issuer,
		Audience: jwt.Audience{config.Audience},
		Subject:  randInt.String(),
		Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
	}
	defaultSigner, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: defaultJWK},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		token, err := jwt.Signed(defaultSigner).Claims(defaultClaims).CompactSerialize()
		require.NoError(t, err)

		claims, err := verifier.GetVerifiedClaims(token)
		require.NoError(t, err)

		assert.Equal(t, defaultClaims.Subject, claims.Subject)
	})

	t.Run("audience string", func(t *testing.T) {
		token, err := jwt.Signed(defaultSigner).Claims(map[string]interface{}{
			"iss": defaultClaims.Issuer,
			"aud": config.Audience,
			"sub": defaultClaims.Subject,
			"exp": defaultClaims.Expiry.Time().Unix(),
			"iat": defaultClaims.IssuedAt.Time().Unix(),
		}).CompactSerialize()
		require.NoError(t, err)

		claims, err := verifier.GetVerifiedClaims(token)
		require.NoError(t, err)

		assert.Equal(t, defaultClaims.Subject, claims.Subject)
	})

	t.Run("URL-equivalent issuer", func(t *testing.T) {
		testClaims := defaultClaims
		testClaims.Issuer = "https://authn.example.com/"
		token, err := jwt.Signed(defaultSigner).Claims(testClaims).CompactSerialize()
		require.NoError(t, err)

		// See: https://github.com/keratin/authn-go/issues/3
		_, err = verifier.GetVerifiedClaims(token)
		assert.Equal(t, jwt.ErrInvalidIssuer, err)
	})

	t.Run("invalid formats", func(t *testing.T) {
		testCases := []struct {
			token string
			err   error
		}{
			{"", fmt.Errorf("square/go-jose: compact JWS format must have three parts")},
			{"a", fmt.Errorf("square/go-jose: compact JWS format must have three parts")},
			{"a.b", fmt.Errorf("square/go-jose: compact JWS format must have three parts")},
			{"a.b.c", base64.CorruptInputError(0)},
		}

		for _, tc := range testCases {
			_, err := verifier.GetVerifiedClaims(tc.token)
			assert.Equal(t, tc.err, err)
		}
	})

	t.Run("signed by unknown keypair", func(t *testing.T) {
		unknownKey, err := rsa.GenerateKey(rand.Reader, 512)
		require.NoError(t, err)
		unknownJWK := jose.JSONWebKey{Key: unknownKey, KeyID: "unknownKey"}
		unknownSigner, err := jose.NewSigner(
			jose.SigningKey{Algorithm: jose.RS256, Key: unknownJWK},
			(&jose.SignerOptions{}).WithType("JWT"),
		)
		require.NoError(t, err)

		token, err := jwt.Signed(unknownSigner).Claims(defaultClaims).CompactSerialize()
		require.NoError(t, err)

		_, err = verifier.GetVerifiedClaims(token)
		assert.Equal(t, ErrNoKey, err)
	})

	t.Run("alg=none attack", func(t *testing.T) {
		token, err := jwt.Signed(defaultSigner).Claims(defaultClaims).CompactSerialize()
		require.NoError(t, err)

		token = swapHeader(token, map[string]string{"alg": "none", "type": "JWT"})

		_, err = verifier.GetVerifiedClaims(token)
		assert.Equal(t, ErrNoKey, err)
	})

	t.Run("alg=hmac attack", func(t *testing.T) {
		// this hmac signer uses the public key to sign, in hopes that the verifier will naively use
		// it to verify.
		jwkJSON, err := jwks.key_map[defaultJWK.KeyID].MarshalJSON()
		require.NoError(t, err)
		hmacSigner, err := jose.NewSigner(
			jose.SigningKey{Algorithm: jose.HS256, Key: jwkJSON},
			(&jose.SignerOptions{}).WithType("JWT"),
		)
		require.NoError(t, err)

		token, err := jwt.Signed(hmacSigner).Claims(defaultClaims).CompactSerialize()
		require.NoError(t, err)

		token = swapHeader(token, map[string]string{"alg": "HS256", "type": "JWT", "kid": defaultJWK.KeyID})

		_, err = verifier.GetVerifiedClaims(token)
		assert.Equal(t, jose.ErrCryptoFailure, err)
	})

	t.Run("wrong issuer", func(t *testing.T) {
		testClaims := defaultClaims
		testClaims.Issuer = "https://authn.elsewhere.com"
		token, err := jwt.Signed(defaultSigner).Claims(testClaims).CompactSerialize()
		require.NoError(t, err)

		_, err = verifier.GetVerifiedClaims(token)
		assert.Equal(t, jwt.ErrInvalidIssuer, err)
	})

	t.Run("wrong audience", func(t *testing.T) {
		testClaims := defaultClaims
		testClaims.Audience = jwt.Audience{"app.elsewhere.com"}
		token, err := jwt.Signed(defaultSigner).Claims(testClaims).CompactSerialize()
		require.NoError(t, err)

		_, err = verifier.GetVerifiedClaims(token)
		assert.Equal(t, jwt.ErrInvalidAudience, err)
	})

	t.Run("tampered subject", func(t *testing.T) {
		token, err := jwt.Signed(defaultSigner).Claims(defaultClaims).CompactSerialize()
		require.NoError(t, err)

		_, err = verifier.GetVerifiedClaims(mergeClaims(token, map[string]string{"sub": "null"}))
		assert.Equal(t, jose.ErrCryptoFailure, err)
	})

	t.Run("expired", func(t *testing.T) {
		testClaims := defaultClaims
		testClaims.Expiry = jwt.NewNumericDate(time.Now().Add(-time.Hour))
		token, err := jwt.Signed(defaultSigner).Claims(testClaims).CompactSerialize()
		require.NoError(t, err)

		_, err = verifier.GetVerifiedClaims(token)
		assert.Equal(t, jwt.ErrExpired, err)
	})
}

func swapHeader(token string, newHeader map[string]string) string {
	bytes, err := json.Marshal(newHeader)
	if err != nil {
		panic(err)
	}

	parts := strings.Split(token, ".")
	parts[0] = base64.RawStdEncoding.EncodeToString(bytes)
	return strings.Join(parts, ".")
}

func mergeClaims(token string, newClaims map[string]string) string {
	parts := strings.Split(token, ".")

	// decode
	var claims map[string]interface{}
	raw, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(raw, &claims)
	if err != nil {
		panic(err)
	}

	// the merge
	for k, v := range newClaims {
		claims[k] = v
	}

	// re-encode
	bytes, err := json.Marshal(claims)
	if err != nil {
		panic(err)
	}
	parts[1] = base64.RawStdEncoding.EncodeToString(bytes)
	return strings.Join(parts, ".")
}
