package authn

import "github.com/go-jose/go-jose/v3/jwt"

type Claims struct {
	AuthTime  *jwt.NumericDate `json:"auth_time"`
	SessionID string           `json:"sid"`
	jwt.Claims
}
