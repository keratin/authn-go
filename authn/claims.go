package authn

import "gopkg.in/square/go-jose.v2/jwt"

type Claims struct {
	AuthTime *jwt.NumericDate `json:"auth_time"`
	jwt.Claims
}
