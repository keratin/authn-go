# Keratin AuthN

Keratin AuthN is an authentication service that keeps you in control of the experience without forcing you to be an expert in web security.

This library provides utilities to help integrate with a Go application. You may also be interested in keratin/authn-js for frontend integration.

**Not production ready**

## Installation

Currently this library is not go-gettable. It will eventually be moved it its proper namespace. To use make sure this repo is checked out at `$GOPATH/src/github.com/keratin/authn-go`.

## Example

```go
package main

import (
	"fmt"
	"github.com/keratin/authn-go/authn"
)

var jwt1 = `<your test jwt here>`

func main() {
	err := authn.InitWithConfig(authn.Config{
		Issuer:         "https://issuer.example.com",
		PrivateBaseURL: "http://private.example.com",
		Audience:       "application.example.com",
		Username:       "<Authn Username>",
		Password:       "<Authn Password>",
	})
	fmt.Println(err)

	sub, err := authn.SubjectFrom(jwt1)
	fmt.Println(sub)
	fmt.Println(err)
}

```
