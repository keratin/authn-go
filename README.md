# Keratin AuthN

Keratin AuthN is an authentication service that keeps you in control of the experience without forcing you to be an expert in web security.

This library provides utilities to help integrate with a Go application. You will also need a client for your frontend, such as [https://github.com/keratin/authn-js](https://github.com/keratin/authn-js).

[![Godoc](https://godoc.org/github.com/keratin/authn-go/authn?status.svg)](https://godoc.org/github.com/keratin/authn-go/authn)
[![Gitter](https://badges.gitter.im/keratin/authn-server.svg)](https://gitter.im/keratin/authn-server?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)
[![Build Status](https://travis-ci.org/keratin/authn-go.svg?branch=master)](https://travis-ci.org/keratin/authn-go)
[![Go Report](https://goreportcard.com/badge/github.com/keratin/authn-go)](https://goreportcard.com/report/github.com/keratin/authn-go)

## Installation

```bash
go get github.com/keratin/authn-go/authn
```

## Example

```go
package main

import (
  "fmt"
  "github.com/keratin/authn-go/authn"
)

var jwt1 = `<your test jwt here>`

func main() {
  err := authn.Configure(authn.Config{
    // The AUTHN_URL of your Keratin AuthN server. This will be used to verify tokens created by
    // AuthN, and will also be used for API calls unless PrivateBaseURL is also set.
    Issuer:         "https://issuer.example.com",

    // The domain of your application (no protocol). This domain should be listed in the APP_DOMAINS
    // of your Keratin AuthN server.
    Audience:       "application.example.com",

    // Credentials for AuthN's private endpoints. These will be used to execute admin actions using
    // the Client provided by this library.
    //
    // TIP: make them extra secure in production!
    Username:       "<Authn Username>",
    Password:       "<Authn Password>",

    // OPTIONAL: Send private API calls to AuthN using private network routing. This can be
    // necessary if your environment has a firewall to limit public endpoints.
    PrivateBaseURL: "http://private.example.com",
  })
  fmt.Println(err)

  // SubjectFrom will return an AuthN account ID that you can use as to identify the user, if and
  // only if the token is valid.
  sub, err := authn.SubjectFrom(jwt1)
  fmt.Println(sub)
  fmt.Println(err)
}

```
