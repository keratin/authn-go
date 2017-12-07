package authn

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	jose "gopkg.in/square/go-jose.v2"
)

type internalClient struct {
	baseURL *url.URL
}

func newInternalClient(base string) (*internalClient, error) {
	baseURL, err := url.Parse(base)
	if err != nil {
		return nil, err
	}

	return &internalClient{baseURL: baseURL}, nil
}

func (ic *internalClient) Key(kid string) ([]jose.JSONWebKey, error) {
	resp, err := http.Get(ic.absoluteURL("jwks"))
	if err != nil {
		return []jose.JSONWebKey{}, err
	}
	defer resp.Body.Close()

	if !isStatusSuccess(resp.StatusCode) {
		return []jose.JSONWebKey{}, fmt.Errorf("Failed to get jwks from jwk url: %s", ic.absoluteURL("jwks"))
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return []jose.JSONWebKey{}, err
	}

	jwks := &jose.JSONWebKeySet{}

	err = json.Unmarshal(bodyBytes, jwks)
	if err != nil {
		return []jose.JSONWebKey{}, err
	}
	return jwks.Key(kid), nil
}

func (ic *internalClient) absoluteURL(path string) string {
	return ic.baseURL.ResolveReference(&url.URL{Path: path}).String()
}

// unused. this will eventually execute private admin actions.
func (ic *internalClient) get(path string, dest interface{}) (int, error) {
	resp, err := http.Get(ic.absoluteURL(path))
	if err != nil {
		return -1, err
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, err
	}

	err = json.Unmarshal(bodyBytes, dest)
	if err != nil {
		return resp.StatusCode, err
	}
	return resp.StatusCode, nil
}

func isStatusSuccess(statusCode int) bool {
	return statusCode >= 200 && statusCode < 300
}
