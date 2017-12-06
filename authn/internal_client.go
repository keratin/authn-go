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
	config       Config
	serverConfig *internalClientServerConfig
	baseURL      *url.URL
}

type internalClientServerConfig struct {
	JwksURI string `json:"jwks_uri"`
}

func newInternalClient(config Config) (*internalClient, error) {
	var err error

	ic := internalClient{
		config: config,
	}

	err = ic.setBaseURLFromConfig()
	if err != nil {
		return nil, err
	}

	err = ic.fetchServerConfig()
	if err != nil {
		return nil, err
	}

	return &ic, nil
}

func (ic *internalClient) setBaseURLFromConfig() error {
	baseURL, err := url.Parse(ic.config.PrivateBaseURL)
	if err != nil {
		return err
	}
	ic.baseURL = baseURL
	return nil
}

func (ic *internalClient) fetchServerConfig() error {
	serverconfig := internalClientServerConfig{}
	statusCode, err := ic.get("/configuration", &serverconfig)

	if isStatusSuccess(statusCode) {
		if err != nil {
			return err
		}
		ic.serverConfig = &serverconfig
		return nil
	}
	return fmt.Errorf("Failed to fetch issuer server configuration.\nStatus Code: %d\nParse Error:%s", statusCode, err)
}

func (ic *internalClient) Key(kid string) ([]jose.JSONWebKey, error) {
	resp, err := http.Get(ic.serverConfig.JwksURI)
	if err != nil {
		return []jose.JSONWebKey{}, err
	}
	defer resp.Body.Close()

	if !isStatusSuccess(resp.StatusCode) {
		return []jose.JSONWebKey{}, fmt.Errorf("Failed to get jwks from jwk url: %s", ic.serverConfig.JwksURI)
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
	if statusCode >= 200 && statusCode < 300 {
		return true
	}
	return false
}
