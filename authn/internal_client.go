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
	baseUrl      *url.URL
}

type internalClientServerConfig struct {
	JwksUri string `json:"jwks_uri"`
}

func newInternalClient(config Config) (*internalClient, error) {
	var err error

	ic := internalClient{
		config: config,
	}

	err = ic.init_base_url()
	if err != nil {
		return nil, err
	}

	err = ic.init_server_config()
	if err != nil {
		return nil, err
	}

	return &ic, nil
}

func (ic *internalClient) init_base_url() error {
	baseUrl, err := url.Parse(ic.config.PrivateBaseUrl)
	if err != nil {
		return err
	}
	ic.baseUrl = baseUrl
	return nil
}

func (ic *internalClient) init_server_config() error {
	serverconfig := internalClientServerConfig{}
	status_code, err := ic._http_get("/configuration", &serverconfig)

	if is_status_success(status_code) {
		if err != nil {
			return err
		} else {
			ic.serverConfig = &serverconfig
			return nil
		}
	} else {
		return fmt.Errorf("Failed to fetch issuer server configuration.\nStatus Code: %d\nParse Error:%s", status_code, err)
	}
}

func (ic *internalClient) get_signing_key(kid string) (jose.JSONWebKey, error) {
	resp, err := http.Get(ic.serverConfig.JwksUri)
	if err != nil {
		return jose.JSONWebKey{}, err
	}
	defer resp.Body.Close()

	if !is_status_success(resp.StatusCode) {
		return jose.JSONWebKey{}, fmt.Errorf("Failed to get jwks from jwk url: %s", ic.serverConfig.JwksUri)
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return jose.JSONWebKey{}, err
	}

	jwks := &jose.JSONWebKeySet{}

	err = json.Unmarshal(bodyBytes, jwks)
	if err != nil {
		return jose.JSONWebKey{}, err
	}
	jwk_list := jwks.Key(kid)
	if len(jwk_list) == 0 {
		return jose.JSONWebKey{}, fmt.Errorf("Unable to find kid:%v in jwks", kid)
	}
	return jwk_list[0], nil
}

func (ic *internalClient) get_full_url(location string) string {
	relativeUrl, err := url.Parse(location)
	if err != nil {
		panic(err)
	}

	return ic.baseUrl.ResolveReference(relativeUrl).String()
}

func (ic *internalClient) _http_get(location string, dest interface{}) (int, error) {
	resp, err := http.Get(ic.get_full_url(location))
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

func is_status_success(status_code int) bool {
	if status_code >= 200 && status_code < 300 {
		return true
	}
	return false
}
