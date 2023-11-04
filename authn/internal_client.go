package authn

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	jose "gopkg.in/square/go-jose.v2"
)

type internalClient struct {
	client   *http.Client
	baseURL  *url.URL
	username string
	password string
}

const (
	delete = "DELETE"
	get    = "GET"
	patch  = "PATCH"
	post   = "POST"
	put    = "PUT"
)

func newInternalClient(base, username, password string) (*internalClient, error) {
	// ensure that base ends with a '/', so ResolveReference() will work as desired
	if base[len(base)-1] != '/' {
		base = base + "/"
	}
	baseURL, err := url.Parse(base)
	if err != nil {
		return nil, err
	}

	return &internalClient{
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		baseURL:  baseURL,
		username: username,
		password: password,
	}, nil
}

// TODO: test coverage
func (ic *internalClient) Key(kid string) ([]jose.JSONWebKey, error) {
	resp, err := http.Get(ic.absoluteURL("jwks"))
	if err != nil {
		return []jose.JSONWebKey{}, err
	}
	defer resp.Body.Close()

	if !isStatusSuccess(resp.StatusCode) {
		return []jose.JSONWebKey{}, fmt.Errorf("Received %d from %s", resp.StatusCode, ic.absoluteURL("jwks"))
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

// GetAccount gets the account details for the specified account id
func (ic *internalClient) GetAccount(id string) (*Account, error) {
	resp, err := ic.doWithAuth(get, "accounts/"+id, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data := struct {
		Result Account `json:"result"`
	}{}

	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		return nil, err
	}

	return &data.Result, nil
}

// Update updates the account with the specified id
func (ic *internalClient) Update(id, username string) error {
	form := url.Values{}
	form.Add("username", username)

	_, err := ic.doWithAuth(patch, "accounts/"+id, strings.NewReader(form.Encode()))
	return err
}

// LockAccount locks the account with the specified id
func (ic *internalClient) LockAccount(id string) error {
	_, err := ic.doWithAuth(patch, "accounts/"+id+"/lock", nil)
	return err
}

// UnlockAccount unlocks the account with the specified id
func (ic *internalClient) UnlockAccount(id string) error {
	_, err := ic.doWithAuth(patch, "accounts/"+id+"/unlock", nil)
	return err
}

// ArchiveAccount archives the account with the specified id
func (ic *internalClient) ArchiveAccount(id string) error {
	_, err := ic.doWithAuth(delete, "accounts/"+id, nil)
	return err
}

// ImportAccount imports an existing account
func (ic *internalClient) ImportAccount(username, password string, locked bool) (int, error) {
	form := url.Values{}
	form.Add("username", username)
	form.Add("password", password)
	form.Add("locked", strconv.FormatBool(locked))

	resp, err := ic.doWithAuth(post, "accounts/import", strings.NewReader(form.Encode()))
	if err != nil {
		return -1, err
	}
	defer resp.Body.Close()

	data := struct {
		Result struct {
			ID int `json:"id"`
		} `json:"result"`
	}{}

	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		return -1, err
	}

	return data.Result.ID, err
}

// ExpirePassword expires the users current sessions and flags the account for a required password change on next login
func (ic *internalClient) ExpirePassword(id string) error {
	_, err := ic.doWithAuth(patch, "accounts/"+id+"/expire_password", nil)
	return err
}

// ServiceStats returns the raw request from the /stats endpoint
func (ic *internalClient) ServiceStats() (*http.Response, error) {
	return ic.doWithAuth(get, "stats", nil)
}

// ServerStats returns the raw request from the /metrics endpoint
func (ic *internalClient) ServerStats() (*http.Response, error) {
	return ic.doWithAuth(get, "metrics", nil)
}

func (ic *internalClient) absoluteURL(path string) string {
	return ic.baseURL.ResolveReference(&url.URL{Path: path}).String()
}

// unused. this will eventually execute private admin actions.
// nolint: unused
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

func (ic *internalClient) doWithAuth(verb string, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(verb, ic.absoluteURL(path), body)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(ic.username, ic.password)

	if verb == post || verb == patch || verb == put {
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	}

	resp, err := ic.client.Do(req)
	if err != nil {
		return nil, err
	}
	if !isStatusSuccess(resp.StatusCode) {
		// try to parse the error response
		var errResp ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
			return nil, fmt.Errorf("received %d from %s", resp.StatusCode, ic.absoluteURL(path))
		}

		errResp.StatusCode = resp.StatusCode
		errResp.URL = ic.absoluteURL(path)
		return nil, &errResp
	}
	return resp, nil
}

func isStatusSuccess(statusCode int) bool {
	return statusCode >= 200 && statusCode < 300
}
