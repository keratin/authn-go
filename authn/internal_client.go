package authn

import (
	"encoding/json"
	"fmt"
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

//GetAccount gets the account details for the specified account id
func (ic *internalClient) GetAccount(id string) (*Account, error) {
	//Setup the request
	req, err := http.NewRequest("GET", ic.absoluteURL("accounts/"+id), nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(ic.username, ic.password)

	//Do the request
	resp, err := ic.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("received %d from %s", resp.StatusCode, ic.absoluteURL("accounts/"+id))
	}

	//Marshal the result
	data := struct {
		Result Account `json:"result"`
	}{}

	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		return nil, err
	}

	return &data.Result, nil
}

//Update updates the account with the specified id
func (ic *internalClient) Update(id, username string) error {
	//Setup request body
	form := url.Values{}
	form.Add("username", username)

	//Setup the request
	req, err := http.NewRequest("PATCH", ic.absoluteURL("accounts/"+id), strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.SetBasicAuth(ic.username, ic.password)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	//Do the request
	resp, err := ic.client.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("received %d from %s", resp.StatusCode, ic.absoluteURL("accounts/"+id))
	}

	return nil
}

//LockAccount locks the account with the specified id
func (ic *internalClient) LockAccount(id string) error {
	//Setup the request
	req, err := http.NewRequest("PATCH", ic.absoluteURL("accounts/"+id+"/lock"), nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(ic.username, ic.password)

	//Do the request
	resp, err := ic.client.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("received %d from %s", resp.StatusCode, ic.absoluteURL("accounts/"+id+"/lock"))
	}

	return nil
}

//UnlockAccount unlocks the account with the specified id
func (ic *internalClient) UnlockAccount(id string) error {
	//Setup the request
	req, err := http.NewRequest("PATCH", ic.absoluteURL("accounts/"+id+"/unlock"), nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(ic.username, ic.password)

	//Do the request
	resp, err := ic.client.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("received %d from %s", resp.StatusCode, ic.absoluteURL("accounts/"+id+"/unlock"))
	}

	return nil
}

//ArchiveAccount archives the account with the specified id
func (ic *internalClient) ArchiveAccount(id string) error {
	//Setup the request
	req, err := http.NewRequest("DELETE", ic.absoluteURL("accounts/"+id), nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(ic.username, ic.password)

	//Do the request
	resp, err := ic.client.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("received %d from %s", resp.StatusCode, ic.absoluteURL("accounts/"+id))
	}

	return nil
}

//ImportAccount imports an existing account
func (ic *internalClient) ImportAccount(username, password string, locked bool) error {
	//Setup request body
	form := url.Values{}
	form.Add("username", username)
	form.Add("password", password)
	form.Add("locked", strconv.FormatBool(locked))

	//Setup the request
	req, err := http.NewRequest("POST", ic.absoluteURL("accounts/import"), strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.SetBasicAuth(ic.username, ic.password)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	//Do the request
	resp, err := ic.client.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != 201 {
		return fmt.Errorf("received %d from %s", resp.StatusCode, ic.absoluteURL("accounts/import"))
	}

	return nil
}

//ExpirePassword expires the users current sessions and flags the account for a required password change on next login
func (ic *internalClient) ExpirePassword(id string) error {
	//Setup the request
	req, err := http.NewRequest("PATCH", ic.absoluteURL("accounts/"+id+"/expire_password"), nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(ic.username, ic.password)

	//Do the request
	resp, err := ic.client.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("received %d from %s", resp.StatusCode, ic.absoluteURL("accounts/"+id+"/expire_password"))
	}

	return nil
}

//ServiceStats returns the raw request from the /stats endpoint
func (ic *internalClient) ServiceStats() (*http.Response, error) {
	//Setup the request
	req, err := http.NewRequest("GET", ic.absoluteURL("stats"), nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(ic.username, ic.password)

	//Do the request
	return ic.client.Do(req)
}

//ServerStats returns the raw request from the /metrics endpoint
func (ic *internalClient) ServerStats() (*http.Response, error) {
	//Setup the request
	req, err := http.NewRequest("GET", ic.absoluteURL("metrics"), nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(ic.username, ic.password)

	//Do the request
	return ic.client.Do(req)
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
