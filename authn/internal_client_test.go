package authn

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInternalClient(t *testing.T) {
	t.Run("absoluteURL", func(t *testing.T) {
		testCases := []struct {
			baseURL     string
			path        string
			absoluteURL string
		}{
			{"https://authn.keratin.tech", "path", "https://authn.keratin.tech/path"},
			{"https://authn.keratin.tech/", "path", "https://authn.keratin.tech/path"},
			{"https://keratin.tech/authn", "path", "https://keratin.tech/authn/path"},
			{"https://keratin.tech/authn/", "path", "https://keratin.tech/authn/path"},
		}

		for _, tc := range testCases {
			t.Run(tc.baseURL, func(t *testing.T) {
				ic, err := newInternalClient(tc.baseURL, "username", "password")
				require.NoError(t, err)
				assert.Equal(t, tc.absoluteURL, ic.absoluteURL(tc.path))
			})
		}
	})
}

func testingHTTPClient(handler http.Handler) (*http.Client, func()) {
	s := httptest.NewServer(handler)

	cli := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, network, _ string) (net.Conn, error) {
				return net.Dial(network, s.Listener.Addr().String())
			},
		},
	}

	return cli, s.Close
}

//Based on information at https://keratin.github.io/authn-server/#/api?id=get-account
func TestICGetAccount(t *testing.T) {
	type request struct {
		url        string
		htusername string
		htpassword string
		id         string
	}
	type response struct {
		id       int
		username string
		locked   bool
		deleted  bool
		code     int
		errorMsg string
	}
	testCases := []struct {
		request  request
		response response
	}{
		{
			request: request{
				url:        "http://test.com",
				htusername: "username",
				htpassword: "password",
				id:         "1",
			},
			response: response{
				id:       1,
				username: "test@test.com",
				locked:   true,
				deleted:  true,
				code:     http.StatusOK,
				errorMsg: "",
			},
		},
		{
			request: request{
				url:        "http://test.com",
				htusername: "username",
				htpassword: "password",
				id:         "1",
			},
			response: response{
				code:     http.StatusNotFound,
				errorMsg: "received 404 from http://test.com/accounts/1",
			},
		},
	}

	for _, tc := range testCases {
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			username, password, ok := r.BasicAuth()
			assert.Equal(t, true, ok)
			assert.Equal(t, http.MethodGet, r.Method)
			assert.Equal(t, tc.request.htusername, username)
			assert.Equal(t, tc.request.htpassword, password)
			assert.Equal(t, "/accounts/"+tc.request.id, r.URL.Path)
			w.WriteHeader(tc.response.code)
			//if we're mocking a good request, return the json
			if tc.response.code == http.StatusOK {
				w.Write([]byte(`{
					"result": {
						"id": ` + strconv.Itoa(tc.response.id) + `,
						"username": "` + tc.response.username + `",
						"locked": ` + strconv.FormatBool(tc.response.locked) + `,
						"deleted": ` + strconv.FormatBool(tc.response.deleted) + `
					}
				}`))
			}
		})
		httpClient, teardown := testingHTTPClient(h)
		defer teardown()

		cli, err := newInternalClient(tc.request.url, tc.request.htusername, tc.request.htpassword)
		if err != nil {
			t.Fatal(err)
		}
		cli.client = httpClient

		account, err := cli.GetAccount(tc.request.id)
		if tc.response.errorMsg == "" { //Expecting no error
			assert.Nil(t, err)
			assert.Equal(t, tc.response.id, account.ID)
			assert.Equal(t, tc.response.username, account.Username)
			assert.Equal(t, tc.response.locked, account.Locked)
			assert.Equal(t, tc.response.deleted, account.Deleted)
		} else { //Expecting an error
			assert.Equal(t, tc.response.errorMsg, err.Error())
		}
	}
}

//Based on information at https://keratin.github.io/authn-server/#/api?id=update
func TestICUpdate(t *testing.T) {
	type request struct {
		url        string
		htusername string
		htpassword string
		id         string
		username   string
	}
	type response struct {
		code     int
		errorMsg string
	}
	testCases := []struct {
		request  request
		response response
	}{
		{
			request: request{
				url:        "http://test.com",
				htusername: "username",
				htpassword: "password",
				id:         "1",
				username:   "test@test.com",
			},
			response: response{
				code:     http.StatusOK,
				errorMsg: "",
			},
		},
		{
			request: request{
				url:        "http://test.com",
				htusername: "username",
				htpassword: "password",
				id:         "1",
				username:   "test@test.com",
			},
			response: response{
				code:     http.StatusNotFound,
				errorMsg: "received 404 from http://test.com/accounts/1",
			},
		},
		{
			request: request{
				url:        "http://test.com",
				htusername: "username",
				htpassword: "password",
				id:         "1",
				username:   "test@test.com",
			},
			response: response{
				code:     http.StatusUnprocessableEntity,
				errorMsg: "received 422 from http://test.com/accounts/1",
			},
		},
	}

	for _, tc := range testCases {
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			username, password, ok := r.BasicAuth()
			assert.Equal(t, ok, true)
			assert.Equal(t, http.MethodPatch, r.Method)
			assert.Equal(t, tc.request.htusername, username)
			assert.Equal(t, tc.request.htpassword, password)
			assert.Equal(t, tc.request.username, r.PostFormValue("username"))
			assert.Equal(t, "/accounts/"+tc.request.id, r.URL.Path)
			w.WriteHeader(tc.response.code)
		})
		httpClient, teardown := testingHTTPClient(h)
		defer teardown()

		cli, err := newInternalClient(tc.request.url, tc.request.htusername, tc.request.htpassword)
		if err != nil {
			t.Fatal(err)
		}
		cli.client = httpClient

		err = cli.Update(tc.request.id, tc.request.username)
		if tc.response.errorMsg == "" { //Expecting no error
			assert.Nil(t, err)
		} else { //Expecting an error
			assert.Equal(t, tc.response.errorMsg, err.Error())
		}
	}
}

//Based on information at https://keratin.github.io/authn-server/#/api?id=lock-account
func TestICLockAccount(t *testing.T) {
	type request struct {
		url        string
		htusername string
		htpassword string
		id         string
	}
	type response struct {
		code     int
		errorMsg string
	}
	testCases := []struct {
		request  request
		response response
	}{
		{
			request: request{
				url:        "http://test.com",
				htusername: "username",
				htpassword: "password",
				id:         "1",
			},
			response: response{
				code:     http.StatusOK,
				errorMsg: "",
			},
		},
		{
			request: request{
				url:        "http://test.com",
				htusername: "username",
				htpassword: "password",
				id:         "1",
			},
			response: response{
				code:     http.StatusNotFound,
				errorMsg: "received 404 from http://test.com/accounts/1/lock",
			},
		},
	}

	for _, tc := range testCases {
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			username, password, ok := r.BasicAuth()
			assert.Equal(t, ok, true)
			assert.Equal(t, http.MethodPatch, r.Method)
			assert.Equal(t, tc.request.htusername, username)
			assert.Equal(t, tc.request.htpassword, password)
			assert.Equal(t, "/accounts/"+tc.request.id+"/lock", r.URL.Path)
			w.WriteHeader(tc.response.code)
		})
		httpClient, teardown := testingHTTPClient(h)
		defer teardown()

		cli, err := newInternalClient(tc.request.url, tc.request.htusername, tc.request.htpassword)
		if err != nil {
			t.Fatal(err)
		}
		cli.client = httpClient

		err = cli.LockAccount(tc.request.id)
		if tc.response.errorMsg == "" { //Expecting no error
			assert.Nil(t, err)
		} else { //Expecting an error
			assert.Equal(t, tc.response.errorMsg, err.Error())
		}
	}
}

//Based on information at https://keratin.github.io/authn-server/#/api?id=unlock-account
func TestICUnlockAccount(t *testing.T) {
	type request struct {
		url        string
		htusername string
		htpassword string
		id         string
	}
	type response struct {
		code     int
		errorMsg string
	}
	testCases := []struct {
		request  request
		response response
	}{
		{
			request: request{
				url:        "http://test.com",
				htusername: "username",
				htpassword: "password",
				id:         "1",
			},
			response: response{
				code:     http.StatusOK,
				errorMsg: "",
			},
		},
		{
			request: request{
				url:        "http://test.com",
				htusername: "username",
				htpassword: "password",
				id:         "1",
			},
			response: response{
				code:     http.StatusNotFound,
				errorMsg: "received 404 from http://test.com/accounts/1/unlock",
			},
		},
	}

	for _, tc := range testCases {
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			username, password, ok := r.BasicAuth()
			assert.Equal(t, ok, true)
			assert.Equal(t, http.MethodPatch, r.Method)
			assert.Equal(t, tc.request.htusername, username)
			assert.Equal(t, tc.request.htpassword, password)
			assert.Equal(t, "/accounts/"+tc.request.id+"/unlock", r.URL.Path)
			w.WriteHeader(tc.response.code)
		})
		httpClient, teardown := testingHTTPClient(h)
		defer teardown()

		cli, err := newInternalClient(tc.request.url, tc.request.htusername, tc.request.htpassword)
		if err != nil {
			t.Fatal(err)
		}
		cli.client = httpClient

		err = cli.UnlockAccount(tc.request.id)
		if tc.response.errorMsg == "" { //Expecting no error
			assert.Nil(t, err)
		} else { //Expecting an error
			assert.Equal(t, tc.response.errorMsg, err.Error())
		}
	}
}

//Based on information at https://keratin.github.io/authn-server/#/api?id=archive-account
func TestICArchiveAccount(t *testing.T) {
	type request struct {
		url        string
		htusername string
		htpassword string
		id         string
	}
	type response struct {
		code     int
		errorMsg string
	}
	testCases := []struct {
		request  request
		response response
	}{
		{
			request: request{
				url:        "http://test.com",
				htusername: "username",
				htpassword: "password",
				id:         "1",
			},
			response: response{
				code:     http.StatusOK,
				errorMsg: "",
			},
		},
		{
			request: request{
				url:        "http://test.com",
				htusername: "username",
				htpassword: "password",
				id:         "1",
			},
			response: response{
				code:     http.StatusNotFound,
				errorMsg: "received 404 from http://test.com/accounts/1",
			},
		},
	}

	for _, tc := range testCases {
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			username, password, ok := r.BasicAuth()
			assert.Equal(t, ok, true)
			assert.Equal(t, http.MethodDelete, r.Method)
			assert.Equal(t, tc.request.htusername, username)
			assert.Equal(t, tc.request.htpassword, password)
			assert.Equal(t, "/accounts/"+tc.request.id, r.URL.Path)
			w.WriteHeader(tc.response.code)
		})
		httpClient, teardown := testingHTTPClient(h)
		defer teardown()

		cli, err := newInternalClient(tc.request.url, tc.request.htusername, tc.request.htpassword)
		if err != nil {
			t.Fatal(err)
		}
		cli.client = httpClient

		err = cli.ArchiveAccount(tc.request.id)
		if tc.response.errorMsg == "" { //Expecting no error
			assert.Nil(t, err)
		} else { //Expecting an error
			assert.Equal(t, tc.response.errorMsg, err.Error())
		}
	}
}

//Based on information at https://keratin.github.io/authn-server/#/api?id=import-account
func TestICImportAccount(t *testing.T) {
	type request struct {
		url        string
		htusername string
		htpassword string
		username   string
		password   string
		locked     bool
	}
	type response struct {
		code     int
		id       int
		errorMsg string
	}
	testCases := []struct {
		request  request
		response response
	}{
		{
			request: request{
				url:        "http://test.com",
				htusername: "username",
				htpassword: "password",
				username:   "username",
				password:   "password",
				locked:     true,
			},
			response: response{
				code:     http.StatusCreated,
				id:       12345,
				errorMsg: "",
			},
		},
		{
			request: request{
				url:        "http://test.com",
				htusername: "username",
				htpassword: "password",
				username:   "username",
				password:   "password",
				locked:     true,
			},
			response: response{
				code:     http.StatusUnprocessableEntity,
				errorMsg: "received 422 from http://test.com/accounts/import",
			},
		},
	}

	for _, tc := range testCases {
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			username, password, ok := r.BasicAuth()
			assert.Equal(t, ok, true)
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, tc.request.htusername, username)
			assert.Equal(t, tc.request.htpassword, password)
			assert.Equal(t, tc.request.username, r.PostFormValue("username"))
			assert.Equal(t, tc.request.password, r.PostFormValue("password"))
			assert.Equal(t, strconv.FormatBool(tc.request.locked), r.PostFormValue("locked"))
			assert.Equal(t, "/accounts/import", r.URL.Path)
			w.WriteHeader(tc.response.code)
			if tc.response.code == http.StatusCreated {
				w.Write([]byte(`{
					"result": {
						"id": ` + strconv.Itoa(tc.response.id) + `
					}
				}`))
			}
		})
		httpClient, teardown := testingHTTPClient(h)
		defer teardown()

		cli, err := newInternalClient(tc.request.url, tc.request.htusername, tc.request.htpassword)
		if err != nil {
			t.Fatal(err)
		}
		cli.client = httpClient

		id, err := cli.ImportAccount(tc.request.username, tc.request.password, tc.request.locked)
		if tc.response.errorMsg == "" { //Expecting no error
			assert.Nil(t, err)
			assert.Equal(t, tc.response.id, id)
		} else { //Expecting an error
			assert.Equal(t, tc.response.errorMsg, err.Error())
		}
	}
}

//Based on information at https://keratin.github.io/authn-server/#/api?id=expire-password
func TestICExpirePassword(t *testing.T) {
	type request struct {
		url        string
		htusername string
		htpassword string
		id         string
	}
	type response struct {
		code     int
		errorMsg string
	}
	testCases := []struct {
		request  request
		response response
	}{
		{
			request: request{
				url:        "http://test.com",
				htusername: "username",
				htpassword: "password",
				id:         "1",
			},
			response: response{
				code:     http.StatusOK,
				errorMsg: "",
			},
		},
		{
			request: request{
				url:        "http://test.com",
				htusername: "username",
				htpassword: "password",
				id:         "1",
			},
			response: response{
				code:     http.StatusNotFound,
				errorMsg: "received 404 from http://test.com/accounts/1/expire_password",
			},
		},
	}

	for _, tc := range testCases {
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			username, password, ok := r.BasicAuth()
			assert.Equal(t, ok, true)
			assert.Equal(t, http.MethodPatch, r.Method)
			assert.Equal(t, tc.request.htusername, username)
			assert.Equal(t, tc.request.htpassword, password)
			assert.Equal(t, "/accounts/"+tc.request.id+"/expire_password", r.URL.Path)
			w.WriteHeader(tc.response.code)
		})
		httpClient, teardown := testingHTTPClient(h)
		defer teardown()

		cli, err := newInternalClient(tc.request.url, tc.request.htusername, tc.request.htpassword)
		if err != nil {
			t.Fatal(err)
		}
		cli.client = httpClient

		err = cli.ExpirePassword(tc.request.id)
		if tc.response.errorMsg == "" { //Expecting no error
			assert.Nil(t, err)
		} else { //Expecting an error
			assert.Equal(t, tc.response.errorMsg, err.Error())
		}
	}
}

//Based on information at https://keratin.github.io/authn-server/#/api?id=service-stats
func TestICServiceStats(t *testing.T) {
	type request struct {
		url        string
		htusername string
		htpassword string
	}
	testCases := []struct {
		request request
	}{
		{
			request: request{
				url:        "http://test.com",
				htusername: "username",
				htpassword: "password",
			},
		},
	}

	for _, tc := range testCases {
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			username, password, ok := r.BasicAuth()
			assert.Equal(t, ok, true)
			assert.Equal(t, http.MethodGet, r.Method)
			assert.Equal(t, tc.request.htusername, username)
			assert.Equal(t, tc.request.htpassword, password)
			assert.Equal(t, "/stats", r.URL.Path)
		})
		httpClient, teardown := testingHTTPClient(h)
		defer teardown()

		cli, err := newInternalClient(tc.request.url, tc.request.htusername, tc.request.htpassword)
		if err != nil {
			t.Fatal(err)
		}
		cli.client = httpClient

		_, err = cli.ServiceStats()
		assert.Nil(t, err)
	}
}

//Based on information at https://keratin.github.io/authn-server/#/api?id=server-stats
func TestICServerStats(t *testing.T) {
	type request struct {
		url        string
		htusername string
		htpassword string
	}
	testCases := []struct {
		request request
	}{
		{
			request: request{
				url:        "http://test.com",
				htusername: "username",
				htpassword: "password",
			},
		},
	}

	for _, tc := range testCases {
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			username, password, ok := r.BasicAuth()
			assert.Equal(t, ok, true)
			assert.Equal(t, http.MethodGet, r.Method)
			assert.Equal(t, tc.request.htusername, username)
			assert.Equal(t, tc.request.htpassword, password)
			assert.Equal(t, "/metrics", r.URL.Path)
		})
		httpClient, teardown := testingHTTPClient(h)
		defer teardown()

		cli, err := newInternalClient(tc.request.url, tc.request.htusername, tc.request.htpassword)
		if err != nil {
			t.Fatal(err)
		}
		cli.client = httpClient

		_, err = cli.ServerStats()
		assert.Nil(t, err)
	}
}

func TestICErrorResponses(t *testing.T) {
	type request struct {
		url        string
		htusername string
		htpassword string
		id         string
	}
	type response struct {
		code int
		body string
	}

	testCases := []struct {
		request     request
		response    response
		errorFields map[string]string
		errMsg      string
	}{
		{
			request: request{
				url:        "http://test.com",
				htusername: "user",
				htpassword: "password",
				id:         "1",
			},
			response: response{
				code: http.StatusOK,
			},
			errorFields: nil,
		},
		{
			request: request{
				url:        "http://test.com",
				htusername: "user",
				htpassword: "password",
				id:         "1",
			},
			response: response{
				code: http.StatusNotFound,
				body: `{"errors":[{"field": "id", "message": "NOT_FOUND"}]}`,
			},
			errorFields: map[string]string{
				"id": "NOT_FOUND",
			},
			errMsg: "received 404 from http://test.com/accounts/1/expire_password. Errors in id: NOT_FOUND",
		},
		{
			request: request{
				url:        "http://test.com",
				htusername: "user",
				htpassword: "password",
				id:         "1",
			},
			response: response{
				code: http.StatusInternalServerError,
				body: `{
					"errors": [
						{"field": "field1", "message": "Error-Message-1"},
						{"field": "field2", "message": "Error-Message-2"}
					]
				}`,
			},
			errorFields: map[string]string{
				"field1": "Error-Message-1",
				"field2": "Error-Message-2",
			},
			errMsg: "received 500 from http://test.com/accounts/1/expire_password. Errors in field1: Error-Message-1; field2: Error-Message-2",
		},
	}

	for _, tc := range testCases {
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			username, password, ok := r.BasicAuth()
			assert.Equal(t, ok, true)
			assert.Equal(t, http.MethodPatch, r.Method)
			assert.Equal(t, tc.request.htusername, username)
			assert.Equal(t, tc.request.htpassword, password)

			w.WriteHeader(tc.response.code)
			if tc.response.code != http.StatusOK {
				w.Write([]byte(tc.response.body))
			}
		})

		httpClient, teardown := testingHTTPClient(h)
		defer teardown()

		cli, err := newInternalClient(tc.request.url, tc.request.htusername, tc.request.htpassword)
		if err != nil {
			t.Fatal(err)
		}

		cli.client = httpClient

		err = cli.ExpirePassword(tc.request.id)
		if tc.errorFields == nil {
			assert.NoError(t, err)
		} else {
			errResp, ok := err.(*ErrorResponse)
			if !ok {
				t.Fatal("error must be ErrorResponse")
			}

			assert.Equal(t, tc.response.code, errResp.StatusCode)
			assert.Equal(t, tc.errMsg, err.Error())

			// check all expected field errors
			for field, expMsg := range tc.errorFields {
				assert.True(t, errResp.HasField(field))
				msg, ok := errResp.Field(field)
				assert.True(t, ok)
				assert.Equal(t, expMsg, msg)
			}

			// make sure there aren't any errors other than the
			// expected ones
			for _, fe := range errResp.Errors {
				_, ok := tc.errorFields[fe.Field]
				assert.True(t, ok)
			}
		}
	}
}
