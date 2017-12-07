package authn

import (
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
				ic, err := newInternalClient(tc.baseURL)
				require.NoError(t, err)
				assert.Equal(t, tc.absoluteURL, ic.absoluteURL(tc.path))
			})
		}
	})
}
