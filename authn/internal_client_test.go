package authn

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInternalClient(t *testing.T) {
	t.Run("absolute URLs", func(t *testing.T) {
		testCases := []struct {
			baseURL     string
			path        string
			absoluteURL string
		}{
			{"https://authn.keratin.tech", "path", "https://authn.keratin.tech/path"},
			{"https://authn.keratin.tech/", "path", "https://authn.keratin.tech/path"},
			{"https://authn.keratin.tech/dir", "path", "https://authn.keratin.tech/dir/path"},
			{"https://authn.keratin.tech/dir/", "path", "https://authn.keratin.tech/dir/path"},
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
