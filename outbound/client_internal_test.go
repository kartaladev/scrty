// The construction tests are in the package rather than beside it, because what
// they pin is the defaults New applies. A default that nothing overrides has no
// observable behaviour to assert from outside without waiting for it — ten
// seconds, in the timeout's case — so the fields are read directly here, and
// every behaviour built on them is asserted from outside in client_test.go.
package outbound

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOutboundConstruction(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []Option
		assert func(t *testing.T, c *Client, err error)
	}

	// refusedBy asserts a wiring mistake is refused at construction, and that
	// the message names the option at fault so the consumer knows what to change.
	refusedBy := func(option string) func(t *testing.T, c *Client, err error) {
		return func(t *testing.T, c *Client, err error) {
			require.ErrorIs(t, err, ErrConfig)
			assert.Nil(t, c)
			assert.Contains(t, err.Error(), option)
		}
	}

	cases := []testCase{
		{
			name: "no options at all: https only, ten hops, ten seconds, one mebibyte",
			assert: func(t *testing.T, c *Client, err error) {
				require.NoError(t, err)
				require.NotNil(t, c)
				assert.Equal(t, []string{"https"}, c.schemes)
				assert.Empty(t, c.origins)
				assert.Equal(t, 10, c.maxRedirects)
				assert.Equal(t, 10*time.Second, c.timeout)
				assert.Equal(t, int64(1<<20), c.maxBytes)
				assert.NotNil(t, c.hc)
			},
		},
		{
			name: "http is added to the default, never replacing it",
			opts: []Option{WithAllowedSchemes("http")},
			assert: func(t *testing.T, c *Client, err error) {
				require.NoError(t, err)
				assert.ElementsMatch(t, []string{"https", "http"}, c.schemes)
			},
		},
		{
			name: "allowing https again is not a mistake",
			opts: []Option{WithAllowedSchemes("https")},
			assert: func(t *testing.T, c *Client, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"https"}, c.schemes)
			},
		},
		{
			name: "no redirect is followed, which is a configuration and not a mistake",
			opts: []Option{WithMaxRedirects(0)},
			assert: func(t *testing.T, c *Client, err error) {
				require.NoError(t, err)
				assert.Equal(t, 0, c.maxRedirects)
			},
		},
		{
			name: "an origin without a path is declared",
			opts: []Option{WithAllowedOrigins("https://idp.example.com:443", "http://localhost:8080/")},
			assert: func(t *testing.T, c *Client, err error) {
				require.NoError(t, err)
				assert.Len(t, c.origins, 2)
			},
		},
		{
			name:   "a scheme that is neither http nor https",
			opts:   []Option{WithAllowedSchemes("ftp")},
			assert: refusedBy("WithAllowedSchemes"),
		},
		{
			name:   "the file scheme",
			opts:   []Option{WithAllowedSchemes("file")},
			assert: refusedBy("WithAllowedSchemes"),
		},
		{
			name:   "an empty scheme",
			opts:   []Option{WithAllowedSchemes("")},
			assert: refusedBy("WithAllowedSchemes"),
		},
		{
			name:   "a negative redirect cap",
			opts:   []Option{WithMaxRedirects(-1)},
			assert: refusedBy("WithMaxRedirects"),
		},
		{
			name:   "a bound of no time at all",
			opts:   []Option{WithTimeout(0)},
			assert: refusedBy("WithTimeout"),
		},
		{
			name:   "a negative bound",
			opts:   []Option{WithTimeout(-time.Second)},
			assert: refusedBy("WithTimeout"),
		},
		{
			name:   "a response limit of nothing",
			opts:   []Option{WithMaxResponseBytes(0)},
			assert: refusedBy("WithMaxResponseBytes"),
		},
		{
			name:   "a negative response limit",
			opts:   []Option{WithMaxResponseBytes(-1)},
			assert: refusedBy("WithMaxResponseBytes"),
		},
		{
			name:   "no client at all",
			opts:   []Option{WithHTTPClient(nil)},
			assert: refusedBy("WithHTTPClient"),
		},
		{
			name:   "an origin carrying a path",
			opts:   []Option{WithAllowedOrigins("https://idp.example.com/path")},
			assert: refusedBy("WithAllowedOrigins"),
		},
		{
			name:   "an origin carrying a query",
			opts:   []Option{WithAllowedOrigins("https://idp.example.com?tenant=a")},
			assert: refusedBy("WithAllowedOrigins"),
		},
		{
			name:   "an origin carrying userinfo",
			opts:   []Option{WithAllowedOrigins("https://user@idp.example.com")},
			assert: refusedBy("WithAllowedOrigins"),
		},
		{
			name:   "an origin that is not an absolute http or https URL",
			opts:   []Option{WithAllowedOrigins("idp.example.com")},
			assert: refusedBy("WithAllowedOrigins"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := New(tc.opts...)
			tc.assert(t, c, err)
		})
	}
}

// TestOutboundConsumerClientIsCopied pins that the consumer's own client is left
// as it was. It is a single case with its own shape, so it stays outside the
// construction table.
func TestOutboundConsumerClientIsCopied(t *testing.T) {
	t.Parallel()

	consumer := &http.Client{Timeout: time.Minute}

	c, err := New(WithHTTPClient(consumer))
	require.NoError(t, err)

	assert.Nil(t, consumer.CheckRedirect, "the consumer's client must not be mutated")
	assert.NotSame(t, consumer, c.hc)
	assert.NotNil(t, c.hc.CheckRedirect)
	assert.Equal(t, time.Minute, c.hc.Timeout, "the copy keeps everything else the consumer configured")
}
