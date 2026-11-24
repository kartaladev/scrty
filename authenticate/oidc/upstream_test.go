package oidc_test

import (
	"bytes"
	"fmt"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/authenticate/oidc"
)

func TestUpstream_NeverPrintsToken(t *testing.T) {
	t.Parallel()

	up := oidc.NewUpstreamForTest(upstreamAccessToken, "s-1", nil, nil)

	type exported struct{ Up oidc.Upstream }
	type unexported struct{ up oidc.Upstream }
	type pointed struct{ up *oidc.Upstream }

	logJSON := func(v any) string {
		var buf bytes.Buffer
		slog.New(slog.NewJSONHandler(&buf, nil)).Info("m", slog.Any("upstream", v))
		return buf.String()
	}

	type testCase struct {
		name   string
		render func() string
		assert func(t *testing.T, out string)
	}
	redacted := func(t *testing.T, out string) {
		t.Helper()
		assert.NotContains(t, out, upstreamAccessToken)
		assert.NotEmpty(t, out)
	}
	cases := []testCase{
		{name: "%v", render: func() string { return fmt.Sprintf("%v", up) }, assert: func(t *testing.T, out string) {
			redacted(t, out)
			assert.Equal(t, "[redacted]", out)
		}},
		{name: "%+v", render: func() string { return fmt.Sprintf("%+v", up) }, assert: redacted},
		{name: "%#v", render: func() string { return fmt.Sprintf("%#v", up) }, assert: redacted},
		{name: "%s", render: func() string { return fmt.Sprintf("%s", up) }, assert: redacted},
		{name: "%q", render: func() string { return fmt.Sprintf("%q", up) }, assert: redacted},
		{name: "%x", render: func() string { return fmt.Sprintf("%x", up) }, assert: redacted},
		{name: "String", render: func() string { return up.String() }, assert: redacted},
		{name: "pointer %+v", render: func() string { return fmt.Sprintf("%+v", &up) }, assert: redacted},
		{name: "slog JSON attribute", render: func() string { return logJSON(up) }, assert: func(t *testing.T, out string) {
			redacted(t, out)
			assert.Contains(t, out, `"upstream":"[redacted]"`)
		}},
		{name: "slog text attribute", render: func() string {
			var buf bytes.Buffer
			slog.New(slog.NewTextHandler(&buf, nil)).Info("m", "upstream", up)
			return buf.String()
		}, assert: redacted},
		{name: "exported field %+v", render: func() string { return fmt.Sprintf("%+v", exported{Up: up}) }, assert: redacted},
		{name: "exported field %#v", render: func() string { return fmt.Sprintf("%#v", exported{Up: up}) }, assert: redacted},
		{name: "unexported field %+v", render: func() string { return fmt.Sprintf("%+v", unexported{up: up}) }, assert: redacted},
		{name: "unexported field %#v", render: func() string { return fmt.Sprintf("%#v", unexported{up: up}) }, assert: redacted},
		{name: "unexported pointer field %+v", render: func() string { return fmt.Sprintf("%+v", pointed{up: &up}) }, assert: redacted},
		{name: "unexported field in a slog JSON attribute", render: func() string { return logJSON(unexported{up: up}) }, assert: redacted},
		{name: "exported field in a slog JSON attribute", render: func() string { return logJSON(exported{Up: up}) }, assert: redacted},
		{name: "slice %v", render: func() string { return fmt.Sprintf("%v", []oidc.Upstream{up}) }, assert: redacted},
		{name: "map value %+v", render: func() string { return fmt.Sprintf("%+v", map[string]unexported{"k": {up: up}}) }, assert: redacted},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, tc.render())
		})
	}
}
