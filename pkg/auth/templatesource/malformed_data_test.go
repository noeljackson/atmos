package templatesource

import (
	"bytes"
	"testing"
	"text/template"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	errUtils "github.com/cloudposse/atmos/errors"
)

func TestProtectRendersMalformedAuthShapedApplicationData(t *testing.T) {
	action := `{{ printf "%s" (call .ordinary) }}`
	for name, source := range malformedApplicationSources(action) {
		t.Run(name, func(t *testing.T) {
			var raw yaml.Node
			require.Error(t, yaml.Unmarshal([]byte(source), &raw), "raw template must exercise the malformed-YAML fallback")
			_, parseErr := template.New("raw-template").Parse(source)
			require.NoError(t, parseErr, "raw source must remain valid Go template syntax")
			protected, restore, err := Protect(source)
			require.NoError(t, err)
			require.Equal(t, source, protected, "application templates must remain available to ordinary rendering")
			require.Equal(t, source, restore(protected))
			renderer, err := template.New("application").Parse(protected)
			require.NoError(t, err)
			calls := 0
			var output bytes.Buffer
			require.NoError(t, renderer.Execute(&output, map[string]any{"ordinary": func() string { calls++; return "application" }}))
			require.Equal(t, 1, calls)
			var document map[string]any
			require.NoError(t, yaml.Unmarshal([]byte(restore(output.String())), &document))
			require.Contains(t, restore(output.String()), `TOKEN: "application"`)
		})
	}
}

func TestProtectRejectsMalformedOwnedCredentialAction(t *testing.T) {
	source := `auth: {identities: {service: {spec: {env: {TOKEN: "{{ printf "%s" (call .ordinary) }}"}}}}}`
	calls := 0
	protected, _, protectErr := Protect(source)
	if protectErr == nil {
		renderer, err := template.New("credentials").Parse(protected)
		require.NoError(t, err)
		var output bytes.Buffer
		require.NoError(t, renderer.Execute(&output, map[string]any{"ordinary": func() string { calls++; return "must-not-run" }}))
	}
	require.Zero(t, calls, "actual auth must still fail closed when raw YAML is malformed")
	require.ErrorIs(t, protectErr, errUtils.ErrInvalidAuthConfig)
	require.Empty(t, protected)
}

func malformedApplicationSources(action string) map[string]string {
	data := `{auth: {identities: {application: {spec: {env: {TOKEN: "` + action + `"}}}}}}`
	result := make(map[string]string)
	for _, section := range []string{"vars", "settings"} {
		result["root "+section] = section + ": " + data + "\n"
		result["component "+section] = "components: {terraform: {example: {" + section + ": " + data + "}}}\n"
	}
	return result
}
