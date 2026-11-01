package exec

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	errUtils "github.com/cloudposse/atmos/errors"
	"github.com/cloudposse/atmos/pkg/schema"
)

func TestAuthEnvironmentMalformedApplicationDataRendersNormally(t *testing.T) {
	server, calls := structuralKeyServer(t)
	action := fmt.Sprintf(`{{ printf "%%s" (ds %q).token }}`, server.URL)
	config := &schema.AtmosConfiguration{Templates: schema.Templates{Settings: schema.TemplatesSettings{Enabled: true, Gomplate: schema.TemplatesSettingsGomplate{Enabled: true}}}}
	for name, render := range authEnvironmentTemplateRenderers(config) {
		t.Run(name, func(t *testing.T) {
			for kind, source := range malformedApplicationInputs(action) {
				t.Run(kind, func(t *testing.T) {
					var raw yaml.Node
					require.Error(t, yaml.Unmarshal([]byte(source), &raw))
					calls.Store(0)
					output, err := render(source, map[string]any{})
					require.NoError(t, err)
					require.Positive(t, calls.Load(), "application data helpers must remain available outside credential ownership")
					var document map[string]any
					require.NoError(t, yaml.Unmarshal([]byte(output), &document))
					require.Contains(t, output, `TOKEN: "general-value"`)
				})
			}
			t.Run("actual auth rejects before helpers", func(t *testing.T) {
				calls.Store(0)
				source := `auth: {identities: {service: {spec: {env: {TOKEN: "` + action + `"}}}}}`
				output, err := render(source, map[string]any{})
				require.Zero(t, calls.Load())
				require.ErrorIs(t, err, errUtils.ErrInvalidAuthConfig)
				require.Empty(t, output)
			})
		})
	}
}

func malformedApplicationInputs(action string) map[string]string {
	data := `{auth: {identities: {application: {spec: {env: {TOKEN: "` + action + `"}}}}}}`
	result := make(map[string]string)
	for _, section := range []string{"vars", "settings"} {
		result["root "+section] = section + ": " + data + "\n"
		result["component "+section] = "components: {terraform: {example: {" + section + ": " + data + "}}}\n"
	}
	return result
}
