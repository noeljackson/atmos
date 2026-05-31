package hetzner_project

import (
	"context"
	"testing"

	"github.com/cloudposse/atmos/pkg/auth/credentials"
	"github.com/cloudposse/atmos/pkg/auth/types"
	"github.com/cloudposse/atmos/pkg/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIdentityAuthenticateOverridesProviderCredentials(t *testing.T) {
	identity, err := New(&types.HetznerProjectIdentityPrincipal{
		Project:  "system",
		Token:    "identity-token",
		TokenEnv: []string{"TF_VAR_HCLOUD_TOKEN_SYSTEM"},
	})
	require.NoError(t, err)
	identity.SetName("system")
	identity.SetConfig(&schema.Identity{
		Via: &schema.IdentityVia{Provider: "hetzner"},
		Credentials: map[string]interface{}{
			"s3_access_key_id":     "access",
			"s3_secret_access_key": "secret",
			"s3_endpoint":          "https://hel1.your-objectstorage.com",
			"s3_region":            "hel1",
		},
	})

	creds, err := identity.Authenticate(context.Background(), &types.HetznerCredentials{Token: "provider-token"})

	require.NoError(t, err)
	hetznerCreds, ok := creds.(*types.HetznerCredentials)
	require.True(t, ok)
	assert.Equal(t, "system", hetznerCreds.Project)
	assert.Equal(t, "identity-token", hetznerCreds.Token)
	assert.Equal(t, "access", hetznerCreds.S3AccessKeyID)
	assert.Equal(t, "secret", hetznerCreds.S3SecretAccessKey)
}

func TestIdentityAuthenticateLoadsProjectTokenFromKeyring(t *testing.T) {
	t.Setenv("ATMOS_KEYRING_TYPE", "file")
	t.Setenv("ATMOS_KEYRING_FILE_PATH", t.TempDir())
	t.Setenv("ATMOS_KEYRING_PASSWORD", "test-password")

	store := credentials.NewCredentialStore()
	require.NoError(t, store.Store("hetzner-system", &types.HetznerCredentials{
		Token:       "keyring-token",
		Project:     "system",
		ProjectName: "sonica-system",
		TokenEnv:    []string{"TF_VAR_HCLOUD_TOKEN_SYSTEM"},
	}, ""))

	identity, err := New(&types.HetznerProjectIdentityPrincipal{
		Project: "system",
	})
	require.NoError(t, err)
	identity.SetName("hetzner-system")

	creds, err := identity.Authenticate(context.Background(), nil)

	require.NoError(t, err)
	hetznerCreds, ok := creds.(*types.HetznerCredentials)
	require.True(t, ok)
	assert.Equal(t, "keyring-token", hetznerCreds.Token)
	assert.Equal(t, "system", hetznerCreds.Project)
	assert.Equal(t, "sonica-system", hetznerCreds.ProjectName)
	assert.Equal(t, []string{"TF_VAR_HCLOUD_TOKEN_SYSTEM"}, hetznerCreds.TokenEnv)
}

func TestIdentityEnvironmentLoadsSharedObjectStorageFromKeyring(t *testing.T) {
	t.Setenv("ATMOS_KEYRING_TYPE", "file")
	t.Setenv("ATMOS_KEYRING_FILE_PATH", t.TempDir())
	t.Setenv("ATMOS_KEYRING_PASSWORD", "test-password")

	store := credentials.NewCredentialStore()
	require.NoError(t, store.Store("hetzner-app", &types.HetznerCredentials{
		Token:    "project-token",
		TokenEnv: []string{"TF_VAR_HCLOUD_TOKEN_APP"},
	}, ""))
	require.NoError(t, store.Store("hetzner-object-storage", &types.HetznerCredentials{
		S3AccessKeyID:     "access",
		S3SecretAccessKey: "secret",
		S3Endpoint:        "https://hel1.your-objectstorage.com",
		S3Region:          "hel1",
	}, ""))

	identity, err := New(&types.HetznerProjectIdentityPrincipal{
		Project: "app",
	})
	require.NoError(t, err)
	identity.SetName("hetzner-app")
	identity.SetConfig(&schema.Identity{
		Credentials: map[string]interface{}{
			"object_storage_identity": "hetzner-object-storage",
		},
	})

	env, err := identity.Environment()

	require.NoError(t, err)
	assert.Equal(t, "project-token", env["HCLOUD_TOKEN"])
	assert.Equal(t, "project-token", env["TF_VAR_HCLOUD_TOKEN_APP"])
	assert.Equal(t, "access", env["AWS_ACCESS_KEY_ID"])
	assert.Equal(t, "secret", env["AWS_SECRET_ACCESS_KEY"])
	assert.Equal(t, "https://hel1.your-objectstorage.com", env["AWS_ENDPOINT_URL_S3"])
}

func TestIdentityEnvironment(t *testing.T) {
	identity, err := New(&types.HetznerProjectIdentityPrincipal{
		Project:  "system",
		Token:    "token",
		TokenEnv: []string{"TF_VAR_HCLOUD_TOKEN_SYSTEM"},
	})
	require.NoError(t, err)

	env, err := identity.Environment()

	require.NoError(t, err)
	assert.Equal(t, "token", env["HCLOUD_TOKEN"])
	assert.Equal(t, "token", env["TF_VAR_HCLOUD_TOKEN_SYSTEM"])
}

func TestIdentityEnvironmentFromSourceEnv(t *testing.T) {
	t.Setenv("HCLOUD_TOKEN_SYSTEM", "token")

	identity, err := New(&types.HetznerProjectIdentityPrincipal{
		Project:        "system",
		TokenSourceEnv: "HCLOUD_TOKEN_SYSTEM",
		TokenEnv:       []string{"TF_VAR_HCLOUD_TOKEN_SYSTEM"},
	})
	require.NoError(t, err)

	env, err := identity.Environment()

	require.NoError(t, err)
	assert.Equal(t, "token", env["HCLOUD_TOKEN"])
	assert.Equal(t, "token", env["TF_VAR_HCLOUD_TOKEN_SYSTEM"])
}

func TestIdentityPostAuthenticateSetsAuthContext(t *testing.T) {
	identity, err := New(&types.HetznerProjectIdentityPrincipal{
		Project:     "system",
		ProjectID:   "123",
		ProjectName: "sonica-system",
	})
	require.NoError(t, err)

	authContext := &schema.AuthContext{}
	err = identity.PostAuthenticate(context.Background(), &types.PostAuthenticateParams{
		AuthContext: authContext,
		Credentials: &types.HetznerCredentials{
			Project:       "system",
			ProjectID:     "123",
			ProjectName:   "sonica-system",
			S3Endpoint:    "https://hel1.your-objectstorage.com",
			S3Region:      "hel1",
			S3AccessKeyID: "access",
		},
	})

	require.NoError(t, err)
	require.NotNil(t, authContext.Hetzner)
	assert.Equal(t, "system", authContext.Hetzner.Project)
	assert.Equal(t, "123", authContext.Hetzner.ProjectID)
	assert.Equal(t, "sonica-system", authContext.Hetzner.ProjectName)
	assert.Equal(t, "https://hel1.your-objectstorage.com", authContext.Hetzner.S3Endpoint)
	assert.Equal(t, "access", authContext.Hetzner.S3AccessKeyID)
}
