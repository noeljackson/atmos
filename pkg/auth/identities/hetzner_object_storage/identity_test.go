package hetzner_object_storage

import (
	"context"
	"testing"

	"github.com/cloudposse/atmos/pkg/auth/credentials"
	"github.com/cloudposse/atmos/pkg/auth/types"
	"github.com/cloudposse/atmos/pkg/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIdentityEnvironmentLoadsObjectStorageFromKeyring(t *testing.T) {
	t.Setenv("ATMOS_KEYRING_TYPE", "file")
	t.Setenv("ATMOS_KEYRING_FILE_PATH", t.TempDir())
	t.Setenv("ATMOS_KEYRING_PASSWORD", "test-password")

	store := credentials.NewCredentialStore()
	require.NoError(t, store.Store("hetzner-object-storage", &types.HetznerCredentials{
		S3AccessKeyID:     "access",
		S3SecretAccessKey: "secret",
		S3Endpoint:        "https://hel1.your-objectstorage.com",
		S3Region:          "hel1",
	}, ""))

	identity, err := New(&types.HetznerObjectStorageIdentityPrincipal{})
	require.NoError(t, err)
	identity.SetName("hetzner-object-storage")

	env, err := identity.Environment()

	require.NoError(t, err)
	assert.Equal(t, "access", env["AWS_ACCESS_KEY_ID"])
	assert.Equal(t, "secret", env["AWS_SECRET_ACCESS_KEY"])
	assert.Equal(t, "https://hel1.your-objectstorage.com", env["AWS_ENDPOINT_URL_S3"])
	assert.NotContains(t, env, "HCLOUD_TOKEN")
}

func TestIdentityConfigOverridesKeyring(t *testing.T) {
	t.Setenv("ATMOS_KEYRING_TYPE", "file")
	t.Setenv("ATMOS_KEYRING_FILE_PATH", t.TempDir())
	t.Setenv("ATMOS_KEYRING_PASSWORD", "test-password")

	store := credentials.NewCredentialStore()
	require.NoError(t, store.Store("hetzner-object-storage", &types.HetznerCredentials{
		S3AccessKeyID:     "keyring-access",
		S3SecretAccessKey: "keyring-secret",
		S3Endpoint:        "https://hel1.your-objectstorage.com",
		S3Region:          "hel1",
	}, ""))

	identity, err := New(&types.HetznerObjectStorageIdentityPrincipal{})
	require.NoError(t, err)
	identity.SetName("hetzner-object-storage")
	identity.SetConfig(&schema.Identity{
		Credentials: map[string]interface{}{
			"s3_region": "nbg1",
		},
	})

	creds, err := identity.LoadCredentials(context.Background())

	require.NoError(t, err)
	hetznerCreds, ok := creds.(*types.HetznerCredentials)
	require.True(t, ok)
	assert.Equal(t, "keyring-access", hetznerCreds.S3AccessKeyID)
	assert.Equal(t, "nbg1", hetznerCreds.S3Region)
}
