package hetzner

import (
	"context"
	"testing"

	"github.com/cloudposse/atmos/pkg/auth/credentials"
	"github.com/cloudposse/atmos/pkg/auth/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProviderAuthenticate(t *testing.T) {
	provider, err := New(&types.HetznerTokenProviderSpec{
		Token:             "token",
		S3AccessKeyID:     "access",
		S3SecretAccessKey: "secret",
		S3Endpoint:        "https://hel1.your-objectstorage.com",
		S3Region:          "hel1",
	})
	require.NoError(t, err)
	provider.SetName("hetzner")

	creds, err := provider.Authenticate(context.Background())

	require.NoError(t, err)
	hetznerCreds, ok := creds.(*types.HetznerCredentials)
	require.True(t, ok)
	assert.Equal(t, "token", hetznerCreds.Token)
	assert.Equal(t, "access", hetznerCreds.S3AccessKeyID)
}

func TestProviderAuthenticateFromEnvironment(t *testing.T) {
	t.Setenv("HCLOUD_TOKEN_SYSTEM", "token")
	t.Setenv("AWS_ACCESS_KEY_ID", "access")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")

	provider, err := New(&types.HetznerTokenProviderSpec{
		TokenSourceEnv:         "HCLOUD_TOKEN_SYSTEM",
		S3AccessKeyIDSourceEnv: "AWS_ACCESS_KEY_ID",
		S3SecretKeySourceEnv:   "AWS_SECRET_ACCESS_KEY",
	})
	require.NoError(t, err)

	creds, err := provider.Authenticate(context.Background())

	require.NoError(t, err)
	hetznerCreds, ok := creds.(*types.HetznerCredentials)
	require.True(t, ok)
	assert.Equal(t, "token", hetznerCreds.Token)
	assert.Equal(t, "access", hetznerCreds.S3AccessKeyID)
	assert.Equal(t, "secret", hetznerCreds.S3SecretAccessKey)
}

func TestProviderAuthenticateWithObjectStorageIdentity(t *testing.T) {
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

	provider, err := New(&types.HetznerTokenProviderSpec{
		ObjectStorageIdentity: "hetzner-object-storage",
		Token:                 "token",
	})
	require.NoError(t, err)

	creds, err := provider.Authenticate(context.Background())

	require.NoError(t, err)
	hetznerCreds, ok := creds.(*types.HetznerCredentials)
	require.True(t, ok)
	assert.Equal(t, "token", hetznerCreds.Token)
	assert.Equal(t, "access", hetznerCreds.S3AccessKeyID)
	assert.Equal(t, "secret", hetznerCreds.S3SecretAccessKey)
}

func TestProviderAuthenticateRequiresObjectStorageIdentity(t *testing.T) {
	t.Setenv("ATMOS_KEYRING_TYPE", "file")
	t.Setenv("ATMOS_KEYRING_FILE_PATH", t.TempDir())
	t.Setenv("ATMOS_KEYRING_PASSWORD", "test-password")

	provider, err := New(&types.HetznerTokenProviderSpec{
		ObjectStorageIdentity: "missing",
		ObjectStorageRequired: true,
	})
	require.NoError(t, err)

	_, err = provider.Authenticate(context.Background())

	assert.Error(t, err)
}

func TestEnvironmentFromCredentials(t *testing.T) {
	env := EnvironmentFromCredentials(&types.HetznerCredentials{
		Token:             "token",
		S3AccessKeyID:     "access",
		S3SecretAccessKey: "secret",
		S3Endpoint:        "https://hel1.your-objectstorage.com",
		S3Region:          "hel1",
		TokenEnv:          []string{"TF_VAR_HCLOUD_TOKEN_SYSTEM"},
	})

	assert.Equal(t, "token", env["HCLOUD_TOKEN"])
	assert.Equal(t, "token", env["TF_VAR_HCLOUD_TOKEN_SYSTEM"])
	assert.Equal(t, "access", env["AWS_ACCESS_KEY_ID"])
	assert.Equal(t, "secret", env["AWS_SECRET_ACCESS_KEY"])
	assert.Equal(t, "https://hel1.your-objectstorage.com", env["AWS_ENDPOINT_URL_S3"])
	assert.Equal(t, "hel1", env["AWS_REGION"])
	assert.Equal(t, "hel1", env["AWS_DEFAULT_REGION"])
}
