package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseHetznerTokenProviderSpec(t *testing.T) {
	spec, err := ParseHetznerTokenProviderSpec(map[string]any{
		"token":                           "token",
		"token_source_env":                "HCLOUD_TOKEN_SYSTEM",
		"object_storage_identity":         "hetzner-object-storage",
		"object_storage_required":         true,
		"s3_access_key_id":                "access",
		"s3_access_key_id_source_env":     "AWS_ACCESS_KEY_ID",
		"s3_secret_access_key":            "secret",
		"s3_secret_access_key_source_env": "AWS_SECRET_ACCESS_KEY",
		"s3_endpoint":                     "https://hel1.your-objectstorage.com",
		"s3_region":                       "hel1",
	})

	require.NoError(t, err)
	assert.Equal(t, "token", spec.Token)
	assert.Equal(t, "HCLOUD_TOKEN_SYSTEM", spec.TokenSourceEnv)
	assert.Equal(t, "hetzner-object-storage", spec.ObjectStorageIdentity)
	assert.True(t, spec.ObjectStorageRequired)
	assert.Equal(t, "access", spec.S3AccessKeyID)
	assert.Equal(t, "AWS_ACCESS_KEY_ID", spec.S3AccessKeyIDSourceEnv)
	assert.Equal(t, "secret", spec.S3SecretAccessKey)
	assert.Equal(t, "AWS_SECRET_ACCESS_KEY", spec.S3SecretKeySourceEnv)
	assert.Equal(t, "https://hel1.your-objectstorage.com", spec.S3Endpoint)
	assert.Equal(t, "hel1", spec.S3Region)
}

func TestParseHetznerTokenProviderSpec_Nil(t *testing.T) {
	spec, err := ParseHetznerTokenProviderSpec(nil)

	require.NoError(t, err)
	assert.NotNil(t, spec)
}

func TestParseHetznerProjectIdentityPrincipal(t *testing.T) {
	principal, err := ParseHetznerProjectIdentityPrincipal(map[string]any{
		"project":                 "system",
		"token_source_env":        "HCLOUD_TOKEN_SYSTEM",
		"object_storage_identity": "hetzner-object-storage",
		"token_env":               []string{"TF_VAR_HCLOUD_TOKEN_SYSTEM"},
	})

	require.NoError(t, err)
	assert.Equal(t, "system", principal.Project)
	assert.Equal(t, "HCLOUD_TOKEN_SYSTEM", principal.TokenSourceEnv)
	assert.Equal(t, "hetzner-object-storage", principal.ObjectStorageIdentity)
	assert.Equal(t, []string{"TF_VAR_HCLOUD_TOKEN_SYSTEM"}, principal.TokenEnv)
}

func TestParseHetznerProjectIdentityPrincipal_MissingProject(t *testing.T) {
	principal, err := ParseHetznerProjectIdentityPrincipal(map[string]any{})

	assert.Nil(t, principal)
	assert.Error(t, err)
}

func TestParseHetznerObjectStorageIdentityPrincipal(t *testing.T) {
	principal, err := ParseHetznerObjectStorageIdentityPrincipal(map[string]any{
		"s3_access_key_id":     "access",
		"s3_secret_access_key": "secret",
		"s3_endpoint":          "https://hel1.your-objectstorage.com",
		"s3_region":            "hel1",
	})

	require.NoError(t, err)
	assert.Equal(t, "access", principal.S3AccessKeyID)
	assert.Equal(t, "secret", principal.S3SecretAccessKey)
	assert.Equal(t, "https://hel1.your-objectstorage.com", principal.S3Endpoint)
	assert.Equal(t, "hel1", principal.S3Region)
}
