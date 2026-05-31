package hetzner_object_storage

import (
	"context"
	"fmt"
	"maps"
	"os"

	errUtils "github.com/cloudposse/atmos/errors"
	atmosCredentials "github.com/cloudposse/atmos/pkg/auth/credentials"
	"github.com/cloudposse/atmos/pkg/auth/providers/hetzner"
	"github.com/cloudposse/atmos/pkg/auth/types"
	"github.com/cloudposse/atmos/pkg/perf"
	"github.com/cloudposse/atmos/pkg/schema"
)

// Identity implements the hetzner/object-storage identity.
type Identity struct {
	name      string
	realm     string
	principal *types.HetznerObjectStorageIdentityPrincipal
	config    *schema.Identity
}

// New creates a Hetzner Object Storage identity.
func New(principal *types.HetznerObjectStorageIdentityPrincipal) (*Identity, error) {
	defer perf.Track(nil, "hetzner_object_storage.New")()

	if principal == nil {
		principal = &types.HetznerObjectStorageIdentityPrincipal{}
	}
	return &Identity{principal: principal}, nil
}

func (i *Identity) SetName(name string) {
	i.name = name
}

func (i *Identity) SetRealm(realm string) {
	i.realm = realm
}

func (i *Identity) SetConfig(config *schema.Identity) {
	i.config = config
}

func (i *Identity) Kind() string {
	return types.IdentityKindHetznerObjectStorage
}

func (i *Identity) Name() string {
	if i.name != "" {
		return i.name
	}
	return i.Kind()
}

func (i *Identity) GetProviderName() (string, error) {
	return "hetzner-object-storage", nil
}

func (i *Identity) Validate() error {
	return nil
}

func (i *Identity) Authenticate(ctx context.Context, baseCreds types.ICredentials) (types.ICredentials, error) {
	defer perf.Track(nil, "hetzner_object_storage.Authenticate")()

	return i.LoadCredentials(ctx)
}

func (i *Identity) Environment() (map[string]string, error) {
	defer perf.Track(nil, "hetzner_object_storage.Environment")()

	loaded, err := i.LoadCredentials(context.Background())
	if err != nil {
		return nil, err
	}
	creds, ok := loaded.(*types.HetznerCredentials)
	if !ok {
		return nil, fmt.Errorf("%w: loaded credentials are not Hetzner credentials", errUtils.ErrAuthenticationFailed)
	}
	env := hetzner.EnvironmentFromCredentials(creds)
	delete(env, "HCLOUD_TOKEN")
	if i.config != nil {
		for _, item := range i.config.Env {
			if item.Key != "" {
				env[item.Key] = item.Value
			}
		}
	}
	return env, nil
}

func (i *Identity) Paths() ([]types.Path, error) {
	return []types.Path{}, nil
}

func (i *Identity) PrepareEnvironment(ctx context.Context, environ map[string]string) (map[string]string, error) {
	defer perf.Track(nil, "hetzner_object_storage.PrepareEnvironment")()

	result := maps.Clone(environ)
	if result == nil {
		result = make(map[string]string)
	}
	env, err := i.Environment()
	if err != nil {
		return nil, err
	}
	for key, value := range env {
		result[key] = value
	}
	return result, nil
}

func (i *Identity) PostAuthenticate(ctx context.Context, params *types.PostAuthenticateParams) error {
	defer perf.Track(nil, "hetzner_object_storage.PostAuthenticate")()

	env, err := i.Environment()
	if err != nil {
		return err
	}
	for key, value := range env {
		if err := os.Setenv(key, value); err != nil {
			return fmt.Errorf("%w: set environment variable %s: %w", errUtils.ErrAuthenticationFailed, key, err)
		}
	}
	if params != nil && params.AuthContext != nil {
		creds, _ := params.Credentials.(*types.HetznerCredentials)
		if creds == nil {
			loaded, loadErr := i.LoadCredentials(ctx)
			if loadErr != nil {
				return loadErr
			}
			creds, _ = loaded.(*types.HetznerCredentials)
		}
		params.AuthContext.Hetzner = &schema.HetznerAuthContext{
			S3Endpoint:    creds.S3Endpoint,
			S3Region:      creds.S3Region,
			S3AccessKeyID: creds.S3AccessKeyID,
		}
	}
	return nil
}

func (i *Identity) Logout(ctx context.Context) error {
	store := atmosCredentials.NewCredentialStore()
	return store.Delete(i.Name(), i.realm)
}

func (i *Identity) CredentialsExist() (bool, error) {
	creds, err := i.credentialsFromStore()
	return err == nil && creds != nil && creds.S3AccessKeyID != "" && creds.S3SecretAccessKey != "", nil
}

func (i *Identity) LoadCredentials(ctx context.Context) (types.ICredentials, error) {
	creds := &types.HetznerCredentials{}
	if stored, err := i.credentialsFromStore(); err == nil && stored != nil {
		mergeObjectStorageCredentials(creds, stored)
	}
	i.applyPrincipal(creds)
	i.applyConfigCredentials(creds)
	if creds.S3AccessKeyID == "" || creds.S3SecretAccessKey == "" {
		return nil, fmt.Errorf("%w: Hetzner Object Storage credentials not found for identity %q. Please configure credentials by running: atmos auth user configure --identity %s", errUtils.ErrAuthenticationFailed, i.Name(), i.Name())
	}
	return creds, nil
}

func (i *Identity) credentialsFromStore() (*types.HetznerCredentials, error) {
	store := atmosCredentials.NewCredentialStore()
	retrieved, err := store.Retrieve(i.Name(), i.realm)
	if err != nil {
		return nil, err
	}
	creds, ok := retrieved.(*types.HetznerCredentials)
	if !ok {
		return nil, fmt.Errorf("%w: stored credentials for %q are not Hetzner credentials", errUtils.ErrAuthenticationFailed, i.Name())
	}
	return creds, nil
}

func (i *Identity) applyPrincipal(creds *types.HetznerCredentials) {
	if i == nil || i.principal == nil || creds == nil {
		return
	}
	if i.principal.S3AccessKeyID != "" {
		creds.S3AccessKeyID = i.principal.S3AccessKeyID
	} else if i.principal.S3AccessKeyIDSourceEnv != "" {
		creds.S3AccessKeyID = os.Getenv(i.principal.S3AccessKeyIDSourceEnv)
	}
	if i.principal.S3SecretAccessKey != "" {
		creds.S3SecretAccessKey = i.principal.S3SecretAccessKey
	} else if i.principal.S3SecretKeySourceEnv != "" {
		creds.S3SecretAccessKey = os.Getenv(i.principal.S3SecretKeySourceEnv)
	}
	if i.principal.S3Endpoint != "" {
		creds.S3Endpoint = i.principal.S3Endpoint
	}
	if i.principal.S3Region != "" {
		creds.S3Region = i.principal.S3Region
	}
}

func (i *Identity) applyConfigCredentials(creds *types.HetznerCredentials) {
	if i == nil || i.config == nil || creds == nil {
		return
	}
	applyString := func(key string, set func(string)) {
		if value, ok := i.config.Credentials[key].(string); ok && value != "" {
			set(value)
		}
	}
	applyString("s3_access_key_id", func(value string) { creds.S3AccessKeyID = value })
	applyString("s3_access_key_id_source_env", func(value string) { creds.S3AccessKeyID = valueFromEnvUnlessSet(creds.S3AccessKeyID, value) })
	applyString("s3_secret_access_key", func(value string) { creds.S3SecretAccessKey = value })
	applyString("s3_secret_access_key_source_env", func(value string) { creds.S3SecretAccessKey = valueFromEnvUnlessSet(creds.S3SecretAccessKey, value) })
	applyString("s3_endpoint", func(value string) { creds.S3Endpoint = value })
	applyString("s3_region", func(value string) { creds.S3Region = value })
}

func mergeObjectStorageCredentials(target, source *types.HetznerCredentials) {
	if target == nil || source == nil {
		return
	}
	if source.S3AccessKeyID != "" {
		target.S3AccessKeyID = source.S3AccessKeyID
	}
	if source.S3SecretAccessKey != "" {
		target.S3SecretAccessKey = source.S3SecretAccessKey
	}
	if source.S3Endpoint != "" {
		target.S3Endpoint = source.S3Endpoint
	}
	if source.S3Region != "" {
		target.S3Region = source.S3Region
	}
}

func valueFromEnvUnlessSet(current, envName string) string {
	if current != "" {
		return current
	}
	if envName == "" {
		return ""
	}
	return os.Getenv(envName)
}
