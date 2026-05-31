package hetzner_project

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

// Identity implements the hetzner/project identity.
type Identity struct {
	name      string
	realm     string
	principal *types.HetznerProjectIdentityPrincipal
	config    *schema.Identity
}

// New creates a Hetzner project identity.
func New(principal *types.HetznerProjectIdentityPrincipal) (*Identity, error) {
	defer perf.Track(nil, "hetzner_project.New")()

	if principal == nil {
		return nil, fmt.Errorf("%w: principal cannot be nil", errUtils.ErrInvalidIdentityConfig)
	}
	return &Identity{principal: principal}, nil
}

// SetName sets the identity name.
func (i *Identity) SetName(name string) {
	i.name = name
}

// SetRealm sets the credential isolation realm.
func (i *Identity) SetRealm(realm string) {
	i.realm = realm
}

// SetConfig stores the full identity config for via.provider and credential overrides.
func (i *Identity) SetConfig(config *schema.Identity) {
	i.config = config
}

// Kind returns the identity kind.
func (i *Identity) Kind() string {
	return types.IdentityKindHetznerProject
}

// Name returns the identity name.
func (i *Identity) Name() string {
	if i.name != "" {
		return i.name
	}
	return i.Kind()
}

// GetProviderName returns the provider configured in via.provider or provider.
func (i *Identity) GetProviderName() (string, error) {
	if i.config != nil {
		if i.config.Via != nil && i.config.Via.Provider != "" {
			return i.config.Via.Provider, nil
		}
		if i.config.Provider != "" {
			return i.config.Provider, nil
		}
	}
	return "", nil
}

// Validate validates identity configuration.
func (i *Identity) Validate() error {
	defer perf.Track(nil, "hetzner_project.Validate")()

	if i.principal == nil {
		return fmt.Errorf("%w: principal is nil", errUtils.ErrInvalidIdentityConfig)
	}
	if i.principal.Project == "" && i.principal.ProjectID == "" && i.principal.ProjectName == "" {
		return fmt.Errorf("%w: project, project_id, or project_name is required", errUtils.ErrInvalidIdentityConfig)
	}
	return nil
}

// Authenticate combines provider credentials with identity project overrides.
func (i *Identity) Authenticate(ctx context.Context, baseCreds types.ICredentials) (types.ICredentials, error) {
	defer perf.Track(nil, "hetzner_project.Authenticate")()

	if err := i.Validate(); err != nil {
		return nil, err
	}

	creds := &types.HetznerCredentials{}
	if baseCreds != nil {
		if baseHetzner, ok := baseCreds.(*types.HetznerCredentials); ok {
			*creds = *baseHetzner
		}
	}

	if err := i.applyObjectStorageFromStore(creds); err != nil {
		return nil, err
	}
	i.applyProjectCredentialsFromStore(creds)
	i.applyPrincipal(creds)
	i.applyConfigCredentials(creds)
	if creds.Token == "" {
		return nil, i.missingTokenError()
	}
	return creds, nil
}

// Environment returns environment variables for this identity.
func (i *Identity) Environment() (map[string]string, error) {
	defer perf.Track(nil, "hetzner_project.Environment")()

	loaded, err := i.LoadCredentials(context.Background())
	if err != nil {
		return nil, err
	}
	creds, ok := loaded.(*types.HetznerCredentials)
	if !ok {
		return nil, fmt.Errorf("%w: loaded credentials are not Hetzner credentials", errUtils.ErrAuthenticationFailed)
	}

	env := hetzner.EnvironmentFromCredentials(creds)
	if i.config != nil {
		for _, item := range i.config.Env {
			if item.Key != "" {
				env[item.Key] = item.Value
			}
		}
	}
	return env, nil
}

// Paths returns no credential file paths.
func (i *Identity) Paths() ([]types.Path, error) {
	return []types.Path{}, nil
}

// PrepareEnvironment merges identity env vars into environ.
func (i *Identity) PrepareEnvironment(ctx context.Context, environ map[string]string) (map[string]string, error) {
	defer perf.Track(nil, "hetzner_project.PrepareEnvironment")()

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

// PostAuthenticate sets env vars and populates auth context.
func (i *Identity) PostAuthenticate(ctx context.Context, params *types.PostAuthenticateParams) error {
	defer perf.Track(nil, "hetzner_project.PostAuthenticate")()

	var creds *types.HetznerCredentials
	if params != nil {
		creds, _ = params.Credentials.(*types.HetznerCredentials)
	}
	if creds == nil {
		loaded, err := i.LoadCredentials(ctx)
		if err != nil {
			return err
		}
		creds, _ = loaded.(*types.HetznerCredentials)
	}
	env := hetzner.EnvironmentFromCredentials(creds)
	if i.config != nil {
		for _, item := range i.config.Env {
			if item.Key != "" {
				env[item.Key] = item.Value
			}
		}
	}
	for key, value := range env {
		if err := os.Setenv(key, value); err != nil {
			return fmt.Errorf("%w: set environment variable %s: %w", errUtils.ErrAuthenticationFailed, key, err)
		}
	}

	if params != nil && params.AuthContext != nil {
		params.AuthContext.Hetzner = &schema.HetznerAuthContext{
			Project:       creds.Project,
			ProjectID:     creds.ProjectID,
			ProjectName:   creds.ProjectName,
			S3Endpoint:    creds.S3Endpoint,
			S3Region:      creds.S3Region,
			S3AccessKeyID: creds.S3AccessKeyID,
		}
	}

	return nil
}

// Logout is a no-op for static credentials.
func (i *Identity) Logout(ctx context.Context) error {
	return nil
}

// CredentialsExist returns true because credentials are sourced from config.
func (i *Identity) CredentialsExist() (bool, error) {
	creds, err := i.credentialsFromStore(i.Name())
	return err == nil && creds != nil && creds.Token != "", nil
}

// LoadCredentials returns credentials sourced from identity config.
func (i *Identity) LoadCredentials(ctx context.Context) (types.ICredentials, error) {
	creds := &types.HetznerCredentials{}
	if err := i.applyObjectStorageFromStore(creds); err != nil {
		return nil, err
	}
	i.applyProjectCredentialsFromStore(creds)
	i.applyPrincipal(creds)
	i.applyConfigCredentials(creds)
	if creds.Token == "" {
		return nil, i.missingTokenError()
	}
	return creds, nil
}

func (i *Identity) applyProjectCredentialsFromStore(creds *types.HetznerCredentials) {
	if i == nil || creds == nil {
		return
	}
	stored, err := i.credentialsFromStore(i.Name())
	if err != nil || stored == nil {
		return
	}
	mergeHetznerCredentials(creds, stored)
}

func (i *Identity) applyObjectStorageFromStore(creds *types.HetznerCredentials) error {
	if i == nil || creds == nil {
		return nil
	}
	alias, required := i.objectStorageIdentity()
	if alias == "" {
		if required {
			return fmt.Errorf("%w: object_storage_identity is required when object_storage_required is true for identity %q", errUtils.ErrInvalidIdentityConfig, i.Name())
		}
		return nil
	}
	stored, err := i.credentialsFromStore(alias)
	if err != nil {
		if required {
			return fmt.Errorf("%w: failed to retrieve Hetzner Object Storage credentials for %q: %w", errUtils.ErrAuthenticationFailed, alias, err)
		}
		return nil
	}
	mergeHetznerObjectStorageCredentials(creds, stored)
	return nil
}

func (i *Identity) credentialsFromStore(alias string) (*types.HetznerCredentials, error) {
	if alias == "" {
		return nil, fmt.Errorf("%w: credential alias is empty", errUtils.ErrInvalidAuthConfig)
	}
	store := atmosCredentials.NewCredentialStore()
	retrieved, err := store.Retrieve(alias, i.realm)
	if err != nil {
		return nil, err
	}
	creds, ok := retrieved.(*types.HetznerCredentials)
	if !ok {
		return nil, fmt.Errorf("%w: stored credentials for %q are not Hetzner credentials", errUtils.ErrAuthenticationFailed, alias)
	}
	return creds, nil
}

func (i *Identity) objectStorageIdentity() (string, bool) {
	if i == nil {
		return "", false
	}
	if i.config != nil && i.config.Credentials != nil {
		alias, _ := i.config.Credentials["object_storage_identity"].(string)
		required, _ := i.config.Credentials["object_storage_required"].(bool)
		if alias != "" {
			return alias, required
		}
		if required {
			return "", true
		}
	}
	if i.principal != nil {
		if i.principal.ObjectStorageIdentity != "" {
			return i.principal.ObjectStorageIdentity, i.principal.ObjectStorageRequired
		}
		if i.principal.ObjectStorageRequired {
			return "", true
		}
	}
	return "", false
}

func (i *Identity) missingTokenError() error {
	return fmt.Errorf("%w: Hetzner API token not found for identity %q. Please configure credentials by running: atmos auth user configure --identity %s", errUtils.ErrAuthenticationFailed, i.Name(), i.Name())
}

func (i *Identity) applyPrincipal(creds *types.HetznerCredentials) {
	if i == nil || i.principal == nil || creds == nil {
		return
	}
	if i.principal.Project != "" {
		creds.Project = i.principal.Project
	}
	if i.principal.ProjectID != "" {
		creds.ProjectID = i.principal.ProjectID
	}
	if i.principal.ProjectName != "" {
		creds.ProjectName = i.principal.ProjectName
	}
	if i.principal.Token != "" {
		creds.Token = i.principal.Token
	} else if i.principal.TokenSourceEnv != "" {
		creds.Token = os.Getenv(i.principal.TokenSourceEnv)
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
	if len(i.principal.TokenEnv) > 0 {
		creds.TokenEnv = i.principal.TokenEnv
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
	applyString("token", func(value string) { creds.Token = value })
	applyString("token_source_env", func(value string) { creds.Token = valueFromEnvUnlessSet(creds.Token, value) })
	applyString("s3_access_key_id", func(value string) { creds.S3AccessKeyID = value })
	applyString("s3_access_key_id_source_env", func(value string) { creds.S3AccessKeyID = valueFromEnvUnlessSet(creds.S3AccessKeyID, value) })
	applyString("s3_secret_access_key", func(value string) { creds.S3SecretAccessKey = value })
	applyString("s3_secret_access_key_source_env", func(value string) { creds.S3SecretAccessKey = valueFromEnvUnlessSet(creds.S3SecretAccessKey, value) })
	applyString("s3_endpoint", func(value string) { creds.S3Endpoint = value })
	applyString("s3_region", func(value string) { creds.S3Region = value })
	if raw, ok := i.config.Credentials["token_env"].([]string); ok {
		creds.TokenEnv = raw
		return
	}
	if raw, ok := i.config.Credentials["token_env"].([]any); ok {
		creds.TokenEnv = make([]string, 0, len(raw))
		for _, item := range raw {
			if value, ok := item.(string); ok && value != "" {
				creds.TokenEnv = append(creds.TokenEnv, value)
			}
		}
	}
}

func mergeHetznerCredentials(target, source *types.HetznerCredentials) {
	if target == nil || source == nil {
		return
	}
	if source.Token != "" {
		target.Token = source.Token
	}
	if source.Project != "" {
		target.Project = source.Project
	}
	if source.ProjectID != "" {
		target.ProjectID = source.ProjectID
	}
	if source.ProjectName != "" {
		target.ProjectName = source.ProjectName
	}
	if len(source.TokenEnv) > 0 {
		target.TokenEnv = source.TokenEnv
	}
	mergeHetznerObjectStorageCredentials(target, source)
}

func mergeHetznerObjectStorageCredentials(target, source *types.HetznerCredentials) {
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
