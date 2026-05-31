package hetzner

import (
	"context"
	"fmt"
	"maps"
	"os"

	errUtils "github.com/cloudposse/atmos/errors"
	atmosCredentials "github.com/cloudposse/atmos/pkg/auth/credentials"
	"github.com/cloudposse/atmos/pkg/auth/types"
	"github.com/cloudposse/atmos/pkg/perf"
)

// Provider implements the hetzner/token auth provider.
type Provider struct {
	name  string
	spec  *types.HetznerTokenProviderSpec
	realm string
}

// New creates a Hetzner token provider.
func New(spec *types.HetznerTokenProviderSpec) (*Provider, error) {
	defer perf.Track(nil, "hetzner.New")()

	if spec == nil {
		spec = &types.HetznerTokenProviderSpec{}
	}
	return &Provider{spec: spec}, nil
}

// SetName sets the provider name.
func (p *Provider) SetName(name string) {
	p.name = name
}

// Kind returns the provider kind.
func (p *Provider) Kind() string {
	return types.ProviderKindHetznerToken
}

// Name returns the provider name.
func (p *Provider) Name() string {
	return p.name
}

// SetRealm sets the credential isolation realm.
func (p *Provider) SetRealm(realm string) {
	p.realm = realm
}

// PreAuthenticate is a no-op for static Hetzner credentials.
func (p *Provider) PreAuthenticate(manager types.AuthManager) error {
	return nil
}

// Authenticate returns credentials configured on the provider.
func (p *Provider) Authenticate(ctx context.Context) (types.ICredentials, error) {
	defer perf.Track(nil, "hetzner.Provider.Authenticate")()

	return p.credentials()
}

// Validate validates provider configuration.
func (p *Provider) Validate() error {
	return nil
}

// Environment returns provider-level environment variables.
func (p *Provider) Environment() (map[string]string, error) {
	creds, err := p.credentials()
	if err != nil {
		return nil, err
	}
	return EnvironmentFromCredentials(creds), nil
}

// Paths returns no credential file paths.
func (p *Provider) Paths() ([]types.Path, error) {
	return []types.Path{}, nil
}

// PrepareEnvironment merges provider env vars into environ.
func (p *Provider) PrepareEnvironment(ctx context.Context, environ map[string]string) (map[string]string, error) {
	result := maps.Clone(environ)
	if result == nil {
		result = make(map[string]string)
	}
	env, err := p.Environment()
	if err != nil {
		return nil, err
	}
	for key, value := range env {
		result[key] = value
	}
	return result, nil
}

// Logout is a no-op for static credentials.
func (p *Provider) Logout(ctx context.Context) error {
	return nil
}

// GetFilesDisplayPath returns an empty path because no files are managed.
func (p *Provider) GetFilesDisplayPath() string {
	return ""
}

func (p *Provider) credentials() (*types.HetznerCredentials, error) {
	if p == nil || p.spec == nil {
		return &types.HetznerCredentials{}, nil
	}
	creds := &types.HetznerCredentials{}
	if err := p.applyObjectStorageFromStore(creds); err != nil {
		return nil, err
	}
	p.applySpec(creds)
	return creds, nil
}

func (p *Provider) applySpec(creds *types.HetznerCredentials) {
	if p == nil || p.spec == nil || creds == nil {
		return
	}
	overlay := &types.HetznerCredentials{
		Token:             valueOrEnv(p.spec.Token, p.spec.TokenSourceEnv),
		S3AccessKeyID:     valueOrEnv(p.spec.S3AccessKeyID, p.spec.S3AccessKeyIDSourceEnv),
		S3SecretAccessKey: valueOrEnv(p.spec.S3SecretAccessKey, p.spec.S3SecretKeySourceEnv),
		S3Endpoint:        p.spec.S3Endpoint,
		S3Region:          p.spec.S3Region,
	}
	mergeHetznerCredentials(creds, overlay)
}

func (p *Provider) applyObjectStorageFromStore(creds *types.HetznerCredentials) error {
	if p == nil || p.spec == nil || creds == nil {
		return nil
	}
	alias := p.spec.ObjectStorageIdentity
	if alias == "" {
		if p.spec.ObjectStorageRequired {
			return fmt.Errorf("%w: object_storage_identity is required when object_storage_required is true", errUtils.ErrInvalidProviderConfig)
		}
		return nil
	}

	store := atmosCredentials.NewCredentialStore()
	retrieved, err := store.Retrieve(alias, p.realm)
	if err != nil {
		if p.spec.ObjectStorageRequired {
			return fmt.Errorf("%w: failed to retrieve Hetzner Object Storage credentials for %q: %w", errUtils.ErrAuthenticationFailed, alias, err)
		}
		return nil
	}
	hetznerCreds, ok := retrieved.(*types.HetznerCredentials)
	if !ok {
		return fmt.Errorf("%w: stored credentials for %q are not Hetzner credentials", errUtils.ErrAuthenticationFailed, alias)
	}
	mergeHetznerObjectStorageCredentials(creds, hetznerCreds)
	return nil
}

func valueOrEnv(value, envName string) string {
	if value != "" {
		return value
	}
	if envName == "" {
		return ""
	}
	return os.Getenv(envName)
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

// EnvironmentFromCredentials returns standard environment variables for Hetzner credentials.
func EnvironmentFromCredentials(creds *types.HetznerCredentials) map[string]string {
	env := make(map[string]string)
	if creds == nil {
		return env
	}
	if creds.Token != "" {
		env["HCLOUD_TOKEN"] = creds.Token
		for _, key := range creds.TokenEnv {
			if key != "" {
				env[key] = creds.Token
			}
		}
	}
	if creds.S3AccessKeyID != "" {
		env["AWS_ACCESS_KEY_ID"] = creds.S3AccessKeyID
	}
	if creds.S3SecretAccessKey != "" {
		env["AWS_SECRET_ACCESS_KEY"] = creds.S3SecretAccessKey
	}
	if creds.S3Endpoint != "" {
		env["AWS_ENDPOINT_URL_S3"] = creds.S3Endpoint
	}
	if creds.S3Region != "" {
		env["AWS_REGION"] = creds.S3Region
		env["AWS_DEFAULT_REGION"] = creds.S3Region
	}
	return env
}
