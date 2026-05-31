package types

import (
	"fmt"

	"github.com/go-viper/mapstructure/v2"

	errUtils "github.com/cloudposse/atmos/errors"
	"github.com/cloudposse/atmos/pkg/perf"
)

// HetznerTokenProviderSpec defines static Hetzner credentials that may be shared by identities.
type HetznerTokenProviderSpec struct {
	Token                  string `json:"token,omitempty" yaml:"token,omitempty" mapstructure:"token"`
	TokenSourceEnv         string `json:"token_source_env,omitempty" yaml:"token_source_env,omitempty" mapstructure:"token_source_env"`
	ObjectStorageIdentity  string `json:"object_storage_identity,omitempty" yaml:"object_storage_identity,omitempty" mapstructure:"object_storage_identity"`
	ObjectStorageRequired  bool   `json:"object_storage_required,omitempty" yaml:"object_storage_required,omitempty" mapstructure:"object_storage_required"`
	S3AccessKeyID          string `json:"s3_access_key_id,omitempty" yaml:"s3_access_key_id,omitempty" mapstructure:"s3_access_key_id"`
	S3AccessKeyIDSourceEnv string `json:"s3_access_key_id_source_env,omitempty" yaml:"s3_access_key_id_source_env,omitempty" mapstructure:"s3_access_key_id_source_env"`
	S3SecretAccessKey      string `json:"s3_secret_access_key,omitempty" yaml:"s3_secret_access_key,omitempty" mapstructure:"s3_secret_access_key"`
	S3SecretKeySourceEnv   string `json:"s3_secret_access_key_source_env,omitempty" yaml:"s3_secret_access_key_source_env,omitempty" mapstructure:"s3_secret_access_key_source_env"`
	S3Endpoint             string `json:"s3_endpoint,omitempty" yaml:"s3_endpoint,omitempty" mapstructure:"s3_endpoint"`
	S3Region               string `json:"s3_region,omitempty" yaml:"s3_region,omitempty" mapstructure:"s3_region"`
}

// HetznerProjectIdentityPrincipal defines the target Hetzner project context.
type HetznerProjectIdentityPrincipal struct {
	Project                string   `json:"project,omitempty" yaml:"project,omitempty" mapstructure:"project"`
	ProjectID              string   `json:"project_id,omitempty" yaml:"project_id,omitempty" mapstructure:"project_id"`
	ProjectName            string   `json:"project_name,omitempty" yaml:"project_name,omitempty" mapstructure:"project_name"`
	Token                  string   `json:"token,omitempty" yaml:"token,omitempty" mapstructure:"token"`
	TokenSourceEnv         string   `json:"token_source_env,omitempty" yaml:"token_source_env,omitempty" mapstructure:"token_source_env"`
	ObjectStorageIdentity  string   `json:"object_storage_identity,omitempty" yaml:"object_storage_identity,omitempty" mapstructure:"object_storage_identity"`
	ObjectStorageRequired  bool     `json:"object_storage_required,omitempty" yaml:"object_storage_required,omitempty" mapstructure:"object_storage_required"`
	S3AccessKeyID          string   `json:"s3_access_key_id,omitempty" yaml:"s3_access_key_id,omitempty" mapstructure:"s3_access_key_id"`
	S3AccessKeyIDSourceEnv string   `json:"s3_access_key_id_source_env,omitempty" yaml:"s3_access_key_id_source_env,omitempty" mapstructure:"s3_access_key_id_source_env"`
	S3SecretAccessKey      string   `json:"s3_secret_access_key,omitempty" yaml:"s3_secret_access_key,omitempty" mapstructure:"s3_secret_access_key"`
	S3SecretKeySourceEnv   string   `json:"s3_secret_access_key_source_env,omitempty" yaml:"s3_secret_access_key_source_env,omitempty" mapstructure:"s3_secret_access_key_source_env"`
	S3Endpoint             string   `json:"s3_endpoint,omitempty" yaml:"s3_endpoint,omitempty" mapstructure:"s3_endpoint"`
	S3Region               string   `json:"s3_region,omitempty" yaml:"s3_region,omitempty" mapstructure:"s3_region"`
	TokenEnv               []string `json:"token_env,omitempty" yaml:"token_env,omitempty" mapstructure:"token_env"`
}

// HetznerObjectStorageIdentityPrincipal defines shared Hetzner Object Storage settings.
type HetznerObjectStorageIdentityPrincipal struct {
	S3AccessKeyID          string `json:"s3_access_key_id,omitempty" yaml:"s3_access_key_id,omitempty" mapstructure:"s3_access_key_id"`
	S3AccessKeyIDSourceEnv string `json:"s3_access_key_id_source_env,omitempty" yaml:"s3_access_key_id_source_env,omitempty" mapstructure:"s3_access_key_id_source_env"`
	S3SecretAccessKey      string `json:"s3_secret_access_key,omitempty" yaml:"s3_secret_access_key,omitempty" mapstructure:"s3_secret_access_key"`
	S3SecretKeySourceEnv   string `json:"s3_secret_access_key_source_env,omitempty" yaml:"s3_secret_access_key_source_env,omitempty" mapstructure:"s3_secret_access_key_source_env"`
	S3Endpoint             string `json:"s3_endpoint,omitempty" yaml:"s3_endpoint,omitempty" mapstructure:"s3_endpoint"`
	S3Region               string `json:"s3_region,omitempty" yaml:"s3_region,omitempty" mapstructure:"s3_region"`
}

// ParseHetznerTokenProviderSpec parses a provider spec into HetznerTokenProviderSpec.
func ParseHetznerTokenProviderSpec(spec map[string]any) (*HetznerTokenProviderSpec, error) {
	defer perf.Track(nil, "types.ParseHetznerTokenProviderSpec")()

	if spec == nil {
		return &HetznerTokenProviderSpec{}, nil
	}

	var out HetznerTokenProviderSpec
	if err := decodeHetznerMap(spec, &out); err != nil {
		return nil, fmt.Errorf("%w: failed to decode Hetzner provider spec: %w", errUtils.ErrInvalidAuthConfig, err)
	}
	return &out, nil
}

// ParseHetznerProjectIdentityPrincipal parses identity principal config.
func ParseHetznerProjectIdentityPrincipal(principal map[string]any) (*HetznerProjectIdentityPrincipal, error) {
	defer perf.Track(nil, "types.ParseHetznerProjectIdentityPrincipal")()

	if principal == nil {
		return nil, fmt.Errorf("%w: principal is nil", errUtils.ErrInvalidAuthConfig)
	}

	var out HetznerProjectIdentityPrincipal
	if err := decodeHetznerMap(principal, &out); err != nil {
		return nil, fmt.Errorf("%w: failed to decode Hetzner identity principal: %w", errUtils.ErrInvalidAuthConfig, err)
	}
	if out.Project == "" && out.ProjectID == "" && out.ProjectName == "" {
		return nil, fmt.Errorf("%w: project, project_id, or project_name is required for Hetzner project identity", errUtils.ErrInvalidAuthConfig)
	}
	return &out, nil
}

// ParseHetznerObjectStorageIdentityPrincipal parses object storage identity principal config.
func ParseHetznerObjectStorageIdentityPrincipal(principal map[string]any) (*HetznerObjectStorageIdentityPrincipal, error) {
	defer perf.Track(nil, "types.ParseHetznerObjectStorageIdentityPrincipal")()

	if principal == nil {
		return &HetznerObjectStorageIdentityPrincipal{}, nil
	}

	var out HetznerObjectStorageIdentityPrincipal
	if err := decodeHetznerMap(principal, &out); err != nil {
		return nil, fmt.Errorf("%w: failed to decode Hetzner Object Storage identity principal: %w", errUtils.ErrInvalidAuthConfig, err)
	}
	return &out, nil
}

func decodeHetznerMap(input map[string]any, out any) error {
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:           out,
		WeaklyTypedInput: false,
		TagName:          "mapstructure",
	})
	if err != nil {
		return err
	}
	return decoder.Decode(input)
}
