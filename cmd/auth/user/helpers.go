package user

import (
	"fmt"
	"sort"

	"github.com/charmbracelet/huh"

	errUtils "github.com/cloudposse/atmos/errors"
	authTypes "github.com/cloudposse/atmos/pkg/auth/types"
	authUtils "github.com/cloudposse/atmos/pkg/auth/utils"
	"github.com/cloudposse/atmos/pkg/perf"
	"github.com/cloudposse/atmos/pkg/schema"
)

// awsUserIdentityInfo holds extracted credential information from YAML config.
type awsUserIdentityInfo struct {
	AccessKeyID     string
	SecretAccessKey string
	MfaArn          string
	SessionDuration string
	AllInYAML       bool
}

// hetznerProjectIdentityInfo holds extracted Hetzner project credential information.
type hetznerProjectIdentityInfo struct {
	Token                 string
	TokenSourceEnv        string
	Project               string
	ProjectID             string
	ProjectName           string
	ObjectStorageIdentity string
	TokenEnv              []string
	AllConfigured         bool
}

// hetznerObjectStorageIdentityInfo holds extracted Hetzner Object Storage credential information.
type hetznerObjectStorageIdentityInfo struct {
	S3AccessKeyID          string
	S3AccessKeyIDSourceEnv string
	S3SecretAccessKey      string
	S3SecretKeySourceEnv   string
	S3Endpoint             string
	S3Region               string
	AllConfigured          bool
}

// selectAWSUserIdentities filters identities to find aws/user types.
func selectAWSUserIdentities(identities map[string]schema.Identity) ([]string, string, error) {
	defer perf.Track(nil, "auth.user.selectAWSUserIdentities")()

	if identities == nil {
		return nil, "", fmt.Errorf("%w: no auth identities configured in atmos.yaml", errUtils.ErrInvalidAuthConfig)
	}

	var selectable []string
	defaultChoice := ""

	for ident := range identities {
		identity := identities[ident]
		if identity.Kind == "aws/user" {
			selectable = append(selectable, ident)
			if identity.Default && defaultChoice == "" {
				defaultChoice = ident
			}
		}
	}

	if len(selectable) == 0 {
		return nil, "", fmt.Errorf("%w: no identities configured for provider type 'aws/user'. Define one under auth.identities in atmos.yaml", errUtils.ErrInvalidAuthConfig)
	}

	return selectable, defaultChoice, nil
}

// selectConfigurableUserIdentities filters identities supported by auth user configure.
func selectConfigurableUserIdentities(identities map[string]schema.Identity) ([]string, string, error) {
	defer perf.Track(nil, "auth.user.selectConfigurableUserIdentities")()

	if identities == nil {
		return nil, "", fmt.Errorf("%w: no auth identities configured in atmos.yaml", errUtils.ErrInvalidAuthConfig)
	}

	selectable := make([]string, 0, len(identities))
	defaultChoice := ""
	for ident, identity := range identities {
		if isConfigurableUserIdentityKind(identity.Kind) {
			selectable = append(selectable, ident)
			if identity.Default && defaultChoice == "" {
				defaultChoice = ident
			}
		}
	}
	sort.Strings(selectable)
	if defaultChoice == "" && len(selectable) > 0 {
		defaultChoice = selectable[0]
	}
	if len(selectable) == 0 {
		return nil, "", fmt.Errorf("%w: no configurable identities found. Define aws/user, hetzner/project, or hetzner/object-storage identities under auth.identities in atmos.yaml", errUtils.ErrInvalidAuthConfig)
	}
	return selectable, defaultChoice, nil
}

func isConfigurableUserIdentityKind(kind string) bool {
	switch kind {
	case authTypes.ProviderKindAWSUser, authTypes.IdentityKindHetznerProject, authTypes.IdentityKindHetznerObjectStorage:
		return true
	default:
		return false
	}
}

func validateConfigurableIdentityChoice(identities map[string]schema.Identity, choice string) error {
	identity, ok := identities[choice]
	if !ok {
		return fmt.Errorf("%w: identity %q not found", errUtils.ErrInvalidAuthConfig, choice)
	}
	if !isConfigurableUserIdentityKind(identity.Kind) {
		return fmt.Errorf("%w: identity %q has unsupported kind %q for auth user configure", errUtils.ErrInvalidAuthConfig, choice, identity.Kind)
	}
	return nil
}

// extractAWSUserInfo extracts credential information from YAML identity config.
func extractAWSUserInfo(identity schema.Identity) awsUserIdentityInfo {
	defer perf.Track(nil, "auth.user.extractAWSUserInfo")()

	var info awsUserIdentityInfo

	// Extract credentials from YAML.
	if identity.Credentials != nil {
		if accessKey, ok := identity.Credentials["access_key_id"].(string); ok {
			info.AccessKeyID = accessKey
		}
		if secretKey, ok := identity.Credentials["secret_access_key"].(string); ok {
			info.SecretAccessKey = secretKey
		}
		if mfa, ok := identity.Credentials["mfa_arn"].(string); ok {
			info.MfaArn = mfa
		}
	}

	// Check if session duration is configured at identity level.
	if identity.Session != nil && identity.Session.Duration != "" {
		info.SessionDuration = identity.Session.Duration
	}

	// Check if all required credentials are managed by YAML.
	info.AllInYAML = info.AccessKeyID != "" && info.SecretAccessKey != ""

	return info
}

// extractHetznerProjectInfo extracts Hetzner project credential information from YAML identity config.
func extractHetznerProjectInfo(identity schema.Identity) hetznerProjectIdentityInfo {
	defer perf.Track(nil, "auth.user.extractHetznerProjectInfo")()

	var info hetznerProjectIdentityInfo
	readStringMap(identity.Principal, map[string]func(string){
		"project":                 func(value string) { info.Project = value },
		"project_id":              func(value string) { info.ProjectID = value },
		"project_name":            func(value string) { info.ProjectName = value },
		"token":                   func(value string) { info.Token = value },
		"token_source_env":        func(value string) { info.TokenSourceEnv = value },
		"object_storage_identity": func(value string) { info.ObjectStorageIdentity = value },
	})
	readStringMap(identity.Credentials, map[string]func(string){
		"token":                   func(value string) { info.Token = value },
		"token_source_env":        func(value string) { info.TokenSourceEnv = value },
		"object_storage_identity": func(value string) { info.ObjectStorageIdentity = value },
	})
	info.TokenEnv = readStringSlice(identity.Principal, "token_env")
	if tokenEnv := readStringSlice(identity.Credentials, "token_env"); len(tokenEnv) > 0 {
		info.TokenEnv = tokenEnv
	}
	info.AllConfigured = info.Token != "" || info.TokenSourceEnv != ""
	return info
}

// extractHetznerObjectStorageInfo extracts Hetzner Object Storage credential information from YAML identity config.
func extractHetznerObjectStorageInfo(identity schema.Identity) hetznerObjectStorageIdentityInfo {
	defer perf.Track(nil, "auth.user.extractHetznerObjectStorageInfo")()

	var info hetznerObjectStorageIdentityInfo
	setters := map[string]func(string){
		"s3_access_key_id":                func(value string) { info.S3AccessKeyID = value },
		"s3_access_key_id_source_env":     func(value string) { info.S3AccessKeyIDSourceEnv = value },
		"s3_secret_access_key":            func(value string) { info.S3SecretAccessKey = value },
		"s3_secret_access_key_source_env": func(value string) { info.S3SecretKeySourceEnv = value },
		"s3_endpoint":                     func(value string) { info.S3Endpoint = value },
		"s3_region":                       func(value string) { info.S3Region = value },
	}
	readStringMap(identity.Principal, setters)
	readStringMap(identity.Credentials, setters)
	info.AllConfigured = (info.S3AccessKeyID != "" && info.S3SecretAccessKey != "") ||
		(info.S3AccessKeyIDSourceEnv != "" && info.S3SecretKeySourceEnv != "")
	return info
}

func readStringMap(values map[string]interface{}, setters map[string]func(string)) {
	for key, set := range setters {
		if value, ok := values[key].(string); ok && value != "" {
			set(value)
		}
	}
}

func readStringSlice(values map[string]interface{}, key string) []string {
	raw, ok := values[key]
	if !ok {
		return nil
	}
	if values, ok := raw.([]string); ok {
		return values
	}
	if values, ok := raw.([]any); ok {
		result := make([]string, 0, len(values))
		for _, item := range values {
			if value, ok := item.(string); ok && value != "" {
				result = append(result, value)
			}
		}
		return result
	}
	return nil
}

// formFieldConfig defines configuration for building credential form fields.
type formFieldConfig struct {
	YAMLValue      string
	InputTitle     string
	NoteTitle      string
	NoteDesc       string
	IsPassword     bool
	IsOptional     bool
	DefaultValue   string
	ValidateFunc   func(string) error
	DescriptionMsg string
}

// buildCredentialFormField creates appropriate form field based on whether value is in YAML.
func buildCredentialFormField(cfg formFieldConfig, valuePtr *string) huh.Field {
	defer perf.Track(nil, "auth.user.buildCredentialFormField")()

	if cfg.YAMLValue != "" {
		// Value is in YAML config - show as informational note.
		*valuePtr = cfg.YAMLValue
		return huh.NewNote().
			Title(cfg.NoteTitle).
			Description(cfg.NoteDesc)
	}

	// Value not in YAML - create input field.
	if cfg.DefaultValue != "" {
		*valuePtr = cfg.DefaultValue
	}

	input := huh.NewInput().
		Title(cfg.InputTitle).
		Value(valuePtr)

	if cfg.DescriptionMsg != "" {
		input = input.Description(cfg.DescriptionMsg)
	}

	if cfg.IsPassword {
		input = input.EchoMode(huh.EchoModePassword)
	}

	if cfg.ValidateFunc != nil {
		input = input.Validate(cfg.ValidateFunc)
	} else if !cfg.IsOptional {
		// Default validation: required field.
		input = input.Validate(func(s string) error {
			if s == "" {
				return errUtils.ErrMissingInput
			}
			return nil
		})
	}

	return input
}

// validateSessionDuration validates session duration format.
func validateSessionDuration(s string) error {
	defer perf.Track(nil, "auth.user.validateSessionDuration")()

	if s == "" {
		return nil // Optional field.
	}
	// Validate duration format using flexible parser.
	_, err := authUtils.ParseDurationFlexible(s)
	if err != nil {
		return fmt.Errorf("invalid duration format (use: 3600, 1h, 12h, 1d, etc.)")
	}
	return nil
}
