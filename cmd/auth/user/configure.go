package user

import (
	"fmt"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	errUtils "github.com/cloudposse/atmos/errors"
	"github.com/cloudposse/atmos/internal/tui/utils"
	"github.com/cloudposse/atmos/pkg/auth/credentials"
	authTypes "github.com/cloudposse/atmos/pkg/auth/types"
	cfg "github.com/cloudposse/atmos/pkg/config"
	"github.com/cloudposse/atmos/pkg/flags"
	"github.com/cloudposse/atmos/pkg/perf"
	"github.com/cloudposse/atmos/pkg/schema"
	"github.com/cloudposse/atmos/pkg/ui"
)

// authUserConfigureCmd prompts for static AWS user credentials and stores them in keyring.
var authUserConfigureCmd = &cobra.Command{
	Use:                "configure",
	Short:              "Configure static user credentials (stored securely in keyring)",
	Long:               `Configure static user credentials (stored securely in keyring)`,
	FParseErrWhitelist: struct{ UnknownFlags bool }{UnknownFlags: false},
	RunE:               executeAuthUserConfigureCommand,
}

func init() {
	defer perf.Track(nil, "auth.user.configure.init")()
	AuthUserCmd.AddCommand(authUserConfigureCmd)
}

// executeAuthUserConfigureCommand is the main execution function for auth user configure.
func executeAuthUserConfigureCommand(cmd *cobra.Command, args []string) error {
	defer perf.Track(nil, "auth.user.executeAuthUserConfigureCommand")()

	// Parse global flags and build ConfigAndStacksInfo to honor --base-path, --config, --config-path, --profile.
	v := viper.GetViper()
	configAndStacksInfo := flags.BuildConfigAndStacksInfo(cmd, v)

	// Load atmos config.
	atmosConfig, err := cfg.InitCliConfig(configAndStacksInfo, false)
	if err != nil {
		return fmt.Errorf(errUtils.ErrWrapFormat, errUtils.ErrInvalidAuthConfig, err)
	}

	// Select identities that support static keyring-backed configuration.
	selectable, defaultChoice, err := selectConfigurableUserIdentities(atmosConfig.Auth.Identities)
	if err != nil {
		return err
	}

	// Guard: ensure there are identities to configure.
	if len(selectable) == 0 {
		return fmt.Errorf("%w: no configurable identities found in configuration", errUtils.ErrNoIdentitiesAvailable)
	}

	// Choose identity.
	choice := getIdentityFlagValue(cmd)
	if choice == cfg.IdentityFlagSelectValue {
		choice = ""
	}
	if choice != "" {
		if err := validateConfigurableIdentityChoice(atmosConfig.Auth.Identities, choice); err != nil {
			return err
		}
	} else {
		choice = defaultChoice
		selector := huh.NewSelect[string]().
			Value(&choice).
			OptionsFunc(func() []huh.Option[string] { return huh.NewOptions(selectable...) }, nil).
			Title("Choose an identity to configure").
			WithTheme(utils.NewAtmosHuhTheme())
		if err := selector.Run(); err != nil {
			return err
		}
	}

	selectedIdentity := atmosConfig.Auth.Identities[choice]
	switch selectedIdentity.Kind {
	case authTypes.ProviderKindAWSUser:
		return configureAWSUserIdentity(selectedIdentity, choice)
	case authTypes.IdentityKindHetznerProject:
		return configureHetznerProjectIdentity(selectedIdentity, choice)
	case authTypes.IdentityKindHetznerObjectStorage:
		return configureHetznerObjectStorageIdentity(selectedIdentity, choice)
	default:
		return fmt.Errorf("%w: identity %q has unsupported kind %q for auth user configure", errUtils.ErrInvalidAuthConfig, choice, selectedIdentity.Kind)
	}
}

func configureAWSUserIdentity(selectedIdentity schema.Identity, alias string) error {
	yamlInfo := extractAWSUserInfo(selectedIdentity)
	// Check if all credentials are managed by Atmos configuration.
	if yamlInfo.AllInYAML {
		// All credentials are in YAML - nothing to configure in keyring.
		ui.Writeln("All credentials are managed by Atmos configuration (atmos.yaml)")
		ui.Writeln("To update credentials, edit your atmos.yaml configuration file")
		if yamlInfo.MfaArn != "" {
			ui.Writef("MFA ARN is also managed by Atmos configuration: %s\n", yamlInfo.MfaArn)
		}
		return nil
	}

	// Prompt and save credentials.
	return promptAndSaveCredentials(yamlInfo, alias)
}

func configureHetznerProjectIdentity(selectedIdentity schema.Identity, alias string) error {
	yamlInfo := extractHetznerProjectInfo(selectedIdentity)
	if yamlInfo.AllConfigured {
		ui.Writeln("Hetzner project token is managed by Atmos configuration (atmos.yaml)")
		ui.Writeln("To update credentials, edit your atmos.yaml configuration file")
		return nil
	}
	creds, err := promptForHetznerProjectCredentials(yamlInfo)
	if err != nil {
		return err
	}
	store := credentials.NewCredentialStore()
	if err := store.Store(alias, creds, ""); err != nil {
		return fmt.Errorf(errUtils.ErrWrapFormat, errUtils.ErrAuthenticationFailed, err)
	}
	ui.Writef("Saved Hetzner project credentials to keyring: %s\n", alias)
	if yamlInfo.ObjectStorageIdentity != "" {
		ui.Writef("Object Storage identity: %s\n", yamlInfo.ObjectStorageIdentity)
	}
	return nil
}

func configureHetznerObjectStorageIdentity(selectedIdentity schema.Identity, alias string) error {
	yamlInfo := extractHetznerObjectStorageInfo(selectedIdentity)
	if yamlInfo.AllConfigured {
		ui.Writeln("Hetzner Object Storage credentials are managed by Atmos configuration (atmos.yaml)")
		ui.Writeln("To update credentials, edit your atmos.yaml configuration file")
		return nil
	}
	creds, err := promptForHetznerObjectStorageCredentials(yamlInfo)
	if err != nil {
		return err
	}
	store := credentials.NewCredentialStore()
	if err := store.Store(alias, creds, ""); err != nil {
		return fmt.Errorf(errUtils.ErrWrapFormat, errUtils.ErrAuthenticationFailed, err)
	}
	ui.Writef("Saved Hetzner Object Storage credentials to keyring: %s\n", alias)
	return nil
}

// promptAndSaveCredentials prompts for credentials and saves them to keyring.
func promptAndSaveCredentials(yamlInfo awsUserIdentityInfo, alias string) error {
	defer perf.Track(nil, "auth.user.promptAndSaveCredentials")()

	// Prompt user for credentials.
	creds, err := promptForCredentials(yamlInfo)
	if err != nil {
		return err
	}

	// Save credentials to keyring.
	store := credentials.NewCredentialStore()
	if err := store.Store(alias, creds, ""); err != nil {
		return fmt.Errorf(errUtils.ErrWrapFormat, errUtils.ErrAwsAuth, err)
	}
	ui.Writef("Saved credentials to keyring: %s\n", alias)
	if creds.SessionDuration != "" {
		ui.Writef("Session duration configured: %s\n", creds.SessionDuration)
	}
	return nil
}

// promptForCredentials builds and runs the credential form.
func promptForCredentials(yamlInfo awsUserIdentityInfo) (*authTypes.AWSCredentials, error) {
	defer perf.Track(nil, "auth.user.promptForCredentials")()

	var accessKeyID, secretAccessKey, mfaArn, sessionDuration string
	var formFields []huh.Field

	// Access Key ID.
	formFields = append(formFields, buildCredentialFormField(formFieldConfig{
		YAMLValue:  yamlInfo.AccessKeyID,
		InputTitle: "AWS Access Key ID",
		NoteTitle:  "AWS Access Key ID (managed by Atmos configuration)",
		NoteDesc:   yamlInfo.AccessKeyID,
		IsOptional: false,
	}, &accessKeyID))

	// Secret Access Key.
	formFields = append(formFields, buildCredentialFormField(formFieldConfig{
		YAMLValue:  yamlInfo.SecretAccessKey,
		InputTitle: "AWS Secret Access Key",
		NoteTitle:  "AWS Secret Access Key (managed by Atmos configuration)",
		NoteDesc:   "****** (configured in atmos.yaml)",
		IsPassword: true,
		IsOptional: false,
	}, &secretAccessKey))

	// MFA ARN.
	formFields = append(formFields, buildCredentialFormField(formFieldConfig{
		YAMLValue:  yamlInfo.MfaArn,
		InputTitle: "AWS User MFA ARN (optional)",
		NoteTitle:  "AWS User MFA ARN (managed by Atmos configuration)",
		NoteDesc:   yamlInfo.MfaArn,
		IsOptional: true,
	}, &mfaArn))

	// Session Duration.
	formFields = append(formFields, buildCredentialFormField(formFieldConfig{
		YAMLValue:      yamlInfo.SessionDuration,
		InputTitle:     "Session Duration (optional, default: 12h)",
		NoteTitle:      "Session Duration (managed by Atmos configuration)",
		NoteDesc:       fmt.Sprintf("%s (configured in atmos.yaml)", yamlInfo.SessionDuration),
		IsOptional:     true,
		DefaultValue:   "12h",
		ValidateFunc:   validateSessionDuration,
		DescriptionMsg: "How long before you need to re-enter MFA. Examples: 3600 (seconds), 1h, 12h, 1d, 24h (max 36h with MFA)",
	}, &sessionDuration))

	form := huh.NewForm(huh.NewGroup(formFields...)).WithTheme(utils.NewAtmosHuhTheme())
	if err := form.Run(); err != nil {
		return nil, err
	}

	return &authTypes.AWSCredentials{
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
		MfaArn:          mfaArn,
		SessionDuration: sessionDuration,
	}, nil
}

func promptForHetznerProjectCredentials(yamlInfo hetznerProjectIdentityInfo) (*authTypes.HetznerCredentials, error) {
	defer perf.Track(nil, "auth.user.promptForHetznerProjectCredentials")()

	var token string
	fields := []huh.Field{
		buildCredentialFormField(formFieldConfig{
			YAMLValue:  yamlInfo.Token,
			InputTitle: "Hetzner API token",
			NoteTitle:  "Hetzner API token (managed by Atmos configuration)",
			NoteDesc:   "****** (configured in atmos.yaml)",
			IsPassword: true,
		}, &token),
	}
	form := huh.NewForm(huh.NewGroup(fields...)).WithTheme(utils.NewAtmosHuhTheme())
	if err := form.Run(); err != nil {
		return nil, err
	}
	return &authTypes.HetznerCredentials{
		Token:       token,
		Project:     yamlInfo.Project,
		ProjectID:   yamlInfo.ProjectID,
		ProjectName: yamlInfo.ProjectName,
		TokenEnv:    yamlInfo.TokenEnv,
	}, nil
}

func promptForHetznerObjectStorageCredentials(yamlInfo hetznerObjectStorageIdentityInfo) (*authTypes.HetznerCredentials, error) {
	defer perf.Track(nil, "auth.user.promptForHetznerObjectStorageCredentials")()

	var accessKeyID, secretAccessKey, endpoint, region string
	fields := []huh.Field{
		buildCredentialFormField(formFieldConfig{
			YAMLValue:  yamlInfo.S3AccessKeyID,
			InputTitle: "Hetzner Object Storage access key ID",
			NoteTitle:  "Hetzner Object Storage access key ID (managed by Atmos configuration)",
			NoteDesc:   yamlInfo.S3AccessKeyID,
		}, &accessKeyID),
		buildCredentialFormField(formFieldConfig{
			YAMLValue:  yamlInfo.S3SecretAccessKey,
			InputTitle: "Hetzner Object Storage secret access key",
			NoteTitle:  "Hetzner Object Storage secret access key (managed by Atmos configuration)",
			NoteDesc:   "****** (configured in atmos.yaml)",
			IsPassword: true,
		}, &secretAccessKey),
		buildCredentialFormField(formFieldConfig{
			YAMLValue:    yamlInfo.S3Endpoint,
			InputTitle:   "Hetzner Object Storage S3 endpoint (optional)",
			NoteTitle:    "Hetzner Object Storage S3 endpoint (managed by Atmos configuration)",
			NoteDesc:     yamlInfo.S3Endpoint,
			IsOptional:   true,
			DefaultValue: yamlInfo.S3Endpoint,
		}, &endpoint),
		buildCredentialFormField(formFieldConfig{
			YAMLValue:    yamlInfo.S3Region,
			InputTitle:   "Hetzner Object Storage S3 region (optional)",
			NoteTitle:    "Hetzner Object Storage S3 region (managed by Atmos configuration)",
			NoteDesc:     yamlInfo.S3Region,
			IsOptional:   true,
			DefaultValue: yamlInfo.S3Region,
		}, &region),
	}
	form := huh.NewForm(huh.NewGroup(fields...)).WithTheme(utils.NewAtmosHuhTheme())
	if err := form.Run(); err != nil {
		return nil, err
	}
	return &authTypes.HetznerCredentials{
		S3AccessKeyID:     accessKeyID,
		S3SecretAccessKey: secretAccessKey,
		S3Endpoint:        endpoint,
		S3Region:          region,
	}, nil
}

func getIdentityFlagValue(cmd *cobra.Command) string {
	if cmd == nil {
		return viper.GetString(cfg.IdentityFlagName)
	}
	if flag := cmd.Flag(cfg.IdentityFlagName); flag != nil && flag.Changed {
		return flag.Value.String()
	}
	if flag := cmd.InheritedFlags().Lookup(cfg.IdentityFlagName); flag != nil && flag.Changed {
		return flag.Value.String()
	}
	return viper.GetString(cfg.IdentityFlagName)
}
