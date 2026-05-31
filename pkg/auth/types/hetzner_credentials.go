package types

import (
	"context"
	"fmt"
	"time"

	errUtils "github.com/cloudposse/atmos/errors"
)

// HetznerCredentials defines Hetzner Cloud and Object Storage credential fields.
type HetznerCredentials struct {
	Token             string   `json:"token,omitempty"`
	Project           string   `json:"project,omitempty"`
	ProjectID         string   `json:"project_id,omitempty"`
	ProjectName       string   `json:"project_name,omitempty"`
	S3AccessKeyID     string   `json:"s3_access_key_id,omitempty"`
	S3SecretAccessKey string   `json:"s3_secret_access_key,omitempty"`
	S3Endpoint        string   `json:"s3_endpoint,omitempty"`
	S3Region          string   `json:"s3_region,omitempty"`
	TokenEnv          []string `json:"token_env,omitempty"`
}

// IsExpired returns false because Hetzner API tokens do not expose expiration metadata.
func (c *HetznerCredentials) IsExpired() bool {
	return false
}

// GetExpiration returns nil because Hetzner credentials are not time-bounded here.
func (c *HetznerCredentials) GetExpiration() (*time.Time, error) {
	return nil, nil
}

// BuildWhoamiInfo implements ICredentials for HetznerCredentials.
func (c *HetznerCredentials) BuildWhoamiInfo(info *WhoamiInfo) {
	if info == nil {
		return
	}
	if c.ProjectID != "" {
		info.Account = c.ProjectID
	}
	if c.ProjectName != "" {
		info.Principal = c.ProjectName
	} else if c.Project != "" {
		info.Principal = c.Project
	}
}

// Validate is intentionally not implemented until an hcloud API validator is added.
func (c *HetznerCredentials) Validate(ctx context.Context) (*ValidationInfo, error) {
	return nil, fmt.Errorf("%w: Hetzner credential validation not yet implemented", errUtils.ErrNotImplemented)
}
