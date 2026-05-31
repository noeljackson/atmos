package types

import (
	"context"
	"errors"
	"testing"

	errUtils "github.com/cloudposse/atmos/errors"
	"github.com/stretchr/testify/assert"
)

func TestHetznerCredentials_BuildWhoamiInfo(t *testing.T) {
	creds := &HetznerCredentials{
		Project:     "system",
		ProjectID:   "123",
		ProjectName: "sonica-system",
	}
	var info WhoamiInfo

	creds.BuildWhoamiInfo(&info)

	assert.Equal(t, "123", info.Account)
	assert.Equal(t, "sonica-system", info.Principal)
}

func TestHetznerCredentials_ValidateNotImplemented(t *testing.T) {
	_, err := (&HetznerCredentials{}).Validate(context.Background())

	assert.True(t, errors.Is(err, errUtils.ErrNotImplemented))
}
