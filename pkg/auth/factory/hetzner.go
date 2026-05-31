package factory

import (
	"fmt"

	errUtils "github.com/cloudposse/atmos/errors"
	"github.com/cloudposse/atmos/pkg/auth/identities/hetzner_object_storage"
	"github.com/cloudposse/atmos/pkg/auth/identities/hetzner_project"
	"github.com/cloudposse/atmos/pkg/auth/providers/hetzner"
	"github.com/cloudposse/atmos/pkg/auth/types"
	"github.com/cloudposse/atmos/pkg/perf"
)

// RegisterHetznerProviders registers Hetzner provider constructors.
func RegisterHetznerProviders(f *Factory) {
	defer perf.Track(nil, "factory.RegisterHetznerProviders")()

	f.RegisterProvider(types.ProviderKindHetznerToken, func(name string, spec map[string]any) (types.Provider, error) {
		parsed, err := types.ParseHetznerTokenProviderSpec(spec)
		if err != nil {
			return nil, fmt.Errorf("%w: parse hetzner/token spec: %v", errUtils.ErrInvalidProviderConfig, err)
		}
		provider, err := hetzner.New(parsed)
		if err != nil {
			return nil, err
		}
		provider.SetName(name)
		return provider, nil
	})
}

// RegisterHetznerIdentities registers Hetzner identity constructors.
func RegisterHetznerIdentities(f *Factory) {
	defer perf.Track(nil, "factory.RegisterHetznerIdentities")()

	f.RegisterIdentity(types.IdentityKindHetznerProject, func(name string, principal map[string]any) (types.Identity, error) {
		parsed, err := types.ParseHetznerProjectIdentityPrincipal(principal)
		if err != nil {
			return nil, fmt.Errorf("%w: parse hetzner/project principal: %v", errUtils.ErrInvalidIdentityConfig, err)
		}
		identity, err := hetzner_project.New(parsed)
		if err != nil {
			return nil, err
		}
		identity.SetName(name)
		return identity, nil
	})

	f.RegisterIdentity(types.IdentityKindHetznerObjectStorage, func(name string, principal map[string]any) (types.Identity, error) {
		parsed, err := types.ParseHetznerObjectStorageIdentityPrincipal(principal)
		if err != nil {
			return nil, fmt.Errorf("%w: parse hetzner/object-storage principal: %v", errUtils.ErrInvalidIdentityConfig, err)
		}
		identity, err := hetzner_object_storage.New(parsed)
		if err != nil {
			return nil, err
		}
		identity.SetName(name)
		return identity, nil
	})
}
