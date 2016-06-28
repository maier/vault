package approle

import (
	"fmt"
	"time"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathLogin(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "login$",
		Fields: map[string]*framework.FieldSchema{
			"selector_id": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Unique identifier of the Role. Required to be supplied when the bound type is 'bound_secret_id'",
			},
			"secret_id": &framework.FieldSchema{
				Type:        framework.TypeString,
				Default:     "",
				Description: "SecretID of the Role",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathLoginUpdate,
		},
		HelpSynopsis:    pathLoginHelpSys,
		HelpDescription: pathLoginHelpDesc,
	}
}

// Returns the Auth object indicating the authentication and authorization information
// if the credentials provided are validated by the backend.
func (b *backend) pathLoginUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	role, err := b.validateCredentials(req, data)
	if err != nil || role == nil {
		return logical.ErrorResponse(fmt.Sprintf("failed to validate SecretID: %s", err)), nil
	}

	auth := &logical.Auth{
		Period: role.Period,
		InternalData: map[string]interface{}{
			"selector_id": role.SelectorID,
		},
		Policies: role.Policies,
		LeaseOptions: logical.LeaseOptions{
			Renewable: true,
		},
	}

	// If 'Period' is set, use the value of 'Period' as the TTL.
	// Otherwise, set the normal TokenTTL.
	if role.Period > time.Duration(0) {
		auth.TTL = role.Period
	} else {
		auth.TTL = role.TokenTTL
	}

	return &logical.Response{
		Auth: auth,
	}, nil
}

// Invoked when the token issued by this backend is attempting a renewal.
func (b *backend) pathLoginRenew(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	selectorID := req.Auth.InternalData["selector_id"].(string)
	if selectorID == "" {
		return nil, fmt.Errorf("failed to fetch selector_id during renewal")
	}

	// Ensure that the Role still exists.
	role, err := b.validateSelectorID(req.Storage, selectorID)
	if err != nil {
		return nil, fmt.Errorf("failed to validate selector during renewal:%s", err)
	}

	// If 'Period' is set on the Role, the token should never expire.
	// Replenish the TTL with 'Period's value.
	if role.Period > time.Duration(0) {
		// If 'Period' was updated after the token was issued,
		// token will bear the updated 'Period' value as its TTL.
		req.Auth.TTL = role.Period
		return &logical.Response{Auth: req.Auth}, nil
	} else {
		return framework.LeaseExtend(role.TokenTTL, role.TokenMaxTTL, b.System())(req, data)
	}
}

const pathLoginHelpSys = "Issue a token based on the credentials supplied"

const pathLoginHelpDesc = `
While the credential 'selector_id' is required at all times,
other credentials required depends on the properties App role
to which the 'selector_id' belongs to. The 'bound_secret_id'
constraint (enabled by default) on the App role requires the
'secret_id' credential to be presented.

'selector_id' is fetched using the 'role/<role_name>/selector_id'
endpoint and 'secret_id' is fetched using the 'role/<role_name>/secret_id'
endpoint.`
