package approle

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/fatih/structs"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/helper/policyutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

// roleStorageEntry stores all the options that are set on an Role
type roleStorageEntry struct {
	// UUID that uniquely represents this Role. This serves as a credential
	// to perform login using this Role.
	RoleID string `json:"role_id" structs:"role_id" mapstructure:"role_id"`

	// UUID that serves as the HMAC key for the hashing the 'secret_id's
	// of the Role
	HMACKey string `json:"hmac_key" structs:"hmac_key" mapstructure:"hmac_key"`

	// Policies that are to be required by the token to access this Role
	Policies []string `json:"policies" structs:"policies" mapstructure:"policies"`

	// Number of times the SecretID generated against this Role can be
	// used to perform login operation
	SecretIDNumUses int `json:"secret_id_num_uses" structs:"secret_id_num_uses" mapstructure:"secret_id_num_uses"`

	// Duration (less than the backend mount's max TTL) after which a
	// SecretID generated against the Role will expire
	SecretIDTTL time.Duration `json:"secret_id_ttl" structs:"secret_id_ttl" mapstructure:"secret_id_ttl"`

	// Duration before which an issued token must be renewed
	TokenTTL time.Duration `json:"token_ttl" structs:"token_ttl" mapstructure:"token_ttl"`

	// Duration after which an issued token should not be allowed to be renewed
	TokenMaxTTL time.Duration `json:"token_max_ttl" structs:"token_max_ttl" mapstructure:"token_max_ttl"`

	// A constraint, if set, requires 'secret_id' credential to be presented during login
	BoundSecretID bool `json:"bound_secret_id" structs:"bound_secret_id" mapstructure:"bound_secret_id"`

	// A constraint, if set, specifies the CIDR blocks from which logins should be allowed
	BoundCIDRList string `json:"bound_cidr_list" structs:"bound_cidr_list" mapstructure:"bound_cidr_list"`

	// Period, if set, indicates that the token generated using this Role
	// should never expire. The token should be renewed within the duration
	// specified by this value. The renewal duration will be fixed if the
	// value is not modified on the Role. If the `Period` in the Role is modified,
	// a token will pick up the new value during its next renewal.
	Period time.Duration `json:"period" mapstructure:"period" structs:"period"`
}

// rolePaths creates all the paths that are used to register and manage an Role.
//
// Paths returned:
// role/ - For listing all the registered Roles
// role/<role_name> - For registering an Role
// role/<role_name>/policies - For updating the param
// role/<role_name>/secret-id-num-uses - For updating the param
// role/<role_name>/secret-id-ttl - For updating the param
// role/<role_name>/token-ttl - For updating the param
// role/<role_name>/token-max-ttl - For updating the param
// role/<role_name>/bound-secret-id - For updating the param
// role/<role_name>/bound-cidr-list - For updating the param
// role/<role_name>/period - For updating the param
// role/<role_name>/role-id - For fetching the role_id of an Role
// role/<role_name>/secret-id - For issuing a secret_id against an Role, also to list the secret_id_accessorss
// role/<role_name>/secret-id/<secret_id_accessor> - For reading the properties of, or deleting a secret_id
// role/<role_name>/custom-secret-id - For assigning a custom SecretID against an Role
func rolePaths(b *backend) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern: "role/?",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathRoleList,
			},
			HelpSynopsis:    strings.TrimSpace(roleHelp["role-list"][0]),
			HelpDescription: strings.TrimSpace(roleHelp["role-list"][1]),
		},
		&framework.Path{
			Pattern: "role/" + framework.GenericNameRegex("role_name"),
			Fields: map[string]*framework.FieldSchema{
				"role_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the Role.",
				},
				"bound_secret_id": &framework.FieldSchema{
					Type:        framework.TypeBool,
					Default:     true,
					Description: "Impose secret_id to be presented when logging in using this Role. Defaults to 'true'.",
				},
				"bound_cidr_list": &framework.FieldSchema{
					Type: framework.TypeString,
					Description: `Comma separated list of CIDR blocks, if set, specifies blocks of IP
addresses which can perform the login operation`,
				},
				"policies": &framework.FieldSchema{
					Type:        framework.TypeString,
					Default:     "default",
					Description: "Comma separated list of policies on the Role.",
				},
				"secret_id_num_uses": &framework.FieldSchema{
					Type:        framework.TypeInt,
					Description: "Number of times a SecretID can access the Role, after which the SecretID will expire.",
				},
				"secret_id_ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Description: "Duration in seconds after which the issued SecretID should expire.",
				},
				"token_ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Description: "Duration in seconds after which the issued token should expire.",
				},
				"token_max_ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Description: "Duration in seconds after which the issued token should not be allowed to be renewed.",
				},
				"period": &framework.FieldSchema{
					Type:    framework.TypeDurationSecond,
					Default: 0,
					Description: `If set, indicates that the token generated using this Role
should never expire. The token should be renewed within the
duration specified by this value. The renewal duration will
be fixed, if this value is not modified. If the Period in the
Role is modified, the token will pick up the new value during
its next renewal.`,
				},
			},
			ExistenceCheck: b.pathRoleExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: b.pathRoleCreateUpdate,
				logical.UpdateOperation: b.pathRoleCreateUpdate,
				logical.ReadOperation:   b.pathRoleRead,
				logical.DeleteOperation: b.pathRoleDelete,
			},
			HelpSynopsis:    strings.TrimSpace(roleHelp["role"][0]),
			HelpDescription: strings.TrimSpace(roleHelp["role"][1]),
		},
		&framework.Path{
			Pattern: "role/" + framework.GenericNameRegex("role_name") + "/policies$",
			Fields: map[string]*framework.FieldSchema{
				"role_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the Role.",
				},
				"policies": &framework.FieldSchema{
					Type:        framework.TypeString,
					Default:     "default",
					Description: "Comma separated list of policies on the Role.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathRolePoliciesUpdate,
				logical.ReadOperation:   b.pathRolePoliciesRead,
				logical.DeleteOperation: b.pathRolePoliciesDelete,
			},
			HelpSynopsis:    strings.TrimSpace(roleHelp["role-policies"][0]),
			HelpDescription: strings.TrimSpace(roleHelp["role-policies"][1]),
		},
		&framework.Path{
			Pattern: "role/" + framework.GenericNameRegex("role_name") + "/bound-cidr-list$",
			Fields: map[string]*framework.FieldSchema{
				"role_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the Role.",
				},
				"bound_cidr_list": &framework.FieldSchema{
					Type: framework.TypeString,
					Description: `Comma separated list of CIDR blocks, if set, specifies blocks of IP
addresses which can perform the login operation`,
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathRoleBoundCIDRListUpdate,
				logical.ReadOperation:   b.pathRoleBoundCIDRListRead,
				logical.DeleteOperation: b.pathRoleBoundCIDRListDelete,
			},
			HelpSynopsis:    strings.TrimSpace(roleHelp["role-bound-cidr-list"][0]),
			HelpDescription: strings.TrimSpace(roleHelp["role-bound-cidr-list"][1]),
		},
		&framework.Path{
			Pattern: "role/" + framework.GenericNameRegex("role_name") + "/bound-secret-id$",
			Fields: map[string]*framework.FieldSchema{
				"role_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the Role.",
				},
				"bound_secret_id": &framework.FieldSchema{
					Type:        framework.TypeBool,
					Default:     true,
					Description: "Impose secret_id to be presented when logging in using this Role.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathRoleBoundSecretIDUpdate,
				logical.ReadOperation:   b.pathRoleBoundSecretIDRead,
				logical.DeleteOperation: b.pathRoleBoundSecretIDDelete,
			},
			HelpSynopsis:    strings.TrimSpace(roleHelp["role-bound-secret-id"][0]),
			HelpDescription: strings.TrimSpace(roleHelp["role-bound-secret-id"][1]),
		},
		&framework.Path{
			Pattern: "role/" + framework.GenericNameRegex("role_name") + "/num-uses$",
			Fields: map[string]*framework.FieldSchema{
				"role_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the Role.",
				},
				"secret_id_num_uses": &framework.FieldSchema{
					Type:        framework.TypeInt,
					Description: "Number of times a SecretID can access the Role, after which the SecretID will expire.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathRoleSecretIDNumUsesUpdate,
				logical.ReadOperation:   b.pathRoleSecretIDNumUsesRead,
				logical.DeleteOperation: b.pathRoleSecretIDNumUsesDelete,
			},
			HelpSynopsis:    strings.TrimSpace(roleHelp["role-num-uses"][0]),
			HelpDescription: strings.TrimSpace(roleHelp["role-num-uses"][1]),
		},
		&framework.Path{
			Pattern: "role/" + framework.GenericNameRegex("role_name") + "/secret-id-ttl$",
			Fields: map[string]*framework.FieldSchema{
				"role_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the Role.",
				},
				"secret_id_ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Description: "Duration in seconds after which the issued SecretID should expire.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathRoleSecretIDTTLUpdate,
				logical.ReadOperation:   b.pathRoleSecretIDTTLRead,
				logical.DeleteOperation: b.pathRoleSecretIDTTLDelete,
			},
			HelpSynopsis:    strings.TrimSpace(roleHelp["role-secret-id-ttl"][0]),
			HelpDescription: strings.TrimSpace(roleHelp["role-secret-id-ttl"][1]),
		},
		&framework.Path{
			Pattern: "role/" + framework.GenericNameRegex("role_name") + "/period$",
			Fields: map[string]*framework.FieldSchema{
				"role_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the Role.",
				},
				"period": &framework.FieldSchema{
					Type:    framework.TypeDurationSecond,
					Default: 0,
					Description: `If set, indicates that the token generated using this Role
should never expire. The token should be renewed within the
duration specified by this value. The renewal duration will
be fixed if this value is not modified. If the Period in the
Role is modified, the token will pick up the new value during
its next renewal.`,
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathRolePeriodUpdate,
				logical.ReadOperation:   b.pathRolePeriodRead,
				logical.DeleteOperation: b.pathRolePeriodDelete,
			},
			HelpSynopsis:    strings.TrimSpace(roleHelp["role-period"][0]),
			HelpDescription: strings.TrimSpace(roleHelp["role-period"][1]),
		},

		&framework.Path{
			Pattern: "role/" + framework.GenericNameRegex("role_name") + "/token-ttl$",
			Fields: map[string]*framework.FieldSchema{
				"role_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the Role.",
				},
				"token_ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Description: "Duration in seconds after which the issued token should expire.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathRoleTokenTTLUpdate,
				logical.ReadOperation:   b.pathRoleTokenTTLRead,
				logical.DeleteOperation: b.pathRoleTokenTTLDelete,
			},
			HelpSynopsis:    strings.TrimSpace(roleHelp["role-token-ttl"][0]),
			HelpDescription: strings.TrimSpace(roleHelp["role-token-ttl"][1]),
		},
		&framework.Path{
			Pattern: "role/" + framework.GenericNameRegex("role_name") + "/token-max-ttl$",
			Fields: map[string]*framework.FieldSchema{
				"role_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the Role.",
				},
				"token_max_ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Description: "Duration in seconds after which the issued token should not be allowed to be renewed.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathRoleTokenMaxTTLUpdate,
				logical.ReadOperation:   b.pathRoleTokenMaxTTLRead,
				logical.DeleteOperation: b.pathRoleTokenMaxTTLDelete,
			},
			HelpSynopsis:    strings.TrimSpace(roleHelp["role-token-max-ttl"][0]),
			HelpDescription: strings.TrimSpace(roleHelp["role-token-max-ttl"][1]),
		},
		&framework.Path{
			Pattern: "role/" + framework.GenericNameRegex("role_name") + "/role-id$",
			Fields: map[string]*framework.FieldSchema{
				"role_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the Role.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: b.pathRoleRoleIDRead,
			},
			HelpSynopsis:    strings.TrimSpace(roleHelp["role-id"][0]),
			HelpDescription: strings.TrimSpace(roleHelp["role-id"][1]),
		},
		&framework.Path{
			Pattern: "role/" + framework.GenericNameRegex("role_name") + "/secret-id/?$",
			Fields: map[string]*framework.FieldSchema{
				"role_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the Role.",
				},
				"metadata": &framework.FieldSchema{
					Type: framework.TypeString,
					Description: `Metadata to be tied to the SecretID. This should be a JSON
formatted string containing the metadata in key value pairs.`,
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathRoleSecretIDUpdate,
				logical.ListOperation:   b.pathRoleSecretIDList,
			},
			HelpSynopsis:    strings.TrimSpace(roleHelp["role-secret-id"][0]),
			HelpDescription: strings.TrimSpace(roleHelp["role-secret-id"][1]),
		},
		&framework.Path{
			Pattern: "role/" + framework.GenericNameRegex("role_name") + "/secret-id/" + framework.GenericNameRegex("secret_id_accessor"),
			Fields: map[string]*framework.FieldSchema{
				"role_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the Role.",
				},
				"secret_id_accessor": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Accessor of the SecretID",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation:   b.pathRoleSecretIDAccessorRead,
				logical.DeleteOperation: b.pathRoleSecretIDAccessorDelete,
			},
			HelpSynopsis:    strings.TrimSpace(roleHelp["role-secret-id-accessor"][0]),
			HelpDescription: strings.TrimSpace(roleHelp["role-secret-id-accessor"][1]),
		},
		&framework.Path{
			Pattern: "role/" + framework.GenericNameRegex("role_name") + "/custom-secret-id$",
			Fields: map[string]*framework.FieldSchema{
				"role_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the Role.",
				},
				"secret_id": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "SecretID to be attached to the Role.",
				},
				"metadata": &framework.FieldSchema{
					Type: framework.TypeString,
					Description: `Metadata to be tied to the SecretID. This should be a JSON
formatted string containing metadata in key value pairs.`,
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathRoleCustomSecretIDUpdate,
			},
			HelpSynopsis:    strings.TrimSpace(roleHelp["role-custom-secret-id"][0]),
			HelpDescription: strings.TrimSpace(roleHelp["role-custom-secret-id"][1]),
		},
	}
}

// pathRoleExistenceCheck returns whether the role with the given name exists or not.
func (b *backend) pathRoleExistenceCheck(req *logical.Request, data *framework.FieldData) (bool, error) {
	role, err := b.roleEntry(req.Storage, data.Get("role_name").(string))
	if err != nil {
		return false, err
	}
	return role != nil, nil
}

// pathRoleList is used to list all the Roles registered with the backend.
func (b *backend) pathRoleList(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.roleLock.RLock()
	defer b.roleLock.RUnlock()
	roles, err := req.Storage.List("role/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(roles), nil
}

// pathRoleSecretIDList is used to list all the 'secret_id_accessor's issued against the Role.
func (b *backend) pathRoleSecretIDList(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role_name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role_name"), nil
	}

	// Get the role entry
	role, err := b.roleEntry(req.Storage, strings.ToLower(roleName))
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("role %s does not exist", roleName)), nil
	}

	// If the argument to secretIDLock does not start with 2 hex
	// chars, a generic lock is returned. So, passing empty string
	// to get the "custom" lock that could be used for listing.
	lock := b.secretIDLock("")
	lock.RLock()
	defer lock.RUnlock()

	// Listing works one level at a time. Get the first level of data
	// which could then be used to get the actual SecretID storage entries.
	secretIDHMACs, err := req.Storage.List(fmt.Sprintf("secret_id/%s/", b.salt.SaltID(role.RoleID)))
	if err != nil {
		return nil, err
	}

	var listItems []string
	for _, secretIDHMAC := range secretIDHMACs {
		// Prepare the full index of the SecretIDs.
		entryIndex := fmt.Sprintf("secret_id/%s/%s", b.salt.SaltID(role.RoleID), secretIDHMAC)

		// SecretID locks are not indexed by SecretIDs itself.
		// This is because SecretIDs are not stored in plaintext
		// form anywhere in the backend, and hence accessing its
		// corresponding lock many times using SecretIDs is not
		// possible. Also, indexing it everywhere using secretIDHMACs
		// makes listing operation easier.
		lock := b.secretIDLock(secretIDHMAC)
		lock.RLock()

		result := secretIDStorageEntry{}
		if entry, err := req.Storage.Get(entryIndex); err != nil {
			lock.RUnlock()
			return nil, err
		} else if entry == nil {
			lock.RUnlock()
			return nil, fmt.Errorf("storage entry for SecretID is present but no content found at the index")
		} else if err := entry.DecodeJSON(&result); err != nil {
			lock.RUnlock()
			return nil, err
		}
		listItems = append(listItems, result.SecretIDAccessor)
		lock.RUnlock()
	}

	return logical.ListResponse(listItems), nil
}

// setRoleEntry grabs a write lock and stores the options on an Role into the storage.
// Also creates a reverse index from the Role's RoleID to the Role itself.
func (b *backend) setRoleEntry(s logical.Storage, roleName string, role *roleStorageEntry) error {
	b.roleLock.Lock()
	defer b.roleLock.Unlock()

	// Create a storage entry for the Role
	entry, err := logical.StorageEntryJSON("role/"+strings.ToLower(roleName), role)
	if err != nil {
		return err
	}
	if entry == nil {
		return fmt.Errorf("failed to create storage entry for role %s", roleName)
	}
	if err = s.Put(entry); err != nil {
		return err
	}

	// Create a storage entry for reverse mroleing of RoleID to Role.
	// Note that secondary index is created when the roleLock is held.
	return b.setRoleIDEntry(s, role.RoleID, &roleIDStorageEntry{
		Type: "role",
		Name: roleName,
	})
}

// roleEntry grabs the read lock and fetches the options of an Role from the storage
func (b *backend) roleEntry(s logical.Storage, roleName string) (*roleStorageEntry, error) {
	if roleName == "" {
		return nil, fmt.Errorf("missing role_name")
	}

	var result roleStorageEntry

	b.roleLock.RLock()
	defer b.roleLock.RUnlock()

	if entry, err := s.Get("role/" + strings.ToLower(roleName)); err != nil {
		return nil, err
	} else if entry == nil {
		return nil, nil
	} else if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

// pathRoleCreateUpdate registers a new Role with the backend or updates the options
// of an existing Role
func (b *backend) pathRoleCreateUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role_name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role_name"), nil
	}

	// Check if the Role already exists
	role, err := b.roleEntry(req.Storage, roleName)
	if err != nil {
		return nil, err
	}

	// Create a new entry object if this is a CreateOperation
	if role == nil && req.Operation == logical.CreateOperation {
		roleID, err := uuid.GenerateUUID()
		if err != nil {
			return nil, fmt.Errorf("failed to create role_id: %s\n", err)
		}
		hmacKey, err := uuid.GenerateUUID()
		if err != nil {
			return nil, fmt.Errorf("failed to create role_id: %s\n", err)
		}
		role = &roleStorageEntry{
			RoleID:  roleID,
			HMACKey: hmacKey,
		}
	} else if role == nil {
		return nil, fmt.Errorf("Role entry not found when the requested operation is to update it")
	}

	if boundSecretIDRaw, ok := data.GetOk("bound_secret_id"); ok {
		role.BoundSecretID = boundSecretIDRaw.(bool)
	} else if req.Operation == logical.CreateOperation {
		role.BoundSecretID = data.Get("bound_secret_id").(bool)
	}

	if boundCIDRListRaw, ok := data.GetOk("bound_cidr_list"); ok {
		role.BoundCIDRList = strings.TrimSpace(boundCIDRListRaw.(string))
	} else if req.Operation == logical.CreateOperation {
		role.BoundCIDRList = data.Get("bound_cidr_list").(string)
	}
	if err = validateCIDRList(role.BoundCIDRList); err != nil {
		return logical.ErrorResponse(fmt.Sprintf("failed to validate CIDR blocks: %s", err)), nil
	}

	if policiesRaw, ok := data.GetOk("policies"); ok {
		role.Policies = policyutil.ParsePolicies(policiesRaw.(string))
	} else if req.Operation == logical.CreateOperation {
		role.Policies = policyutil.ParsePolicies(data.Get("policies").(string))
	}

	periodRaw, ok := data.GetOk("period")
	if ok {
		role.Period = time.Second * time.Duration(periodRaw.(int))
	} else if req.Operation == logical.CreateOperation {
		role.Period = time.Second * time.Duration(data.Get("period").(int))
	}
	if role.Period > b.System().MaxLeaseTTL() {
		return logical.ErrorResponse(fmt.Sprintf("'period' of '%s' is greater than the backend's maximum lease TTL of '%s'", role.Period.String(), b.System().MaxLeaseTTL().String())), nil
	}

	if secretIDNumUsesRaw, ok := data.GetOk("secret_id_num_uses"); ok {
		role.SecretIDNumUses = secretIDNumUsesRaw.(int)
	} else if req.Operation == logical.CreateOperation {
		role.SecretIDNumUses = data.Get("secret_id_num_uses").(int)
	}
	if role.SecretIDNumUses < 0 {
		return logical.ErrorResponse("secret_id_num_uses cannot be negative"), nil
	}

	if secretIDTTLRaw, ok := data.GetOk("secret_id_ttl"); ok {
		role.SecretIDTTL = time.Second * time.Duration(secretIDTTLRaw.(int))
	} else if req.Operation == logical.CreateOperation {
		role.SecretIDTTL = time.Second * time.Duration(data.Get("secret_id_ttl").(int))
	}

	if tokenTTLRaw, ok := data.GetOk("token_ttl"); ok {
		role.TokenTTL = time.Second * time.Duration(tokenTTLRaw.(int))
	} else if req.Operation == logical.CreateOperation {
		role.TokenTTL = time.Second * time.Duration(data.Get("token_ttl").(int))
	}

	if tokenMaxTTLRaw, ok := data.GetOk("token_max_ttl"); ok {
		role.TokenMaxTTL = time.Second * time.Duration(tokenMaxTTLRaw.(int))
	} else if req.Operation == logical.CreateOperation {
		role.TokenMaxTTL = time.Second * time.Duration(data.Get("token_max_ttl").(int))
	}

	// Check that the TokenTTL value provided is less than the TokenMaxTTL.
	// Sanitizing the TTL and MaxTTL is not required now and can be performed
	// at credential issue time.
	if role.TokenMaxTTL > time.Duration(0) && role.TokenTTL > role.TokenMaxTTL {
		return logical.ErrorResponse("token_ttl should not be greater than token_max_ttl"), nil
	}

	var resp *logical.Response
	if role.TokenMaxTTL > b.System().MaxLeaseTTL() {
		resp = &logical.Response{}
		resp.AddWarning("token_max_ttl is greater than the backend mount's maximum TTL value; issued tokens' max TTL value will be truncated")
	}

	// Store the entry.
	return resp, b.setRoleEntry(req.Storage, roleName, role)
}

// pathRoleRead grabs a read lock and reads the options set on the Role from the storage
func (b *backend) pathRoleRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role_name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role_name"), nil
	}

	if role, err := b.roleEntry(req.Storage, strings.ToLower(roleName)); err != nil {
		return nil, err
	} else if role == nil {
		return nil, nil
	} else {
		// Convert the 'time.Duration' values to second.
		role.SecretIDTTL /= time.Second
		role.TokenTTL /= time.Second
		role.TokenMaxTTL /= time.Second
		role.Period /= time.Second

		// Create a map of data to be returned and remove sensitive information from it
		data := structs.New(role).Map()
		delete(data, "role_id")
		delete(data, "hmac_key")

		return &logical.Response{
			Data: data,
		}, nil
	}
}

// pathRoleDelete removes the Role from the storage
func (b *backend) pathRoleDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role_name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role_name"), nil
	}

	role, err := b.roleEntry(req.Storage, strings.ToLower(roleName))
	if err != nil {
		return nil, err
	}

	// Acquire the lock before deleting the secrets.
	b.roleLock.Lock()
	defer b.roleLock.Unlock()

	// Just before the role is deleted, remove all the SecretIDs issued as part of the role.
	if err = b.flushRoleSecrets(req.Storage, role.RoleID); err != nil {
		return nil, fmt.Errorf("failed to invalidate the secrets belonging to role '%s': %s", roleName, err)
	}

	// Delete the reverse mroleing from RoleID to the Role
	if err = b.roleIDEntryDelete(req.Storage, role.RoleID); err != nil {
		return nil, fmt.Errorf("failed to delete the mroleing from RoleID to role '%s': %s", roleName, err)
	}

	// After deleting the SecretIDs and the RoleID, delete the Role itself
	if err = req.Storage.Delete("role/" + strings.ToLower(roleName)); err != nil {
		return nil, err
	}

	return nil, nil
}

// Returns the properties of the SecretID
func (b *backend) pathRoleSecretIDAccessorRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role_name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role_name"), nil
	}

	secretIDAccessor := data.Get("secret_id_accessor").(string)
	if secretIDAccessor == "" {
		return logical.ErrorResponse("missing secret_id_accessor"), nil
	}

	// SecretID is indexed based on salted RoleID and HMACed SecretID.
	// Get the Role details to fetch the RoleID and accessor to get
	// the HMAC-ed SecretID.

	role, err := b.roleEntry(req.Storage, strings.ToLower(roleName))
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, fmt.Errorf("role %s does not exist", roleName)
	}

	accessorEntry, err := b.secretIDAccessorEntry(req.Storage, secretIDAccessor)
	if err != nil {
		return nil, err
	}
	if accessorEntry == nil {
		return nil, fmt.Errorf("failed to find accessor entry for secret_id_accessor:%s\n", secretIDAccessor)
	}

	entryIndex := fmt.Sprintf("secret_id/%s/%s", b.salt.SaltID(role.RoleID), accessorEntry.SecretIDHMAC)

	lock := b.secretIDLock(accessorEntry.SecretIDHMAC)
	lock.RLock()
	defer lock.RUnlock()

	result := secretIDStorageEntry{}
	if entry, err := req.Storage.Get(entryIndex); err != nil {
		return nil, err
	} else if entry == nil {
		return nil, nil
	} else if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	result.SecretIDTTL /= time.Second
	return &logical.Response{
		Data: structs.New(result).Map(),
	}, nil
}

func (b *backend) pathRoleSecretIDAccessorDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role_name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role_name"), nil
	}

	secretIDAccessor := data.Get("secret_id_accessor").(string)
	if secretIDAccessor == "" {
		return logical.ErrorResponse("missing secret_id_accessor"), nil
	}

	// SecretID is indexed based on salted RoleID and HMACed SecretID.
	// Get the Role details to fetch the RoleID and accessor to get
	// the HMAC-ed SecretID.

	role, err := b.roleEntry(req.Storage, strings.ToLower(roleName))
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, fmt.Errorf("role %s does not exist", roleName)
	}

	accessorEntry, err := b.secretIDAccessorEntry(req.Storage, secretIDAccessor)
	if err != nil {
		return nil, err
	}
	if accessorEntry == nil {
		return nil, fmt.Errorf("failed to find accessor entry for secret_id_accessor:%s\n", secretIDAccessor)
	}

	entryIndex := fmt.Sprintf("secret_id/%s/%s", b.salt.SaltID(role.RoleID), accessorEntry.SecretIDHMAC)
	accessorEntryIndex := "accessor/" + b.salt.SaltID(secretIDAccessor)

	lock := b.secretIDLock(accessorEntry.SecretIDHMAC)
	lock.Lock()
	defer lock.Unlock()

	// Delete the accessor of the SecretID first
	if err := req.Storage.Delete(accessorEntryIndex); err != nil {
		return nil, fmt.Errorf("failed to delete accessor storage entry: %s", err)
	}

	// Delete the storage entry that corresponds to the SecretID
	if err := req.Storage.Delete(entryIndex); err != nil {
		return nil, fmt.Errorf("failed to delete SecretID: %s", err)
	}

	return nil, nil
}

func (b *backend) pathRoleBoundCIDRListUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role_name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role_name"), nil
	}

	role, err := b.roleEntry(req.Storage, strings.ToLower(roleName))
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	if boundCIDRListRaw, ok := data.GetOk("bound_cidr_list"); ok {
		role.BoundCIDRList = strings.TrimSpace(boundCIDRListRaw.(string))
		if err = validateCIDRList(role.BoundCIDRList); err != nil {
			return logical.ErrorResponse(fmt.Sprintf("failed to validate CIDR blocks: %s", err)), nil
		}
		return nil, b.setRoleEntry(req.Storage, roleName, role)
	} else {
		return logical.ErrorResponse("missing bound_cidr_list"), nil
	}
}

func (b *backend) pathRoleBoundCIDRListRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role_name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role_name"), nil
	}

	if role, err := b.roleEntry(req.Storage, strings.ToLower(roleName)); err != nil {
		return nil, err
	} else if role == nil {
		return nil, nil
	} else {
		return &logical.Response{
			Data: map[string]interface{}{
				"bound_cidr_list": role.BoundCIDRList,
			},
		}, nil
	}
}

func (b *backend) pathRoleBoundCIDRListDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role_name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role_name"), nil
	}

	role, err := b.roleEntry(req.Storage, strings.ToLower(roleName))
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	// Deleting a field implies setting the value to it's default value.
	role.BoundCIDRList = data.GetDefaultOrZero("bound_cidr_list").(string)

	return nil, b.setRoleEntry(req.Storage, roleName, role)
}

func (b *backend) pathRoleBoundSecretIDUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role_name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role_name"), nil
	}

	role, err := b.roleEntry(req.Storage, strings.ToLower(roleName))
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	if boundSecretIDRaw, ok := data.GetOk("bound_secret_id"); ok {
		role.BoundSecretID = boundSecretIDRaw.(bool)
		return nil, b.setRoleEntry(req.Storage, roleName, role)
	} else {
		return logical.ErrorResponse("missing bound_secret_id"), nil
	}
}

func (b *backend) pathRoleBoundSecretIDRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role_name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role_name"), nil
	}

	if role, err := b.roleEntry(req.Storage, strings.ToLower(roleName)); err != nil {
		return nil, err
	} else if role == nil {
		return nil, nil
	} else {
		return &logical.Response{
			Data: map[string]interface{}{
				"bound_secret_id": role.BoundSecretID,
			},
		}, nil
	}
}

func (b *backend) pathRoleBoundSecretIDDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role_name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role_name"), nil
	}

	role, err := b.roleEntry(req.Storage, strings.ToLower(roleName))
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	// Deleting a field implies setting the value to it's default value.
	role.BoundSecretID = data.GetDefaultOrZero("bound_secret_id").(bool)

	return nil, b.setRoleEntry(req.Storage, roleName, role)
}

func (b *backend) pathRolePoliciesUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role_name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role_name"), nil
	}

	role, err := b.roleEntry(req.Storage, strings.ToLower(roleName))
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	if policiesRaw, ok := data.GetOk("policies"); ok {
		role.Policies = policyutil.ParsePolicies(policiesRaw.(string))
		return nil, b.setRoleEntry(req.Storage, roleName, role)
	} else {
		return logical.ErrorResponse("missing policies"), nil
	}
}

func (b *backend) pathRolePoliciesRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role_name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role_name"), nil
	}

	if role, err := b.roleEntry(req.Storage, strings.ToLower(roleName)); err != nil {
		return nil, err
	} else if role == nil {
		return nil, nil
	} else {
		return &logical.Response{
			Data: map[string]interface{}{
				"policies": role.Policies,
			},
		}, nil
	}
}

func (b *backend) pathRolePoliciesDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role_name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role_name"), nil
	}

	role, err := b.roleEntry(req.Storage, strings.ToLower(roleName))
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	role.Policies = policyutil.ParsePolicies(data.GetDefaultOrZero("policies").(string))

	return nil, b.setRoleEntry(req.Storage, roleName, role)
}

func (b *backend) pathRoleSecretIDNumUsesUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role_name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role_name"), nil
	}

	role, err := b.roleEntry(req.Storage, strings.ToLower(roleName))
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	if numUsesRaw, ok := data.GetOk("secret_id_num_uses"); ok {
		role.SecretIDNumUses = numUsesRaw.(int)
		if role.SecretIDNumUses < 0 {
			return logical.ErrorResponse("secret_id_num_uses cannot be negative"), nil
		}
		return nil, b.setRoleEntry(req.Storage, roleName, role)
	} else {
		return logical.ErrorResponse("missing secret_id_num_uses"), nil
	}
}

func (b *backend) pathRoleRoleIDRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role_name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role_name"), nil
	}

	if role, err := b.roleEntry(req.Storage, strings.ToLower(roleName)); err != nil {
		return nil, err
	} else if role == nil {
		return nil, nil
	} else {
		return &logical.Response{
			Data: map[string]interface{}{
				"role_id": role.RoleID,
			},
		}, nil
	}
}

func (b *backend) pathRoleSecretIDNumUsesRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role_name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role_name"), nil
	}

	if role, err := b.roleEntry(req.Storage, strings.ToLower(roleName)); err != nil {
		return nil, err
	} else if role == nil {
		return nil, nil
	} else {
		return &logical.Response{
			Data: map[string]interface{}{
				"secret_id_num_uses": role.SecretIDNumUses,
			},
		}, nil
	}
}

func (b *backend) pathRoleSecretIDNumUsesDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role_name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role_name"), nil
	}

	role, err := b.roleEntry(req.Storage, strings.ToLower(roleName))
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	role.SecretIDNumUses = data.GetDefaultOrZero("secret_id_num_uses").(int)

	return nil, b.setRoleEntry(req.Storage, roleName, role)
}

func (b *backend) pathRoleSecretIDTTLUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role_name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role_name"), nil
	}

	role, err := b.roleEntry(req.Storage, strings.ToLower(roleName))
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	if secretIDTTLRaw, ok := data.GetOk("secret_id_ttl"); ok {
		role.SecretIDTTL = time.Second * time.Duration(secretIDTTLRaw.(int))
		return nil, b.setRoleEntry(req.Storage, roleName, role)
	} else {
		return logical.ErrorResponse("missing secret_id_ttl"), nil
	}
}

func (b *backend) pathRoleSecretIDTTLRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role_name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role_name"), nil
	}

	if role, err := b.roleEntry(req.Storage, strings.ToLower(roleName)); err != nil {
		return nil, err
	} else if role == nil {
		return nil, nil
	} else {
		role.SecretIDTTL /= time.Second
		return &logical.Response{
			Data: map[string]interface{}{
				"secret_id_ttl": role.SecretIDTTL,
			},
		}, nil
	}
}

func (b *backend) pathRoleSecretIDTTLDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role_name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role_name"), nil
	}

	role, err := b.roleEntry(req.Storage, strings.ToLower(roleName))
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	role.SecretIDTTL = time.Second * time.Duration(data.GetDefaultOrZero("secret_id_ttl").(int))

	return nil, b.setRoleEntry(req.Storage, roleName, role)
}

func (b *backend) pathRolePeriodUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role_name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role_name"), nil
	}

	role, err := b.roleEntry(req.Storage, strings.ToLower(roleName))
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	if periodRaw, ok := data.GetOk("period"); ok {
		role.Period = time.Second * time.Duration(periodRaw.(int))
		if role.Period > b.System().MaxLeaseTTL() {
			return logical.ErrorResponse(fmt.Sprintf("'period' of '%s' is greater than the backend's maximum lease TTL of '%s'", role.Period.String(), b.System().MaxLeaseTTL().String())), nil
		}
		return nil, b.setRoleEntry(req.Storage, roleName, role)
	} else {
		return logical.ErrorResponse("missing period"), nil
	}
}

func (b *backend) pathRolePeriodRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role_name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role_name"), nil
	}

	if role, err := b.roleEntry(req.Storage, strings.ToLower(roleName)); err != nil {
		return nil, err
	} else if role == nil {
		return nil, nil
	} else {
		role.Period /= time.Second
		return &logical.Response{
			Data: map[string]interface{}{
				"period": role.Period,
			},
		}, nil
	}
}

func (b *backend) pathRolePeriodDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role_name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role_name"), nil
	}

	role, err := b.roleEntry(req.Storage, strings.ToLower(roleName))
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	role.Period = time.Second * time.Duration(data.GetDefaultOrZero("period").(int))

	return nil, b.setRoleEntry(req.Storage, roleName, role)
}

func (b *backend) pathRoleTokenTTLUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role_name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role_name"), nil
	}

	role, err := b.roleEntry(req.Storage, strings.ToLower(roleName))
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	if tokenTTLRaw, ok := data.GetOk("token_ttl"); ok {
		role.TokenTTL = time.Second * time.Duration(tokenTTLRaw.(int))
		if role.TokenMaxTTL > time.Duration(0) && role.TokenTTL > role.TokenMaxTTL {
			return logical.ErrorResponse("token_ttl should not be greater than token_max_ttl"), nil
		}
		return nil, b.setRoleEntry(req.Storage, roleName, role)
	} else {
		return logical.ErrorResponse("missing token_ttl"), nil
	}
}

func (b *backend) pathRoleTokenTTLRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role_name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role_name"), nil
	}

	if role, err := b.roleEntry(req.Storage, strings.ToLower(roleName)); err != nil {
		return nil, err
	} else if role == nil {
		return nil, nil
	} else {
		role.TokenTTL /= time.Second
		return &logical.Response{
			Data: map[string]interface{}{
				"token_ttl": role.TokenTTL,
			},
		}, nil
	}
}

func (b *backend) pathRoleTokenTTLDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role_name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role_name"), nil
	}

	role, err := b.roleEntry(req.Storage, strings.ToLower(roleName))
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	role.TokenTTL = time.Second * time.Duration(data.GetDefaultOrZero("token_ttl").(int))

	return nil, b.setRoleEntry(req.Storage, roleName, role)
}

func (b *backend) pathRoleTokenMaxTTLUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role_name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role_name"), nil
	}

	role, err := b.roleEntry(req.Storage, strings.ToLower(roleName))
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	if tokenMaxTTLRaw, ok := data.GetOk("token_max_ttl"); ok {
		role.TokenMaxTTL = time.Second * time.Duration(tokenMaxTTLRaw.(int))
		if role.TokenMaxTTL > time.Duration(0) && role.TokenTTL > role.TokenMaxTTL {
			return logical.ErrorResponse("token_max_ttl should be greater than or equal to token_ttl"), nil
		}
		return nil, b.setRoleEntry(req.Storage, roleName, role)
	} else {
		return logical.ErrorResponse("missing token_max_ttl"), nil
	}
}

func (b *backend) pathRoleTokenMaxTTLRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role_name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role_name"), nil
	}

	if role, err := b.roleEntry(req.Storage, strings.ToLower(roleName)); err != nil {
		return nil, err
	} else if role == nil {
		return nil, nil
	} else {
		role.TokenMaxTTL /= time.Second
		return &logical.Response{
			Data: map[string]interface{}{
				"token_max_ttl": role.TokenMaxTTL,
			},
		}, nil
	}
}

func (b *backend) pathRoleTokenMaxTTLDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role_name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role_name"), nil
	}

	role, err := b.roleEntry(req.Storage, strings.ToLower(roleName))
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	role.TokenMaxTTL = time.Second * time.Duration(data.GetDefaultOrZero("token_max_ttl").(int))

	return nil, b.setRoleEntry(req.Storage, roleName, role)
}

func (b *backend) pathRoleSecretIDUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	secretID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate SecretID:%s", err)
	}
	return b.handleRoleSecretIDCommon(req, data, secretID)
}

func (b *backend) pathRoleCustomSecretIDUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.handleRoleSecretIDCommon(req, data, data.Get("secret_id").(string))
}

func (b *backend) handleRoleSecretIDCommon(req *logical.Request, data *framework.FieldData, secretID string) (*logical.Response, error) {
	roleName := data.Get("role_name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role_name"), nil
	}

	if secretID == "" {
		return logical.ErrorResponse("missing secret_id"), nil
	}

	role, err := b.roleEntry(req.Storage, strings.ToLower(roleName))
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("role %s does not exist", roleName)), nil
	}

	// Currently, only one type of bound is implemented.
	// Ensure that it is enabled.
	if !role.BoundSecretID {
		return logical.ErrorResponse("bound_secret_id is not set on the role"), nil
	}

	secretIDStorage := &secretIDStorageEntry{
		SecretIDNumUses: role.SecretIDNumUses,
		SecretIDTTL:     role.SecretIDTTL,
	}

	metadata := data.Get("metadata").(string)
	if metadata != "" {
		json.Unmarshal([]byte(metadata), &secretIDStorage.Metadata)
		for key, value := range secretIDStorage.Metadata {
			if key != "" && value == "" {
				return logical.ErrorResponse(fmt.Sprintf("metadata should only contain <key,value> inputs as JSON; invalid value for key '%s'", key)), nil
			}
		}
	}

	if secretIDStorage, err = b.registerSecretIDEntry(req.Storage, role.RoleID, secretID, role.HMACKey, secretIDStorage); err != nil {
		return nil, fmt.Errorf("failed to store SecretID: %s", err)
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"secret_id":          secretID,
			"secret_id_accessor": secretIDStorage.SecretIDAccessor,
		},
	}, nil
}

// Checks if all the CIDR blocks in the comma separated list are valid by parsing it.
func validateCIDRList(cidrList string) error {
	if cidrList == "" {
		return nil
	}

	cidrBlocks := strings.Split(cidrList, ",")
	for _, block := range cidrBlocks {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(block)); err != nil {
			return err
		}
	}
	return nil
}

var roleHelp = map[string][2]string{
	"role-list": {
		"Lists all the Roles registered with the backend.",
		"The list will contain the names of the Roles.",
	},
	"role": {
		"Register an Role with the backend.",
		`An Role can represent a service, a machine or anything that can be IDed.
The set of policies on the Role defines access to the Role, meaning, any
Vault token with a policy set that is a superset of the policies on the
Role registered here will have access to the Role. If a SecretID is desired
to be generated against only this specific Role, it can be done via
'role/<role_name>/secret-id' and 'role/<role_name>/custom-secret-id' endpoints.
The properties of the SecretID created against the Role and the properties
of the token issued with the SecretID generated againt the Role, can be
configured using the parameters of this endpoint.`,
	},
	"role-bound-secret-id": {
		"Impose secret_id to be presented during login using this Role.",
		`By setting this to 'true', during login the parameter 'secret_id' becomes a mandatory argument.
The value of 'secret_id' can be retrieved using 'role/<role_name>/secret-id' endpoint.`,
	},
	"role-bound-cidr-list": {
		`Comma separated list of CIDR blocks, if set, specifies blocks of IP
addresses which can perform the login operation`,
		`During login, the IP address of the client will be checked to see if it
belongs to the CIDR blocks specified. If CIDR blocks were set and if the
IP is not encompassed by it, login fails`,
	},
	"role-policies": {
		"Policies of the Role.",
		`A comma-delimited set of Vault policies that defines access to the Role.
All the Vault tokens with policies that encompass the policy set
defined on the Role, can access the Role.`,
	},
	"role-num-uses": {
		"Use limit of the SecretID generated against the Role.",
		`If the SecretIDs are generated/assigned against the Role using the
'role/<role_name>/secret-id' or 'role/<role_name>/custom-secret-id' endpoints,
then the number of times that SecretID can access the Role is defined by
this option.`,
	},
	"role-secret-id-ttl": {
		`Duration in seconds, representing the lifetime of the SecretIDs
that are generated against the Role using 'role/<role_name>/secret-id' or
'role/<role_name>/custom-secret-id' endpoints.`,
		``,
	},
	"role-secret-id-accessor": {
		"Read or delete a issued secret_id",
		`This is particularly useful to clean-up the non-expiring 'secret_id's.
The list operation on the 'role/<role_name>/secret-id' endpoint will return
the 'secret_id_accessor's. This endpoint can be used to read the properties
of the secret. If the 'secret_id_num_uses' field in the response is 0, it
represents a non-expiring 'secret_id'. This endpoint can be invoked to delete
the 'secret_id's as well.`,
	},
	"role-token-ttl": {
		`Duration in seconds, the lifetime of the token issued by using the SecretID that
is generated against this Role, before which the token needs to be renewed.`,
		`If SecretIDs are generated against the Role, using 'role/<role_name>/secret-id' or the
'role/<role_name>/custom-secret-id' endpoints, and if those SecretIDs are used
to perform the login operation, then the value of 'token-ttl' defines the
lifetime of the token issued, before which the token needs to be renewed.`,
	},
	"role-token-max-ttl": {
		`Duration in seconds, the maximum lifetime of the tokens issued by using
the SecretIDs that were generated against this Role, after which the
tokens are not allowed to be renewed.`,
		`If SecretIDs are generated against the Role using 'role/<role_name>/secret-id'
or the 'role/<role_name>/custom-secret-id' endpoints, and if those SecretIDs
are used to perform the login operation, then the value of 'token-max-ttl'
defines the maximum lifetime of the tokens issued, after which the tokens
cannot be renewed. A reauthentication is required after this duration.
This value will be croleed by the backend mount's maximum TTL value.`,
	},
	"role-id": {
		"Returns the 'role_id' of the Role.",
		`If login is performed from an Role, then its 'role_id' should be presented
as a credential during the login. This 'role_id' can be retrieved using
this endpoint.`,
	},
	"role-secret-id": {
		"Generate a SecretID against this Role.",
		`The SecretID generated using this endpoint will be scoped to access
just this Role and none else. The properties of this SecretID will be
based on the options set on the Role. It will expire after a period
defined by the 'secret_id_ttl' option on the Role and/or the backend
mount's maximum TTL value.`,
	},
	"role-custom-secret-id": {
		"Assign a SecretID of choice against the Role.",
		`This option is not recommended unless there is a specific need
to do so. This will assign a client supplied SecretID to be used to access
the Role. This SecretID will behave similarly to the SecretIDs generated by
the backend. The properties of this SecretID will be based on the options
set on the Role. It will expire after a period defined by the 'secret_id_ttl'
option on the Role and/or the backend mount's maximum TTL value.`,
	},
	"role-period": {
		"Updates the value of 'period' on the Role",
		`If set,  indicates that the token generated using this Role
should never expire. The token should be renewed within the
duration specified by this value. The renewal duration will
be fixed. If the Period in the Role is modified, the token
will pick up the new value during its next renewal.`,
	},
}
