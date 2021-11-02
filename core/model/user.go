package model

import (
	"core-building-block/utils"
	"time"

	"github.com/rokwire/logging-library-go/logutils"
)

const (
	//TypeAccount account
	TypeAccount logutils.MessageDataType = "account"
	//TypeAccountPreferences account preferences
	TypeAccountPreferences logutils.MessageDataType = "account preferences"
	//TypeAccountAuthType account auth type
	TypeAccountAuthType logutils.MessageDataType = "account auth type"
	//TypeAccountPermissions account permissions
	TypeAccountPermissions logutils.MessageDataType = "account permissions"
	//TypeAccountRoles account roles
	TypeAccountRoles logutils.MessageDataType = "account roles"
	//TypeMFAType mfa type
	TypeMFAType logutils.MessageDataType = "mfa type"
	//TypeProfile profile
	TypeProfile logutils.MessageDataType = "profile"
	//TypeDevice device
	TypeDevice logutils.MessageDataType = "device"
)

//Account represents account entity
//	The account is the user himself or herself.
//	This is what the person provides to the system so that to use it.
//
//	Every account is for an organization within an application
type Account struct {
	ID string //this is ID for the account

	Application  Application
	Organization Organization

	Permissions []Permission
	Roles       []ApplicationRole
	Groups      []ApplicationGroup

	AuthTypes []AccountAuthType

	MFATypes      []MFAType
	RecoveryCodes []string

	Preferences map[string]interface{}
	Profile     Profile //one account has one profile, one profile can be shared between many accounts

	// Anonymous bool

	Devices []Device

	DateCreated time.Time
	DateUpdated *time.Time
}

//GetAccountAuthType finds account auth type
func (a Account) GetAccountAuthType(authTypeID string, identifier string) *AccountAuthType {
	var result AccountAuthType
	for _, aat := range a.AuthTypes {
		if aat.AuthType.ID == authTypeID && aat.Identifier == identifier {
			result = aat
		}
	}
	//assign account
	result.Account = a
	return &result
}

//GetPermissions returns all permissions granted to this account
func (a Account) GetPermissions() []Permission {
	permissionsMap := a.GetPermissionsMap()
	permissions := make([]Permission, len(permissionsMap))
	i := 0
	for _, permission := range permissionsMap {
		permissions[i] = permission
		i++
	}
	return permissions
}

//GetPermissionNames returns all names of permissions granted to this account
func (a Account) GetPermissionNames() []string {
	permissionsMap := a.GetPermissionsMap()
	permissions := make([]string, len(permissionsMap))
	i := 0
	for name := range permissionsMap {
		permissions[i] = name
		i++
	}
	return permissions
}

//GetPermissionsMap returns a map of all permissions granted to this account
func (a Account) GetPermissionsMap() map[string]Permission {
	permissionsMap := make(map[string]Permission, len(a.Permissions))
	for _, permission := range a.Permissions {
		permissionsMap[permission.Name] = permission
	}
	for _, role := range a.Roles {
		for _, permission := range role.Permissions {
			permissionsMap[permission.Name] = permission
		}
	}
	for _, group := range a.Groups {
		for _, permission := range group.Permissions {
			permissionsMap[permission.Name] = permission
		}
		for _, role := range group.Roles {
			for _, permission := range role.Permissions {
				permissionsMap[permission.Name] = permission
			}
		}
	}
	return permissionsMap
}

//GetVerifiedMFATypes returns a list of only verified MFA types for this account
func (a Account) GetVerifiedMFATypes() []MFAType {
	mfaTypes := make([]MFAType, 0)
	for _, mfa := range a.MFATypes {
		if mfa.Verified {
			mfaTypes = append(mfaTypes, mfa)
		}
	}
	return mfaTypes
}

//AccountAuthType represents account auth type
type AccountAuthType struct {
	ID string

	AuthType AuthType //one of the supported auth type
	Account  Account

	Identifier string
	Params     map[string]interface{}

	Credential *Credential //this can be nil as the external auth types authenticates the users outside the system

	Active bool

	DateCreated time.Time
	DateUpdated *time.Time
}

//Credential represents a credential for account auth type/s
type Credential struct {
	ID string

	AuthType          AuthType
	AccountsAuthTypes []AccountAuthType //one credential can be used for more than one account auth type
	Verified          bool
	Value             map[string]interface{} //credential value

	DateCreated time.Time
	DateUpdated *time.Time
}

//MFAType represents a MFA type used by an account
type MFAType struct {
	Type string

	Verified bool
	Params   map[string]interface{} //mfa type params

	DateCreated time.Time
	DateUpdated *time.Time
}

//Profile represents profile entity
//	The profile is an information about the user
//  What the person shares with the system/other users/
//	The person should be able to use the system even all profile fields are empty/it is just an information for the user/
type Profile struct {
	ID string

	PhotoURL  string
	FirstName string
	LastName  string
	Email     string
	Phone     string
	BirthYear int16
	Address   string
	ZipCode   string
	State     string
	Country   string

	Accounts []Account //the users can share profiles between their applications accounts for some applications

	DateCreated time.Time
	DateUpdated *time.Time
}

//Device represents user devices entity.
type Device struct {
	ID   string
	Type string //mobile, web, desktop, other
	OS   string

	//sometime one device could be used by more than one users - someone sells his/her smartphone, using the same browser computer etc
	Accounts []Account

	DateCreated time.Time
	DateUpdated *time.Time
}

//ExternalSystemUser represents external system user
type ExternalSystemUser struct {
	Identifier string `json:"identifier" bson:"identifier"` //this is the identifier used in our system to map the user

	//these are common fields which should be popuated by the external system
	FirstName  string   `json:"first_name" bson:"first_name"`
	MiddleName string   `json:"middle_name" bson:"middle_name"`
	LastName   string   `json:"last_name" bson:"last_name"`
	Email      string   `json:"email" bson:"email"`
	Groups     []string `json:"groups" bson:"groups"`

	//here are the system specific data for the user - uiucedu_uin etc
	SystemSpecific map[string]interface{} `json:"system_specific" bson:"system_specific"`
}

//Equals checks if two external system users are equals
func (esu ExternalSystemUser) Equals(other ExternalSystemUser) bool {
	if esu.Identifier != other.Identifier {
		return false
	}
	if esu.FirstName != other.FirstName {
		return false
	}
	if esu.MiddleName != other.MiddleName {
		return false
	}
	if esu.LastName != other.LastName {
		return false
	}
	if esu.Email != other.Email {
		return false
	}
	if !utils.DeepEqual(esu.Groups, other.Groups) {
		return false
	}
	if !utils.DeepEqual(esu.SystemSpecific, other.SystemSpecific) {
		return false
	}
	return true
}

//AccountRelations represents external relations between the application accounts in an organization
// For example in Safer Illinois application:
// - families takes discount for covid tests.
// - couples gets discount for the taxes.
// For other applications:
// - relatives are hosted in the same building etc.
type AccountRelations struct {
	ID   string
	Type string //family, couple, relatives, brothers/sisters, external roommate when there is no provided place by the university for example

	Manager Account
	Members []Account
}
