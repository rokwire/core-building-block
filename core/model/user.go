package model

import (
	"core-building-block/utils"
	"time"

	"github.com/rokmetro/logging-library/logutils"
)

const (
	//TypeAccount account type
	TypeAccount logutils.MessageDataType = "account"
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

	Permissions []ApplicationPermission
	Roles       []ApplicationRole
	Groups      []ApplicationGroup

	AuthTypes []AccountAuthType

	Profile Profile //one account has one profile, one profile can be shared between many accounts

	Devices []Device

	DateCreated time.Time
	DateUpdated *time.Time
}

//AccountAuthType represents account auth type
type AccountAuthType struct {
	ID string

	AuthType AuthType //one of the supported auth type
	Account  Account

	Identifier string
	Params     interface{}

	Credential *Credential //this can be nil as the external auth types authenticates the users outside the system

	Active    bool
	Active2FA bool

	DateCreated time.Time
	DateUpdated *time.Time
}

//Credential represents a credential for account auth type/s
type Credential struct {
	ID string

	AccountsAuthTypes []AccountAuthType //one credential can be used for more than one account auth type

	Value interface{} //credential value

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

	Accounts []Account //the users can share profiles between their applications accounts for some applications

	DateCreated time.Time
	DateUpdated *time.Time
}

//Device represents user devices entity.
type Device struct {
	ID   string
	Type string //mobile, web, desktop, other

	//TODO - other fields when they are clear
	OS         string //?
	MacAddress string //?
	///

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
