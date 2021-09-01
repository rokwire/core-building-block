package model

import (
	"bytes"
	"core-building-block/utils"
	"fmt"
	"time"

	"github.com/rokmetro/logging-library/logutils"
)

const (
	//TypeUser user type
	TypeUser logutils.MessageDataType = "user"
)

//User represents user entity
type User struct {
	ID string

	//one item if the user is used only for one application or many items if the user is shared between many applications
	ApplicationsAccounts []ApplicationUserAccount
	//one item if the user is used only for one application or many items if the user is shared between many applications
	ApplicationsUsers []ApplicationUser

	Profile UserProfile

	OrganizationsMemberships []OrganizationMembership

	Devices []Device

	DateCreated time.Time
	DateUpdated *time.Time
}

func (u User) FindUserAuthType(appID string, authTypeID string) *UserAuthType {
	for _, appUserAccount := range u.ApplicationsAccounts {
		if appUserAccount.AppID == appID {
			for _, userAuthType := range appUserAccount.AuthTypes {
				if userAuthType.AuthTypeID == authTypeID {
					return &userAuthType
				}
			}
		}
	}
	return nil
}

func (u User) String() string {

	var memberships bytes.Buffer
	memberships.WriteString("")

	if len(u.OrganizationsMemberships) >= 0 {
		for _, c := range u.OrganizationsMemberships {
			memberships.WriteString(c.Organization.Name)
			memberships.WriteString("\t")
		}
	}

	return fmt.Sprintf("[ID:%s\n\tProfile:%s\n\tOrganizationsMemberships:%s]",
		u.ID, u.Profile, memberships.String())
}

//ApplicationUserAccount represents UserAccount for an application
//	The user account is the user himself or herself
//	What the person provides to the system so that to use it
type ApplicationUserAccount struct {
	ID string `bson:"id"`

	AppID string `bson:"app_id"`

	//all available auth types for the application
	AuthTypes []UserAuthType `bson:"auth_types"`

	Active2FA bool `bson:"active_2fa"`
}

//UserAuthType represents user auth type
// The сystem supports [n] auth types - username, email, phone, illlinois_oidc etc
// One application can support <= [n] auth types from the system ones(subset)
type UserAuthType struct {
	ID         string `bson:"id"`
	AuthTypeID string `bson:"auth_type_id"`
	Active     bool   `bson:"active"` //auth type can be activated/deactivated

	//{
	//	"identifier":"petaka" //username
	//}
	//or
	//{
	//	"identifier":"petyo@inabyte.com" //email
	//}
	//or
	//{
	//	"identifier":"+359000000000" //phone
	//}
	//or
	//
	//illinois_oidc
	//{
	//	"identifier": "pss",
	//	"user": {
	//		"identifier": "pss",
	//		"first_name": "Petyo",
	//		"middle_name": "Stoimenov",
	//		"last_name": "Stoyanov",
	//		"email": "pss@illinois.edu",
	//		"groups": ["urn:mace:uiuc.edu:urbana:authman:app-rokwire-service-policy-rokwire health media", "urn:mace:uiuc.edu:urbana:authman:app-rokwire-service-policy-rokwire admin configs", "urn:mace:uiuc.edu:urbana:authman:app-rokwire-service-policy-rokwire app config manager", "urn:mace:uiuc.edu:urbana:authman:app-rokwire-service-policy-rokwire shield", "urn:mace:uiuc.edu:urbana:authman:app-rokwire-service-policy-rokwire public health", "urn:mace:uiuc.edu:urbana:authman:app-rokwire-service-policy-rokwire events manager", "urn:mace:uiuc.edu:urbana:authman:app-rokwire-service-policy-rokwire groups admin", "urn:mace:uiuc.edu:urbana:authman:app-rokwire-service-policy-rokwire debug", "urn:mace:uiuc.edu:urbana:authman:app-rokwire-service-policy-rokwire transportation manager", "urn:mace:uiuc.edu:urbana:authman:app-rokwire-service-policy-rokwire health provider", "urn:mace:uiuc.edu:urbana:authman:app-rokwire-service-policy-rokwire health test verify", "urn:mace:uiuc.edu:urbana:authman:app-rokwire-service-policy-rokwire groups access", "urn:mace:uiuc.edu:urbana:authman:app-rokwire-service-policy-rokwire talent chooser manager", "urn:mace:uiuc.edu:urbana:authman:app-rokwire-service-policy-rokwire admin app"],
	//		"system_specific": {
	//			"uiucedu_uin": "678028578"
	//		}
	//	}
	//}
	Params map[string]interface{} `bson:"params"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

//UserProfile represents user profile entity. The user profile is an information about the user.
type UserProfile struct {
	ID        string `bson:"id"`
	PhotoURL  string `bson:"photo_url"`
	FirstName string `bson:"first_name"`
	LastName  string `bson:"last_name"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

func (up UserProfile) String() string {
	return fmt.Sprintf("[ID:%s\tPhotoURL:%s\tFirstName:%s\tLastName:%s]",
		up.ID, up.PhotoURL, up.FirstName, up.LastName)
}

//ApplicationUser represents application user entity
type ApplicationUser struct {
	ID string

	User        User
	Application Application

	Permissions []ApplicationPermission
	Roles       []ApplicationRole
	Groups      []ApplicationGroup

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
	Users []User

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
