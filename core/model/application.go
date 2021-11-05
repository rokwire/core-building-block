package model

import (
	"fmt"
	"time"

	"github.com/rokwire/logging-library-go/logutils"
)

const (
	//TypeApplication ...
	TypeApplication logutils.MessageDataType = "application"
	//TypePermission ...
	TypePermission logutils.MessageDataType = "permission"
	//TypeAppOrgRole ...
	TypeAppOrgRole logutils.MessageDataType = "application organization role"
	//TypeAppOrgGroup ...
	TypeAppOrgGroup logutils.MessageDataType = "application organization group"
	//TypeOrganization ...
	TypeOrganization logutils.MessageDataType = "organization"
	//TypeApplicationOrganization ...
	TypeApplicationOrganization logutils.MessageDataType = "application organization"
	//TypeApplicationType ...
	TypeApplicationType logutils.MessageDataType = "application type"
	//TypeApplicationUserRelations ...
	TypeApplicationUserRelations logutils.MessageDataType = "app user relations"
	//TypeApplicationConfigs ...
	TypeApplicationConfigs logutils.MessageDataType = "app configs"
)

//Permission represents permission entity
type Permission struct {
	ID   string `bson:"_id"`
	Name string `bson:"name"`

	ServiceID string   `bson:"service_id"`
	Assigners []string `bson:"assigners"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

func (c Permission) String() string {
	return fmt.Sprintf("[ID:%s\nName:%s\nServiceID:%s]", c.ID, c.Name, c.ServiceID)
}

//AppOrgRole represents application organization role entity. It is a collection of permissions
type AppOrgRole struct {
	ID          string
	Name        string
	Description string

	System bool

	Permissions []Permission

	AppOrg ApplicationOrganization

	DateCreated time.Time
	DateUpdated *time.Time
}

func (c AppOrgRole) String() string {
	return fmt.Sprintf("[ID:%s\tName:%s\tPermissions:%s\tAppOrg:%s]", c.ID, c.Name, c.Permissions, c.AppOrg.ID)
}

//AppOrgGroup represents application organization group entity. It is a collection of users
type AppOrgGroup struct {
	ID   string
	Name string

	System bool

	Permissions []Permission
	Roles       []AppOrgRole

	AppOrg ApplicationOrganization

	DateCreated time.Time
	DateUpdated *time.Time
}

func (cg AppOrgGroup) String() string {
	return fmt.Sprintf("[ID:%s\nName:%s\nAppOrg:%s]", cg.ID, cg.Name, cg.AppOrg.ID)
}

//Application represents users application entity - safer community, uuic, etc
type Application struct {
	ID   string
	Name string //safer community, uuic, etc

	MultiTenant bool //safer community is multi-tenant

	//if true the service will always require the user to create profile for the application, otherwise he/she could use his/her already created profile from another platform application
	RequiresOwnUsers bool

	Types []ApplicationType

	Organizations []ApplicationOrganization

	DateCreated time.Time
	DateUpdated *time.Time
}

//FindApplicationType finds app type for identifier
func (a Application) FindApplicationType(identifier string) *ApplicationType {
	for _, appType := range a.Types {
		if appType.Identifier == identifier {
			return &appType
		}
	}
	return nil
}

//Organization represents organization entity
type Organization struct {
	ID   string
	Name string
	Type string //micro small medium large - based on the users count

	Config OrganizationConfig

	Applications []ApplicationOrganization

	DateCreated time.Time
	DateUpdated *time.Time
}

func (c Organization) String() string {
	return fmt.Sprintf("[ID:%s\tName:%s\tType:%s\tConfig:%s]", c.ID, c.Name, c.Type, c.Config)
}

//ApplicationOrganization represents application organization entity
type ApplicationOrganization struct {
	ID string

	Application  Application
	Organization Organization

	ServicesIDs []string //which services are used for this app/org

	IdentityProvidersSettings []IdentityProviderSetting

	SupportedAuthTypes []AuthTypesSupport //supported auth types for this organization in this application

	DateCreated time.Time
	DateUpdated *time.Time
}

//FindIdentityProviderSetting finds the identity provider setting for the application
func (ao ApplicationOrganization) FindIdentityProviderSetting(identityProviderID string) *IdentityProviderSetting {
	for _, idPrSetting := range ao.IdentityProvidersSettings {
		if idPrSetting.IdentityProviderID == identityProviderID {
			return &idPrSetting
		}
	}
	return nil
}

//IsAuthTypeSupported checks if an auth type is supported for application type
func (ao ApplicationOrganization) IsAuthTypeSupported(appType ApplicationType, authType AuthType) bool {
	for _, sat := range ao.SupportedAuthTypes {
		if sat.AppTypeID == appType.ID {
			for _, at := range sat.SupportedAuthTypes {
				if at.AuthTypeID == authType.ID {
					return true
				}
			}
		}
	}
	return false
}

//IdentityProviderSetting represents identity provider setting for an organization in an application
//  User specific fields
//  For example:
//		UIUC Application has uiucedu_uin specific field for Illinois identity provider
//
//  Groups mapping: maps an identity provider groups to application groups
//	For example:
//  	for the UIUC application the Illinois group "urn:mace:uiuc.edu:urbana:authman:app-rokwire-service-policy-rokwire groups access" is mapped to an application group called "groups access"
//  	for the Safer Illinois application the Illinois group "urn:mace:uiuc.edu:urbana:authman:app-rokwire-service-policy-rokwire health test verify" is mapped to an application group called "tests verifiers"
type IdentityProviderSetting struct {
	IdentityProviderID string `bson:"identity_provider_id"`

	UserIdentifierField string `bson:"user_identifier_field"`

	FirstNameField  string `bson:"first_name_field"`
	MiddleNameField string `bson:"middle_name_field"`
	LastNameField   string `bson:"last_name_field"`
	EmailField      string `bson:"email_field"`
	GroupsField     string `bson:"groups_field"`

	UserSpecificFields []string `bson:"user_specific_fields"`

	Groups []struct {
		IdentityProviderGroup string `bson:"identity_provider_group"`
		AppGroupID            string `bson:"app_group_id"`
	} `bson:"groups"`
}

//ApplicationType represents users application type entity - safer community android, safer community ios, safer community web, uuic android etc
type ApplicationType struct {
	ID         string
	Identifier string   //edu.illinois.rokwire etc
	Name       string   //safer community android, safer community ios, safer community web, uuic android etc
	Versions   []string //1.1.0, 1.2.0 etc

	Application Application
}

//AuthTypesSupport represents supported auth types for an organization in an application type with configs/params
type AuthTypesSupport struct {
	AppTypeID string `bson:"app_type_id"`

	SupportedAuthTypes []struct {
		AuthTypeID string                 `bson:"auth_type_id"`
		Params     map[string]interface{} `bson:"params"`
	} `bson:"supported_auth_types"`
}

//ApplicationConfigs represents mobile app configs
type ApplicationConfigs struct {
	ID               string                 `json:"id" bson:"_id"`
	AppID            string                 `json:"app_id" bson:"app_id"`
	MobileAppVersion string                 `json:"mobile_app_version" bson:"mobile_app_version"`
	Data             map[string]interface{} `json:"data" bson:"data"`

	DateCreated time.Time  `json:"date_created" bson:"date_created"`
	DateUpdated *time.Time `json:"date_updated" bson:"date_updated"`
}
