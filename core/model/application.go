package model

import (
	"fmt"
	"time"

	"github.com/rokmetro/logging-library/logutils"
)

const (
	//TypeApplication ...
	TypeApplication logutils.MessageDataType = "application"
	//TypeOrganization ...
	TypeOrganization logutils.MessageDataType = "organization"
	//TypeApplicationOrganization ...
	TypeApplicationOrganization logutils.MessageDataType = "application organization"
	//TypeApplicationType ...
	TypeApplicationType logutils.MessageDataType = "application type"
	//TypeApplicationUserRelations ...
	TypeApplicationUserRelations logutils.MessageDataType = "app user relations"
)

//ApplicationPermission represents application permission entity
type ApplicationPermission struct {
	ID   string
	Name string

	Application Application

	DateCreated time.Time
	DateUpdated *time.Time
}

func (c ApplicationPermission) String() string {
	return fmt.Sprintf("[ID:%s\nName:%s\nApplication:%s]", c.ID, c.Name, c.Application.Name)
}

//ApplicationRole represents application role entity. It is a collection of permissions
type ApplicationRole struct {
	ID          string
	Name        string
	Description string

	Permissions []ApplicationPermission

	Application Application

	DateCreated time.Time
	DateUpdated *time.Time
}

func (c ApplicationRole) String() string {
	return fmt.Sprintf("[ID:%s\tName:%s\tPermissions:%s\tApplication:%s]", c.ID, c.Name, c.Permissions, c.Application.Name)
}

//ApplicationGroup represents application group entity. It is a collection of users
type ApplicationGroup struct {
	ID   string
	Name string

	Permissions []ApplicationPermission
	Roles       []ApplicationRole

	Application Application

	DateCreated time.Time
	DateUpdated *time.Time
}

func (cg ApplicationGroup) String() string {
	return fmt.Sprintf("[ID:%s\nName:%s\nApplication:%s]", cg.ID, cg.Name, cg.Application.Name)
}

//Application represents users application entity - safer community, uuic, etc
type Application struct {
	ID   string
	Name string //safer community, uuic, etc

	MultiTenant string //safer community is multi-tenant

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
	Application  Application
	Organization Organization

	IdentityProvidersSettings []IdentityProviderSetting

	SupportedAuthTypes []AuthTypesSupport //supported auth types for this organization in this application

	DateCreated time.Time
	DateUpdated *time.Time
}

//FindIdentityProviderSetting finds the identity provider setting for the application
func (a ApplicationOrganization) FindIdentityProviderSetting(identityProviderID string) *IdentityProviderSetting {
	for _, idPrSetting := range a.IdentityProvidersSettings {
		if idPrSetting.IdentityProvider.ID == identityProviderID {
			return &idPrSetting
		}
	}
	return nil
}

//IsAuthTypeSupported checks if an auth type is supported
func (ao ApplicationOrganization) IsAuthTypeSupported(authType AuthType) bool {
	//TODO
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
	IdentityProvider IdentityProvider

	UserIdentifierField string

	FirstNameField  string
	MiddleNameField string
	LastNameField   string
	EmailField      string
	GroupsField     string

	UserSpecificFields []string

	Groups []struct {
		IdentityProviderGroup string
		AppGroupID            string
	}
}

//ApplicationType represents users application type entity - safer community android, safer community ios, safer community web, uuic android etc
type ApplicationType struct {
	ID         string   `bson:"id"`
	Identifier string   `bson:"identifier"` //edu.illinois.rokwire etc
	Name       string   `bson:"name"`       //safer community android, safer community ios, safer community web, uuic android etc
	Versions   []string `bson:"versions"`   //1.1.0, 1.2.0 etc

	Application Application `bson:"-"`
}

//AuthTypesSupport represents supported auth types for an organization in an application type with configs/params
type AuthTypesSupport struct {
	AppType      ApplicationType
	Organization Organization

	SupportedAuthTypes []struct {
		AuthType AuthType
		Params   map[string]interface{}
	}
}

//TODO - Accounts
//ApplicationUserRelations represents external relations between the application users in an organization
// For example in Safer Illinois application:
// - families takes discount for covid tests.
// - couples gets discount for the taxes.
// For other applications:
// - relatives are hosted in the same building etc.
type ApplicationUserRelations struct {
	ID   string
	Type string //family, couple, relatives, brothers/sisters, external roommate when there is no provided place by the university for example

	Organization Organization

	Manager ApplicationUser
	Members []ApplicationUser
}
