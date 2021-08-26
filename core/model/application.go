package model

import (
	"fmt"
	"time"

	"github.com/rokmetro/logging-library/logutils"
)

const (
	//TypeApplication ...
	TypeApplication logutils.MessageDataType = "application"
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
	ID   string `bson:"_id"`
	Name string `bson:"name"` //safer community, uuic, etc

	//if true the service will support own users for this app otherwise the user will decide if to create own user or to use the ecosystem one(shared)
	RequiresOwnUsers bool `bson:"requires_own_users"`

	//one of: none, single, multi
	//none - the application is not related with any organization
	//single - the application is for single organization - UIUC application, Safer Illinois application etc
	//multi - the application is for many organizations - Safer community application etc
	OrgRelType string `bson:"org_rel_type"`

	//identity providers groups mapping - group to group mapping
	IdentityProvidersGroups []ApplicationIdentityProviderGroups `bson:"identity_providers_groups"`

	Types []ApplicationType `bson:"types"`

	Organizations []Organization `bson:"-"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

//ApplicationIdentityProviderGroups maps an identity provider groups to application groups
//	For example:
//  	for the UIUC application the Illinois group "urn:mace:uiuc.edu:urbana:authman:app-rokwire-service-policy-rokwire groups access" is mapped to an application group called "groups access"
//  	for the Safer Illinois application the Illinois group "urn:mace:uiuc.edu:urbana:authman:app-rokwire-service-policy-rokwire health test verify" is mapped to an application group called "tests verifiers"
type ApplicationIdentityProviderGroups struct {
	IdentityProviderID string `bson:"identity_provider_id"`
	Groups             []struct {
		IdentityProviderGroup string `bson:"identity_provider_group"`
		AppGroupID            string `bson:"app_group_id"`
	} `bson:"groups"`
}

//ApplicationType represents users application type entity - safer community android, safer community ios, safer community web, uuic android etc
type ApplicationType struct {
	ID         string   `bson:"id"`
	Identifier string   `bson:"identifier"` //edu.illinois.rokwire etc
	Name       string   `bson:"name"`       //safer community android, safer community ios, safer community web, uuic android etc
	Versions   []string `bson:"versions"`   //1.1.0, 1.2.0 etc

	SupportedAuthTypes []ApplicationTypeAuthType `bson:"supported_auth_types"` //supported auth types for this application type
}

//ApplicationTypeAuthType represents supported auth type for application with configs/params
type ApplicationTypeAuthType struct {
	AuthTypeID string                 `bson:"auth_type_id"`
	Params     map[string]interface{} `bson:"params"`
}

//ApplicationUserRelations represents external relations between the application users
// For example in Safer Illinois application:
// - families takes discount for covid tests.
// - couples gets discount for the taxes.
// For other applications:
// - relatives are hosted in the same building etc.
type ApplicationUserRelations struct {
	ID   string
	Type string //family, couple, relatives, brothers/sisters, external roommate when there is no provided place by the university for example

	//TODO Add when applications users are done
	//Manager OrganizationMembership
	//Members []OrganizationMembership
}

func (cur ApplicationUserRelations) String() string {
	return "TODO"
	//return fmt.Sprintf("[ID:%s\n\tType:%s\n\tRelationManager:%s\n\tMembers:%s\n\t]",
	//	cur.ID, cur.Type, cur.Manager, cur.Members)
}
