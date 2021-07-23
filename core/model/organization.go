package model

import (
	"fmt"

	log "github.com/rokmetro/logging-library/loglib"
)

const (
	TypeOrganization              log.LogData = "organization"
	TypeOrganizationMembership    log.LogData = "org membership"
	TypeOrganizationUserRelations log.LogData = "org user relations"
)

//TODO - Flat vs. hierarchical group management - not sure we need hierarchical, maybe no!?

//Organization represents organization entity
type Organization struct {
	ID               string
	Name             string
	Type             string //micro small medium large - based on the users count
	RequiresOwnLogin bool   //Illinois orgnization requires own login(oidc) but Champaign organization does not requires

	//what login type/s are supported for the organization. It will be empty for Champaign and "OIDC" for university of Illinois
	LoginTypes []string

	Config OrganizationConfig

	Applications []Application
}

func (c Organization) String() string {
	return fmt.Sprintf("[ID:%s\tName:%s\tType:%s\tConfig:%s]", c.ID, c.Name, c.Type, c.Config)
}

//OrganizationMembership represents organization membership entity
type OrganizationMembership struct {
	ID string

	User         User
	Organization Organization

	//the user can have specific user data for the different organizations
	//for Illinois university org - this will be populated by the illinois organization user data - shiboleth, illini cash, icard
	//for Champaign org - this will be empty or populated with data if there is
	OrgUserData map[string]interface{}

	Permissions []OrganizationPermission
	Roles       []OrganizationRole

	Groups []OrganizationGroup
}

func (cm OrganizationMembership) String() string {
	return fmt.Sprintf("[ID:%s\n\tUser:%s\n\tOrganization:%s\n\tUserData:%s\n\tPermissions:%s\n\tRoles:%s\n\tGroups:%s\n\t]",
		cm.ID, cm.User, cm.Organization, cm.OrgUserData, cm.Permissions, cm.Roles, cm.Groups)
}

//OrganizationUserRelations represents external relations between the organization users
// For example in university organization:
// - families takes discount for covid tests.
// - couples gets discount for the taxes.
// For other organization:
// - relatives are hosted in the same building etc.
type OrganizationUserRelations struct {
	ID      string
	Type    string //family, couple, relatives, brothers/sisters, external roommate when there is no provided place by the university for example
	Manager OrganizationMembership
	Members []OrganizationMembership
}

func (cur OrganizationUserRelations) String() string {
	return fmt.Sprintf("[ID:%s\n\tType:%s\n\tRelationManager:%s\n\tMembers:%s\n\t]",
		cur.ID, cur.Type, cur.Manager, cur.Members)
}

//Application represents users application entity - safer community, uuic, etc
type Application struct {
	ID       string
	Name     string   //safer community mobile, safer community web, uuic mobile, uuic web, uuic admin etc
	Versions []string //1.1.0, 1.2.0 etc

	Organizations []Organization
}
