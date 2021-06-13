package model

import "fmt"

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
}

func (c Organization) String() string {
	return fmt.Sprintf("[ID:%s\tName:%s\tType:%s\tConfig:%s]", c.ID, c.Name, c.Type, c.Config)
}

//OrganizationUser represents an organization user entity
type OrganizationUser struct {
	ID   string
	Type string //shibboleth, illini cash, icard
	Data interface{}
}

func (cu OrganizationUser) String() string {
	return fmt.Sprintf("[ID:%s\n\tType:%s\n\tData:%s]", cu.ID, cu.Type, cu.Data)
}

//OrganizationMembership represents organization membership entity
type OrganizationMembership struct {
	ID string

	User              User
	Organization      Organization
	OrganizationUsers []OrganizationUser //some organizations have their own users - shibboleth, illini cash, icard etc

	//the user can have different org profile data for the different organizations
	//for Illinois university org - this will be populated by the illinois organization user
	//for Champaign org - this will be empty or populated with data if it requires to be different than the user profile
	OrgUserProfile *OrganizationUserProfile

	Permissions []OrganizationPermission
	Roles       []OrganizationRole
	Groups      []OrganizationGroup
}

func (cm OrganizationMembership) String() string {
	return fmt.Sprintf("[ID:%s\n\tUser:%s\n\tOrganization:%s\n\tOrganizationUsers:%s\n\tProfile:%s\n\tPermissions:%s\n\tRoles:%s\n\tGroups:%s\n\t]",
		cm.ID, cm.User, cm.Organization, cm.OrganizationUsers, cm.OrgUserProfile, cm.Permissions, cm.Roles, cm.Groups)
}

//OrganizationUserProfile represents organization user profile entity
type OrganizationUserProfile struct {
	ID        string
	PhotoURL  string
	FirstName string
	LastName  string
}

func (cup OrganizationUserProfile) String() string {
	return fmt.Sprintf("[ID:%s\tPhotoURL:%s\tFirstName:%s\tLastName:%s]",
		cup.ID, cup.PhotoURL, cup.FirstName, cup.LastName)
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
