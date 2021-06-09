package model

import "fmt"

//TODO - Flat vs. hierarchical group management - not sure we need hierarchical, maybe no!?

//Organization represents organization entity
type Organization struct {
	ID   string
	Name string
	Type string //micro small medium large - based on the users count

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
	return fmt.Sprintf("[ID:%s\tType:%s\tData:%s]", cu.ID, cu.Type, cu.Data)
}

//OrganizationMembership represents organization membership entity
type OrganizationMembership struct {
	ID string

	User              User
	Organization      Organization
	OrganizationUsers []OrganizationUser //some organizations have their own users - shibboleth, illini cash, icard etc

	Account *OrganizationUserAccount //the user can have different account data(login) from the global one and from the other organization
	Profile *OrganizationUserProfile //the user can have different profile data for the different organizations

	Permissions []OrganizationPermission
	Roles       []OrganizationRole
	Groups      []OrganizationGroup
}

func (cm OrganizationMembership) String() string {
	return fmt.Sprintf("[ID:%s\tUser:%s\tOrganization:%s\tOrganizationUsers:%s\tAccount:%s\tProfile:%s\tPermissions:%s\tRoles:%s\tGroups:%s\t]",
		cm.ID, cm.User, cm.Organization, cm.OrganizationUsers, cm.Account, cm.Profile, cm.Permissions, cm.Roles, cm.Groups)
}

//OrganizationUserAccount represents organization user account entity
type OrganizationUserAccount struct {
	ID       string
	Email    string
	Phone    string //??
	Number   string
	Username string
	//TODO other?
	//has 2FA ???
}

func (cua OrganizationUserAccount) String() string {
	return fmt.Sprintf("[ID:%s\tEmail:%s\tPhone:%s\tNumber:%s\tUsername:%s]",
		cua.ID, cua.Email, cua.Phone, cua.Number, cua.Username)
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
	Type    string //family, couple, relatives, brothers/sisters, external roommate when there is no provided by the university for example
	Manager OrganizationMembership
	Members []OrganizationMembership
}

func (cur OrganizationUserRelations) String() string {
	return fmt.Sprintf("[ID:%s\tType:%s\tRelationManager:%s\tMembers:%s]",
		cur.ID, cur.Type, cur.Manager, cur.Members)
}
