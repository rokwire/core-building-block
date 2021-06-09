package model

import "fmt"

//TODO - Flat vs. hierarchical group management - not sure we need this, maybe no!?
//TODO - when

//Community represents community entity
type Community struct {
	ID   string
	Name string
	Type string //micro small medium large - based on the users count

	Config CommunityConfig
}

func (c Community) String() string {
	return fmt.Sprintf("[ID:%s\tName:%s\tType:%s\tConfig:%s]", c.ID, c.Name, c.Type, c.Config)
}

//CommunityUser represents a community user entity
type CommunityUser struct {
	ID   string
	Type string //shibboleth, illini cash, icard
	Data interface{}
}

func (cu CommunityUser) String() string {
	return fmt.Sprintf("[ID:%s\tType:%s\tData:%s]", cu.ID, cu.Type, cu.Data)
}

//CommunityMembership represents community membership entity
type CommunityMembership struct {
	ID string

	User           User
	Community      Community
	CommunityUsers []CommunityUser //some communities have their own users - shibboleth, illini cash, icard etc

	Account *CommunityUserAccount //the user can have different account data(login) from the global one and from the other communities
	Profile *CommunityUserProfile //the user can have different profile data for the different communities

	Permissions []CommunityPermission
	Roles       []CommunityRole
	Groups      []CommunityGroup
}

func (cm CommunityMembership) String() string {
	return fmt.Sprintf("[ID:%s\tUser:%s\tCommunity:%s\tCommunityUsers:%s\tAccount:%s\tProfile:%s\tPermissions:%s\tRoles:%s\tGroups:%s\t]",
		cm.ID, cm.User, cm.Community, cm.CommunityUsers, cm.Account, cm.Profile, cm.Permissions, cm.Roles, cm.Groups)
}

//CommunityUserAccount represents community user account entity
type CommunityUserAccount struct {
	ID       string
	Email    string
	Phone    string //??
	Number   string
	Username string
	//TODO other?
	//has 2FA ???
}

func (cua CommunityUserAccount) String() string {
	return fmt.Sprintf("[ID:%s\tEmail:%s\tPhone:%s\tNumber:%s\tUsername:%s]",
		cua.ID, cua.Email, cua.Phone, cua.Number, cua.Username)
}

//CommunityUserProfile represents community user profile entity
type CommunityUserProfile struct {
	ID        string
	PhotoURL  string
	FirstName string
	LastName  string
}

func (cup CommunityUserProfile) String() string {
	return fmt.Sprintf("[ID:%s\tPhotoURL:%s\tFirstName:%s\tLastName:%s]",
		cup.ID, cup.PhotoURL, cup.FirstName, cup.LastName)
}

//CommunityUserRelations represents external relations between the community users
// For example in university community:
// - families takes discount for covid tests.
// - couples gets discount for the taxes.
// For hospital community:
// - relatives are hosted in the same building etc.
type CommunityUserRelations struct {
	ID      string
	Type    string //family, couple, relatives, brothers/sisters, external roommate when there is no provided by the university for example
	Manager CommunityMembership
	Members []CommunityMembership
}

func (cur CommunityUserRelations) String() string {
	return fmt.Sprintf("[ID:%s\tType:%s\tRelationManager:%s\tMembers:%s]",
		cur.ID, cur.Type, cur.Manager, cur.Members)
}
