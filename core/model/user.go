package model

import "fmt"

//User represents user entity
type User struct {
	ID string

	Account UserAccount
	Profile UserProfile

	Permissions []GlobalPermission
	Roles       []GlobalRole
	Groups      []GlobalGroup

	OrganizationsMemberships []OrganizationMembership
}

func (u User) String() string {
	return fmt.Sprintf("[ID:%s\tAccount:%s\tProfile:%s\tPermissions:%s\tRoles:%s\tGroups:%s\tOrganizationsMemberships:%s]",
		u.ID, u.Account, u.Profile, u.Permissions, u.Roles, u.Groups, u.OrganizationsMemberships)
}

//UserAccount represents user account entity. The user account is the user himself or herself.
type UserAccount struct {
	ID       string
	Email    string
	Phone    string //??
	Number   string
	Username string
	//TODO other?
	//has 2FA ???
}

func (ua UserAccount) String() string {
	return fmt.Sprintf("[ID:%s\tEmail:%s\tPhone:%s\tNumber:%s\tUsername:%s]",
		ua.ID, ua.Email, ua.Phone, ua.Number, ua.Username)
}

//UserProfile represents user profile entity. The user profile is an information about the user.
type UserProfile struct {
	ID        string
	PhotoURL  string
	FirstName string
	LastName  string
}

func (up UserProfile) String() string {
	return fmt.Sprintf("[ID:%s\tPhotoURL:%s\tFirstName:%s\tLastName:%s]",
		up.ID, up.PhotoURL, up.FirstName, up.LastName)
}

//GlobalGroup represents global group entity. It is a collection of users
type GlobalGroup struct {
	ID   string
	Name string
}

//GlobalPermission represents global permission entity
type GlobalPermission struct {
	ID   string
	Name string
}

func (c GlobalPermission) String() string {
	return fmt.Sprintf("[ID:%s\tName:%s]", c.ID, c.Name)
}

//GlobalRole represents global role entity. It is a collection of permissions
type GlobalRole struct {
	ID   string
	Name string

	Permissions []GlobalPermission
}

func (c GlobalRole) String() string {
	return fmt.Sprintf("[ID:%s\tName:%s\tPermissions:%s]", c.ID, c.Name, c.Permissions)
}

//OrganizationGroup represents organization group entity. It is a collection of users
type OrganizationGroup struct {
	ID   string
	Name string

	Organization Organization
}

func (cg OrganizationGroup) String() string {
	return fmt.Sprintf("[ID:%s\tName:%s\tOrganization:%s]", cg.ID, cg.Name, cg.Organization)
}

//OrganizationPermission represents organization permission entity
type OrganizationPermission struct {
	ID   string
	Name string

	Organization Organization
}

func (c OrganizationPermission) String() string {
	return fmt.Sprintf("[ID:%s\tName:%s\tOrganization:%s]", c.ID, c.Name, c.Organization)
}

//OrganizationRole represents organization role entity. It is a collection of permissions
type OrganizationRole struct {
	ID   string
	Name string

	Permissions []OrganizationPermission

	Organization Organization
}

func (c OrganizationRole) String() string {
	return fmt.Sprintf("[ID:%s\tName:%s\tPermissions:%s\tOrganization:%s]", c.ID, c.Name, c.Permissions, c.Organization)
}
