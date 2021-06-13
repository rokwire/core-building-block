package model

import (
	"bytes"
	"fmt"
)

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

	var memberships bytes.Buffer
	memberships.WriteString("")

	if len(u.OrganizationsMemberships) >= 0 {
		for _, c := range u.OrganizationsMemberships {
			memberships.WriteString(c.Organization.Name)
			memberships.WriteString("\t")
		}
	}

	return fmt.Sprintf("[ID:%s\n\tAccount:%s\n\tProfile:%s\n\tPermissions:%s\n\tRoles:%s\n\tGroups:%s\n\tOrganizationsMemberships:%s]",
		u.ID, u.Account, u.Profile, u.Permissions, u.Roles, u.Groups, memberships.String())
}

//UserAccount represents user account entity. The user account is the user himself or herself.
//we should require the user to give unique phone or unique email(or both) when registering.
//It is also a good practive internally the system to generate unique number and(or) unique username which are not changable.
//At some moment the user could be needed to change his phone or email so we need to rely on the number or on the username which cannot be changed.
type UserAccount struct {
	ID string

	Email string
	Phone string

	Username string

	//for Champaign org - basically this will be one or many of  - email, phone, number, username
	//for Illinois university org - this will be empty because this organization requires it own login
	LoginTypes []string

	//TODO
	//has 2FA ???
}

func (ua UserAccount) String() string {
	return fmt.Sprintf("[ID:%s\tEmail:%s\tPhone:%s\tUsername:%s]",
		ua.ID, ua.Email, ua.Phone, ua.Username)
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
	return fmt.Sprintf("[ID:%s\nName:%s\nOrganization:%s]", cg.ID, cg.Name, cg.Organization)
}

//OrganizationPermission represents organization permission entity
type OrganizationPermission struct {
	ID   string
	Name string

	Organization Organization
}

func (c OrganizationPermission) String() string {
	return fmt.Sprintf("[ID:%s\nName:%s\nOrganization:%s]", c.ID, c.Name, c.Organization)
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
