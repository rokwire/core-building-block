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

	CommunitiesMemberships []CommunityMembership
}

func (u User) String() string {
	return fmt.Sprintf("[ID:%s\tAccount:%s\tProfile:%s\tPermissions:%s\tRoles:%s\tGroups:%s\tCommunitiesMemberships:%s]",
		u.ID, u.Account, u.Profile, u.Permissions, u.Roles, u.Groups, u.CommunitiesMemberships)
}

//UserAccount represents user account entity
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

//UserProfile represents user profile entity
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

//CommunityGroup represents community group entity. It is a collection of users
type CommunityGroup struct {
	ID   string
	Name string

	Community Community
}

func (cg CommunityGroup) String() string {
	return fmt.Sprintf("[ID:%s\tName:%s\tCommunity:%s]", cg.ID, cg.Name, cg.Community)
}

//CommunityPermission represents community permission entity
type CommunityPermission struct {
	ID   string
	Name string

	Community Community
}

func (c CommunityPermission) String() string {
	return fmt.Sprintf("[ID:%s\tName:%s\tCommunity:%s]", c.ID, c.Name, c.Community)
}

//CommunityRole represents community role entity. It is a collection of permissions
type CommunityRole struct {
	ID   string
	Name string

	Permissions []CommunityPermission

	Community Community
}

func (c CommunityRole) String() string {
	return fmt.Sprintf("[ID:%s\tName:%s\tPermissions:%s\tCommunity:%s]", c.ID, c.Name, c.Permissions, c.Community)
}
