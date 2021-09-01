package model

import (
	"bytes"
	"fmt"
	"time"

	"github.com/rokmetro/logging-library/logutils"
)

const (
	//TypeUser user type
	TypeUser logutils.MessageDataType = "user"
)

//User represents user entity
type User struct {
	ID string

	Account UserAccount
	Profile UserProfile

	Permissions []GlobalPermission
	Roles       []GlobalRole

	Groups []GlobalGroup

	OrganizationsMemberships []OrganizationMembership

	Devices []Device

	DateCreated time.Time
	DateUpdated *time.Time
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
	ID string `bson:"id"`

	Email string `bson:"email"`
	Phone string `bson:"phone"`

	Username string `bson:"username"`

	//for Champaign org - basically this will be one or many of  - email, phone, number, username
	//for Illinois university org - this will be empty because this organization requires it own login
	LoginTypes []string `bson:"login_types"`

	AllowLogin bool `bson:"allow_login"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`

	//TODO
	//has 2FA ???
}

func (ua UserAccount) String() string {
	return fmt.Sprintf("[ID:%s\tEmail:%s\tPhone:%s\tUsername:%s]",
		ua.ID, ua.Email, ua.Phone, ua.Username)
}

//UserProfile represents user profile entity. The user profile is an information about the user.
type UserProfile struct {
	ID        string `bson:"id"`
	PhotoURL  string `bson:"photo_url"`
	FirstName string `bson:"first_name"`
	LastName  string `bson:"last_name"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

func (up UserProfile) String() string {
	return fmt.Sprintf("[ID:%s\tPhotoURL:%s\tFirstName:%s\tLastName:%s]",
		up.ID, up.PhotoURL, up.FirstName, up.LastName)
}

//GlobalGroup represents global group entity. It is a collection of users
type GlobalGroup struct {
	ID   string `bson:"_id"`
	Name string `bson:"name"`

	Permissions []GlobalPermission `bson:"permissions"`
	Roles       []GlobalRole       `bson:"roles"`

	Users []User `bson:"-"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

//GlobalPermission represents global permission entity
type GlobalPermission struct {
	ID   string `bson:"_id"`
	Name string `bson:"name"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

func (c GlobalPermission) String() string {
	return fmt.Sprintf("[ID:%s\tName:%s]", c.ID, c.Name)
}

//GlobalRole represents global role entity. It is a collection of permissions
type GlobalRole struct {
	ID          string `bson:"_id"`
	Name        string `bson:"name"`
	Description string `bson:"description"`

	Permissions []GlobalPermission `bson:"permissions"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

func (c GlobalRole) String() string {
	return fmt.Sprintf("[ID:%s\tName:%s\tPermissions:%s]", c.ID, c.Name, c.Permissions)
}

//OrganizationGroup represents organization group entity. It is a collection of users
type OrganizationGroup struct {
	ID   string
	Name string

	Permissions []OrganizationPermission
	Roles       []OrganizationRole

	Organization Organization

	OrganizationsMemberships []OrganizationMembership

	DateUpdated *time.Time
}

func (cg OrganizationGroup) String() string {
	return fmt.Sprintf("[ID:%s\nName:%s\nOrganization:%s]", cg.ID, cg.Name, cg.Organization)
}

//OrganizationPermission represents organization permission entity
type OrganizationPermission struct {
	ID   string
	Name string

	Organization Organization

	DateCreated time.Time
	DateUpdated *time.Time
}

func (c OrganizationPermission) String() string {
	return fmt.Sprintf("[ID:%s\nName:%s\nOrganization:%s]", c.ID, c.Name, c.Organization)
}

//OrganizationRole represents organization role entity. It is a collection of permissions
type OrganizationRole struct {
	ID          string
	Name        string
	Description string

	Permissions []OrganizationPermission

	Organization Organization

	DateCreated time.Time
	DateUpdated *time.Time
}

func (c OrganizationRole) String() string {
	return fmt.Sprintf("[ID:%s\tName:%s\tPermissions:%s\tOrganization:%s]", c.ID, c.Name, c.Permissions, c.Organization)
}

//Device represents user devices entity.
type Device struct {
	ID   string
	Type string //mobile, web, desktop, other

	//TODO - other fields when they are clear
	OS         string //?
	MacAddress string //?
	///

	//sometime one device could be used by more than one users - someone sells his/her smartphone, using the same browser computer etc
	Users []User

	DateCreated time.Time
	DateUpdated *time.Time
}
