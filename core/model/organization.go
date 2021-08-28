package model

import (
	"fmt"
	"time"

	"github.com/rokmetro/logging-library/logutils"
)

const (
	//TypeOrganization ...
	TypeOrganization logutils.MessageDataType = "organization"
	//TypeOrganizationMembership ...
	TypeOrganizationMembership logutils.MessageDataType = "org membership"
)

//Organization represents organization entity
type Organization struct {
	ID   string
	Name string
	Type string //micro small medium large - based on the users count

	Config OrganizationConfig

	Applications []Application

	DateCreated time.Time
	DateUpdated *time.Time
}

func (c Organization) String() string {
	return fmt.Sprintf("[ID:%s\tName:%s\tType:%s\tConfig:%s]", c.ID, c.Name, c.Type, c.Config)
}

//OrganizationMembership represents organization membership entity
type OrganizationMembership struct {
	ID string

	User         User
	Organization Organization

	DateCreated time.Time
	DateUpdated *time.Time
}

func (cm OrganizationMembership) String() string {
	return fmt.Sprintf("[ID:%s\n\tUser:%s\n\tOrganization:%s\n\t]",
		cm.ID, cm.User, cm.Organization)
}
