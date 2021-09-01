package model

import (
	"fmt"
	"time"

	"github.com/rokmetro/logging-library/logutils"
)

const (
	//TypeOrganization ...
	TypeOrganization logutils.MessageDataType = "organization"
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
