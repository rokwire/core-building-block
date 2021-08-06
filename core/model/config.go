package model

import (
	"fmt"
	"time"

	"github.com/rokmetro/logging-library/logutils"
)

const (
	//TypeGlobalConfig ...
	TypeGlobalConfig logutils.MessageDataType = "global config"
	//TypeOrganizationConfig ...
	TypeOrganizationConfig logutils.MessageDataType = "org config"
)
const (
	//TypeGlobalPermission ...
	TypeGlobalPermission logutils.MessageDataType = "global permissions"
)

//GlobalConfig represents global config for the system
type GlobalConfig struct {
	Setting string
}

func (gc GlobalConfig) String() string {
	return fmt.Sprintf("[setting:%s]", gc.Setting)
}

//OrganizationConfig represents configuration for an organization
type OrganizationConfig struct {
	ID      string `bson:"id"`
	Setting string `bson:"setting"`
	//???
	Domains []string `bson:"domains"` //some organizations have their own users so that we need to associate a user with an organization

	Custom interface{} `bson:"custom"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

func (cc OrganizationConfig) String() string {
	return fmt.Sprintf("[ID:%s\tSetting:%s\tDomains:%s\tCustom:%s]", cc.ID, cc.Setting, cc.Domains, cc.Custom)
}
