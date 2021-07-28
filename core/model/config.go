package model

import (
	"fmt"

	log "github.com/rokmetro/logging-library/loglib"
)

const (
	//TypeGlobalConfig ...
	TypeGlobalConfig log.LogData = "global config"
	//TypeOrganizationConfig ...
	TypeOrganizationConfig log.LogData = "org config"
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
}

func (cc OrganizationConfig) String() string {
	return fmt.Sprintf("[ID:%s\tSetting:%s\tDomains:%s\tCustom:%s]", cc.ID, cc.Setting, cc.Domains, cc.Custom)
}
