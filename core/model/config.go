package model

import "fmt"

//GlobalConfig represents global config for the system
type GlobalConfig struct {
	Setting string
}

func (gc GlobalConfig) String() string {
	return fmt.Sprintf("[Setting:%s]", gc.Setting)
}

//OrganizationConfig represents configuration for an organization
type OrganizationConfig struct {
	Name    string
	Setting string
	//???
	Domains []string //some organizations have their own users so that we need to associate a user with an organization

	Custom interface{}
}

func (cc OrganizationConfig) String() string {
	return fmt.Sprintf("[Name:%s\tSetting:%s\tDomains:%s\tCustom:%s]", cc.Name, cc.Setting, cc.Domains, cc.Custom)
}

type Configs struct {
	Name             string `json:"name" bson:"name"`
	NewsUpdatePeriod int    `json:"news_update_period" bson:"news_update_period"` //in minutes
}
