package model

import "fmt"

//GlobalConfig represents global config for the system
type GlobalConfig struct {
	Setting string
}

func (gc GlobalConfig) String() string {
	return fmt.Sprintf("[Setting:%s]", gc.Setting)
}

//CommunityConfig represents configuration for a community
type CommunityConfig struct {
	Name    string
	Setting string
	//???
	Domains []string //some communities have their own users so that we need to associate a user with a community

	Custom interface{}
}

func (cc CommunityConfig) String() string {
	return fmt.Sprintf("[Name:%s\tSetting:%s\tDomains:%s\tCustom:%s]", cc.Name, cc.Setting, cc.Domains, cc.Custom)
}
