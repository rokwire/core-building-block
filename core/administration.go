package core

import (
	"core-building-block/core/model"
	"fmt"
)

func (app *Application) admGetTest() string {
	return "Admin - test"
}

func (app *Application) admGetTestModel() string {
	//global config
	globalConfig := model.GlobalConfig{Setting: "setting_value"}

	//communities configs
	illinoisDomains := []string{"illinois.edu"}
	illinoisCommunityConfig := model.CommunityConfig{Name: "Illinois community config", Setting: "setting_value", Domains: illinoisDomains, Custom: "Illinois community custom config"}

	danceCommunityConfig := model.CommunityConfig{Name: "Dance community config", Setting: "setting_value", Domains: []string{}, Custom: "Dance community custom config"}

	//communities
	illinoisCommunity := model.Community{ID: "1", Name: "Illinois", Type: "large", Config: illinoisCommunityConfig}

	danceCommunity := model.Community{ID: "2", Name: "Dance", Type: "medium", Config: danceCommunityConfig}

	//global permissions and roles

	glRole1 := model.GlobalRole{ID: "1", Name: "super_admin", Permissions: nil} //super_admin has nil permissions as it has all
	glPermission1 := model.GlobalPermission{ID: "1", Name: "invite_community_admin"}
	glPermission2 := model.GlobalPermission{ID: "2", Name: "read_log"}
	glPermission3 := model.GlobalPermission{ID: "3", Name: "modify_config"}
	glRole2 := model.GlobalRole{ID: "2", Name: "lite_admin",
		Permissions: []model.GlobalPermission{glPermission1, glPermission2, glPermission3}}

	//Illinois permissions, roles and groups

	illinoisRole1 := model.CommunityRole{ID: "1", Name: "community_super_admin", Permissions: nil, Community: illinoisCommunity} //community_super_admin has nil permissions as it has all
	illinoisPermission1 := model.CommunityPermission{ID: "1", Name: "read_audit", Community: illinoisCommunity}
	illinoisPermission2 := model.CommunityPermission{ID: "2", Name: "read_manual_test", Community: illinoisCommunity}
	illinoisPermission3 := model.CommunityPermission{ID: "3", Name: "modify_manual_test", Community: illinoisCommunity}
	illinoisRole2 := model.CommunityRole{ID: "2", Name: "manual_tests_manager",
		Permissions: []model.CommunityPermission{illinoisPermission2, illinoisPermission3}, Community: illinoisCommunity}
	illinoisGroup1 := model.CommunityGroup{ID: "1", Name: "students", Community: illinoisCommunity}
	illinoisGroup2 := model.CommunityGroup{ID: "2", Name: "manual tests managers", Community: illinoisCommunity}

	//Dance permissions, roles and groups

	danceRole1 := model.CommunityRole{ID: "3", Name: "community_super_admin", Permissions: nil, Community: danceCommunity} //community_super_admin has nil permissions as it has all
	dancePermission1 := model.CommunityPermission{ID: "4", Name: "view_video", Community: danceCommunity}
	dancePermission2 := model.CommunityPermission{ID: "5", Name: "write_video", Community: danceCommunity}
	dancePermission3 := model.CommunityPermission{ID: "6", Name: "view_schedule", Community: danceCommunity}
	danceRole2 := model.CommunityRole{ID: "4", Name: "videos_manager",
		Permissions: []model.CommunityPermission{dancePermission1, dancePermission2}, Community: danceCommunity}
	danceGroup1 := model.CommunityGroup{ID: "3", Name: "videos managers", Community: danceCommunity}

	//users

	globalUser1Account := model.UserAccount{ID: "1", Email: "petyo.stoyanov@inabit.eu"}
	globalUser1Profile := model.UserProfile{ID: "1", FirstName: "Petyo", LastName: "Stoyanov"}
	globalUser1 := model.User{ID: "1", Account: globalUser1Account, Profile: globalUser1Profile,
		Permissions: nil, Roles: []model.GlobalRole{glRole1}, Groups: nil, CommunitiesMemberships: nil}

	globalUser2Account := model.UserAccount{ID: "2", Email: "pencho.penchev@inabit.eu"}
	globalUser2Profile := model.UserProfile{ID: "2", FirstName: "Pencho", LastName: "penchev"}
	globalUser2 := model.User{ID: "2", Account: globalUser2Account, Profile: globalUser2Profile,
		Permissions: nil, Roles: []model.GlobalRole{glRole2}, Groups: nil, CommunitiesMemberships: nil}

	illiniUser1Account := model.UserAccount{ID: "3", Email: "vivon@inabit.eu"}
	illiniUser1Profile := model.UserProfile{ID: "3", FirstName: "Vivon", LastName: "Vivonov"}
	illiniUser1 := model.User{ID: "3", Account: illiniUser1Account, Profile: illiniUser1Profile,
		Permissions: nil, Roles: nil, Groups: nil, CommunitiesMemberships: nil}
	illiniUser1Community := model.CommunityMembership{ID: "1", User: illiniUser1, Community: illinoisCommunity,
		CommunityUsers: nil, Account: nil, Profile: nil, Permissions: nil, Roles: []model.CommunityRole{illinoisRole1}, Groups: nil}
	illiniUser1.CommunitiesMemberships = []model.CommunityMembership{illiniUser1Community}

	illiniUser2Account := model.UserAccount{ID: "4", Email: "vivon2@inabit.eu"}
	illiniUser2Profile := model.UserProfile{ID: "4", FirstName: "Vivon2", LastName: "Vivonov2"}
	illiniUser2 := model.User{ID: "4", Account: illiniUser2Account, Profile: illiniUser2Profile,
		Permissions: nil, Roles: nil, Groups: nil, CommunitiesMemberships: nil}
	illiniUser2Community := model.CommunityMembership{ID: "2", User: illiniUser2, Community: illinoisCommunity,
		CommunityUsers: nil, Account: nil, Profile: nil,
		Permissions: []model.CommunityPermission{illinoisPermission1},
		Roles:       []model.CommunityRole{illinoisRole2},
		Groups:      []model.CommunityGroup{illinoisGroup1}}
	illiniUser2.CommunitiesMemberships = []model.CommunityMembership{illiniUser2Community}

	illiniUser3Account := model.UserAccount{ID: "5", Email: "vivon3@inabit.eu"}
	illiniUser3Profile := model.UserProfile{ID: "5", FirstName: "Vivon3", LastName: "Vivonov3"}
	illiniUser3 := model.User{ID: "5", Account: illiniUser3Account, Profile: illiniUser3Profile,
		Permissions: nil, Roles: nil, Groups: nil, CommunitiesMemberships: nil}
	illiniUser3Community := model.CommunityMembership{ID: "3", User: illiniUser3, Community: illinoisCommunity,
		CommunityUsers: nil, Account: nil, Profile: nil,
		Permissions: []model.CommunityPermission{illinoisPermission1},
		Roles:       []model.CommunityRole{illinoisRole2},
		Groups:      []model.CommunityGroup{illinoisGroup1}}
	illiniUser3.CommunitiesMemberships = []model.CommunityMembership{illiniUser3Community}

	illiniUsersRel := model.CommunityUserRelations{ID: "1", Type: "family",
		Manager: illiniUser2Community, Members: []model.CommunityMembership{illiniUser3Community}}

	danceUser1Account := model.UserAccount{ID: "6", Email: "cocun@inabit.eu"}
	danceUser1Profile := model.UserProfile{ID: "6", FirstName: "Cocun", LastName: "Cocunov"}
	danceUser1 := model.User{ID: "6", Account: danceUser1Account, Profile: danceUser1Profile,
		Permissions: nil, Roles: nil, Groups: nil, CommunitiesMemberships: nil}
	danceUser1Community := model.CommunityMembership{ID: "4", User: danceUser1, Community: danceCommunity,
		CommunityUsers: nil, Account: nil, Profile: nil, Permissions: nil, Roles: []model.CommunityRole{danceRole1}, Groups: nil}
	danceUser1.CommunitiesMemberships = []model.CommunityMembership{danceUser1Community}

	diAccount := model.UserAccount{ID: "7", Email: "di@inabit.eu"}
	diProfile := model.UserProfile{ID: "7", FirstName: "Dinko", LastName: "Dinkov"}
	diUser := model.User{ID: "7", Account: diAccount, Profile: diProfile,
		Permissions: nil, Roles: nil, Groups: nil, CommunitiesMemberships: nil}
	danceDICommunity := model.CommunityMembership{ID: "5", User: diUser, Community: danceCommunity,
		CommunityUsers: nil, Account: nil, Profile: nil, Permissions: nil, Roles: []model.CommunityRole{danceRole2}, Groups: []model.CommunityGroup{danceGroup1}}
	illinoisDICommunity := model.CommunityMembership{ID: "6", User: diUser, Community: illinoisCommunity,
		CommunityUsers: nil, Account: nil, Profile: nil, Permissions: nil, Roles: []model.CommunityRole{illinoisRole2}, Groups: []model.CommunityGroup{illinoisGroup2}}
	diUser.CommunitiesMemberships = []model.CommunityMembership{danceDICommunity, illinoisDICommunity}

	res := fmt.Sprintf("GlobalConfig:\n\t%s\n\n"+
		"IllinoisCommunityConfig:\n\t%s\n\n"+
		"DanceCommunityConfig:\n\t%s\n\n"+
		"IllinoisCommunity:\n\t%s\n\n"+
		"DanceCommunity:\n\t%s\n\n"+
		"GlobalRole1:\n\t%s\n\n"+
		"GlobalPermission1:\n\t%s\n\n"+
		"GlobalPermission2:\n\t%s\n\n"+
		"GlobalPermission3:\n\t%s\n\n"+
		"GlobalRole2:\n\t%s\n\n"+
		"IllinoisRole1:\n\t%s\n\n"+
		"IllinoisPermission1:\n\t%s\n\n"+
		"IllinoisPermission2:\n\t%s\n\n"+
		"IllinoisPermission3:\n\t%s\n\n"+
		"IllinoisRole2:\n\t%s\n\n"+
		"IllinoisGroup1:\n\t%s\n\n"+
		"IllinoisGroup2:\n\t%s\n\n"+
		"DanceRole1:\n\t%s\n\n"+
		"DancePermission1:\n\t%s\n\n"+
		"DancePermission2:\n\t%s\n\n"+
		"DancePermission3:\n\t%s\n\n"+
		"DanceRole2:\n\t%s\n\n"+
		"DanceGroup1:\n\t%s\n\n"+
		"GlobalUser1:\n\t%s\n\n"+
		"GlobalUser2:\n\t%s\n\n"+
		"IlliniUser1:\n\t%s\n\n"+
		"IlliniUser2:\n\t%s\n\n"+
		"IlliniUser3:\n\t%s\n\n"+
		"IlliniUserRelations:\n\t%s\n\n"+
		"DanceUser1:\n\t%s\n\n"+
		"DIUser1:\n\t%s\n\n",
		globalConfig, illinoisCommunityConfig, danceCommunityConfig,
		illinoisCommunity, danceCommunity,
		glRole1, glPermission1, glPermission2, glPermission3, glRole2,
		illinoisRole1, illinoisPermission1, illinoisPermission2, illinoisPermission3, illinoisRole2, illinoisGroup1, illinoisGroup2,
		danceRole1, dancePermission1, dancePermission2, dancePermission3, danceRole2, danceGroup1,
		globalUser1, globalUser2, illiniUser1, illiniUser2, illiniUser3, illiniUsersRel, danceUser1, diUser)
	return res
}
