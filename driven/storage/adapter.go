package storage

import (
	"context"
	"core-building-block/core/model"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/rokmetro/auth-library/authservice"
	log "github.com/rokmetro/logging-library/loglib"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type rawUser struct {
	ID string `bson:"_id"`

	Account model.UserAccount `bson:"account"`
	Profile model.UserProfile `bson:"profile"`

	Permissions              []string `bson:"permissions"`
	Roles                    []string `bson:"roles"`
	Groups                   []string `bson:"groups"`
	OrganizationsMemberships []string `bson:"memberships"`

	Devices []model.Device `bson:"devices"`
}

type user struct {
	ID string `bson:"_id"`

	Account model.UserAccount `bson:"account"`
	Profile model.UserProfile `bson:"profile"`

	Permissions              []string `bson:"permissions"`
	Roles                    []role
	Groups                   []group
	OrganizationsMemberships []membership

	Devices []model.Device `bson:"devices"`
}

type membership struct {
	ID   string `bson:"_id"`
	User string `bson:"user"`

	OrgID       string                 `bson:"org_id"`
	OrgUserData map[string]interface{} `bson:"org_user_data"`

	Permissions []string `bson:"permissions"`
	Roles       []string `bson:"roles"`
	Groups      []string `bson:"groups"`
}

type group struct {
	ID   string `bson:"_id"`
	Name string `bson:"name"`

	OrgID string `bson:"org_id"`

	Permissions []string `bson:"permissions"`
	Roles       []string `bson:"roles"`
	Members     []string `bson:"members"`
}

type role struct {
	ID   string `bson:"_id"`
	Name string `bson:"name"`

	OrgID string `bson:"org_id"`

	Permissions []string `bson:"permissions"`
}

type organization struct {
	ID               string   `bson:"_id"`
	Name             string   `bson:"name"`
	Type             string   `bson:"type"`
	RequiresOwnLogin bool     `bson:"requires_own_login"`
	LoginTypes       []string `bson:"login_types"`

	Config organizationConfig `bson:"config"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

type organizationConfig struct {
	ID      string   `bson:"id"`
	Domains []string `bson:"domains"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

//Adapter implements the Storage interface
type Adapter struct {
	db *database
}

//Start starts the storage
func (sa *Adapter) Start() error {
	err := sa.db.start()
	if err != nil {
		return log.WrapActionError(log.ActionInitialize, "storage adapter", nil, err)
	}

	return err
}

//RegisterStorageListener registers a data change listener with the storage adapter
func (sa *Adapter) RegisterStorageListener(storageListener Listener) {
	sa.db.listeners = append(sa.db.listeners, storageListener)
}

//ReadTODO TODO TODO
func (sa *Adapter) ReadTODO() error {
	return nil
}

func (sa *Adapter) FindUserByID(id string) (*model.User, error) {
	return sa.findUser("_id", id)
}

func (sa *Adapter) FindUserByAccountID(accountID string) (*model.User, error) {
	return sa.findUser("account.id", accountID)
}

func (sa *Adapter) findUser(key string, id string) (*model.User, error) {
	fullUser := model.User{}
	// transaction
	err := sa.db.dbClient.UseSession(context.Background(), func(sessionContext mongo.SessionContext) error {
		err := sessionContext.StartTransaction()
		if err != nil {
			abortTransaction(sessionContext)
			return err
		}

		pipeline := []bson.M{
			{"$match": bson.M{key: id}},
			{"$lookup": bson.M{
				"from":         "roles",
				"localField":   "roles",
				"foreignField": "_id",
				"as":           "roles",
			}},
			{"$lookup": bson.M{
				"from":         "groups",
				"localField":   "groups",
				"foreignField": "_id",
				"as":           "groups",
			}},
			{"$lookup": bson.M{
				"from":         "memberships",
				"localField":   "memberships",
				"foreignField": "_id",
				"as":           "memberships",
			}},
		}

		var usersResult []*user
		err = sa.db.users.AggregateWithContext(sessionContext, pipeline, &usersResult, nil)
		if err != nil {
			abortTransaction(sessionContext)
			return err
		}
		if len(usersResult) > 0 {
			//there is a user
			existingUser := usersResult[0]
			fullUser.ID = existingUser.ID
			fullUser.Account = existingUser.Account
			fullUser.Profile = existingUser.Profile
			fullUser.Permissions = existingUser.Permissions
			fullUser.Devices = existingUser.Devices

			fullUser.Roles = []model.GlobalRole{}
			for _, role := range existingUser.Roles {
				fullUser.Roles = append(fullUser.Roles, model.GlobalRole{Name: role.Name, Permissions: role.Permissions})
			}

			fullUser.Groups = []model.GlobalGroup{}
			for _, group := range existingUser.Groups {
				groupRoles, err := sa.FindGlobalRoles(&group.Roles, sessionContext)
				if err != nil {
					fmt.Printf("Failed to find global roles for global group %s\n", group.ID)
					fullUser.Groups = append(fullUser.Groups, model.GlobalGroup{Name: group.Name, Permissions: group.Permissions})
				} else {
					fullUser.Groups = append(fullUser.Groups, model.GlobalGroup{Name: group.Name, Permissions: group.Permissions, Roles: *groupRoles})
				}
			}

			fullUser.OrganizationsMemberships = []model.OrganizationMembership{}
			for _, membership := range existingUser.OrganizationsMemberships {
				orgMembership := model.OrganizationMembership{ID: membership.ID, OrgUserData: membership.OrgUserData, Permissions: membership.Permissions}

				roles, err := sa.FindOrganizationRoles(&membership.Roles, membership.OrgID, sessionContext)
				if err != nil {
					fmt.Printf("Failed to find org roles for org membership %s, orgID %s\n", membership.ID, membership.OrgID)
				} else {
					orgMembership.Roles = *roles
				}

				groups, err := sa.FindOrganizationGroups(&membership.Groups, membership.OrgID, sessionContext)
				if err != nil {
					fmt.Printf("Failed to find org groups for org membership %s, orgID %s\n", membership.ID, membership.OrgID)
				} else {
					orgMembership.Groups = *groups
				}

				org, err := sa.FindOrganization(membership.OrgID)
				if err != nil {
					fmt.Printf("Failed to find organization for orgID %s\n", membership.OrgID)
				} else {
					orgMembership.Organization = *org
				}

				fullUser.OrganizationsMemberships = append(fullUser.OrganizationsMemberships, orgMembership)
			}
		}

		//commit the transaction
		err = sessionContext.CommitTransaction(sessionContext)
		if err != nil {
			abortTransaction(sessionContext)
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &fullUser, nil
}

//InsertUser inserts a user
func (sa *Adapter) InsertUser(userAuth *model.UserAuth, authCred *model.AuthCred) (*model.User, error) {
	if userAuth == nil {
		return nil, log.DataError(log.StatusInvalid, log.TypeArg, log.StringArgs(model.TypeUserAuth))
	}

	newID, err := uuid.NewUUID()
	if err != nil {
		return nil, log.DataError(log.StatusInvalid, log.TypeString, log.StringArgs("user_id"))
	}
	newUser := rawUser{ID: newID.String()}

	accountID, err := uuid.NewUUID()
	if err != nil {
		return nil, log.DataError(log.StatusInvalid, log.TypeString, log.StringArgs("account_id"))
	}
	newAccount := model.UserAccount{ID: accountID.String(), Email: userAuth.Email, Phone: userAuth.Phone}
	newUser.Account = newAccount

	profileID, err := uuid.NewUUID()
	if err != nil {
		return nil, log.DataError(log.StatusInvalid, log.TypeString, log.StringArgs("profile_id"))
	}
	newProfile := model.UserProfile{ID: profileID.String(), FirstName: userAuth.FirstName, LastName: userAuth.LastName, Photo: string(userAuth.Picture)}
	newUser.Profile = newProfile

	newUser.Permissions = []string{}
	newUser.Roles = []string{}
	newUser.Groups = []string{}

	membershipID, err := uuid.NewUUID()
	if err != nil {
		return nil, log.DataError(log.StatusInvalid, log.TypeString, log.StringArgs("membership_id"))
	}
	orgID, ok := userAuth.OrgData["orgID"].(string)
	if !ok {
		return nil, log.DataError(log.StatusInvalid, log.TypeString, log.StringArgs("org_id"))
	}
	newOrgMembership := membership{ID: membershipID.String(), User: newID.String(), OrgID: orgID, OrgUserData: userAuth.OrgData,
		Permissions: []string{}, Roles: []string{}, Groups: []string{}}

	// TODO:
	// add new membership ID to any applicable org groups, possibly set groups based on organization populations

	newUser.OrganizationsMemberships = []string{newOrgMembership.ID}

	// transaction
	err = sa.db.dbClient.UseSession(context.Background(), func(sessionContext mongo.SessionContext) error {
		err := sessionContext.StartTransaction()
		if err != nil {
			abortTransaction(sessionContext)
			return log.WrapActionError(log.ActionStart, log.TypeTransaction, nil, err)
		}

		err = sa.InsertMembership(&newOrgMembership, sessionContext)
		if err != nil {
			abortTransaction(sessionContext)
			return log.WrapActionError(log.ActionInsert, model.TypeOrganizationMembership, nil, err)
		}

		// pass some device info in to use here
		newDevice := model.Device{}
		err = sa.SaveDevice(&newDevice, sessionContext)
		if err == nil {
			newUser.Devices = []model.Device{newDevice}
		}

		_, err = sa.db.users.InsertOneWithContext(sessionContext, newUser)
		if err != nil {
			abortTransaction(sessionContext)
			return log.WrapActionError(log.ActionInsert, model.TypeUser, nil, err)
		}

		authCred.AccountID = accountID.String()
		err = sa.InsertCredentials(authCred, sessionContext)
		if err != nil {
			return log.WrapDataError(log.StatusInvalid, model.TypeAuthCred, &log.FieldArgs{"user_id": userAuth.UserID, "account_id": userAuth.AccountID}, err)
		}

		//commit the transaction
		err = sessionContext.CommitTransaction(sessionContext)
		if err != nil {
			abortTransaction(sessionContext)
			return log.WrapActionError(log.ActionCommit, log.TypeTransaction, nil, err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return sa.FindUserByID(newID.String())
}

//UpdateUser updates an existing user
func (sa *Adapter) UpdateUser(user *model.User, newOrgData *map[string]interface{}) (*model.User, error) {
	if user == nil {
		return nil, log.DataError(log.StatusInvalid, log.TypeArg, log.StringArgs(model.TypeUser))
	}

	newUser := rawUser{ID: user.ID}
	newUser.Account = user.Account
	newUser.Profile = user.Profile

	newUser.Permissions = user.Permissions
	newUser.Roles = []string{}
	for _, r := range user.Roles {
		newUser.Roles = append(newUser.Roles, r.ID)
	}
	newUser.Groups = []string{}
	for _, g := range user.Groups {
		newUser.Groups = append(newUser.Groups, g.ID)
	}

	newUser.OrganizationsMemberships = []string{}
	for _, m := range user.OrganizationsMemberships {
		newUser.OrganizationsMemberships = append(newUser.OrganizationsMemberships, m.ID)
	}
	// transaction
	err := sa.db.dbClient.UseSession(context.Background(), func(sessionContext mongo.SessionContext) error {
		err := sessionContext.StartTransaction()
		if err != nil {
			abortTransaction(sessionContext)
			return log.WrapActionError(log.ActionStart, log.TypeTransaction, nil, err)
		}

		if newOrgData != nil {
			membershipID, err := uuid.NewUUID()
			if err != nil {
				return log.WrapDataError(log.StatusInvalid, log.TypeString, log.StringArgs("membership_id"), err)
			}
			orgID, ok := (*newOrgData)["orgID"].(string)
			if !ok {
				return log.WrapDataError(log.StatusInvalid, log.TypeString, log.StringArgs("org_id"), err)
			}
			newOrgMembership := membership{ID: membershipID.String(), User: user.ID, OrgID: orgID, OrgUserData: *newOrgData,
				Permissions: []string{}, Roles: []string{}, Groups: []string{}}

			// TODO:
			// add new membership ID to any applicable org groups, possibly set groups based on organization populations

			newUser.OrganizationsMemberships = append(newUser.OrganizationsMemberships, newOrgMembership.ID)

			err = sa.InsertMembership(&newOrgMembership, sessionContext)
			if err != nil {
				abortTransaction(sessionContext)
				return log.WrapActionError(log.ActionInsert, model.TypeOrganizationMembership, nil, err)
			}
		}

		// TODO:
		// update devices list

		filter := bson.M{"_id": user.ID}
		err = sa.db.users.ReplaceOneWithContext(sessionContext, filter, newUser, nil)
		if err != nil {
			abortTransaction(sessionContext)
			return log.WrapActionError(log.ActionReplace, model.TypeUser, nil, err)
		}
		//commit the transaction
		err = sessionContext.CommitTransaction(sessionContext)
		if err != nil {
			abortTransaction(sessionContext)
			return log.WrapActionError(log.ActionCommit, log.TypeTransaction, nil, err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return sa.FindUserByID(user.ID)
}

//DeleteUser deletes a user
func (sa *Adapter) DeleteUser(id string) error {
	filter := bson.M{"_id": id}
	_, err := sa.db.users.DeleteOne(filter, nil)
	if err != nil {
		return log.WrapActionError(log.ActionDelete, model.TypeUser, nil, err)
	}

	return nil
}

//FindCredentials find a set of credentials
func (sa *Adapter) FindCredentials(orgID string, appID string, authType string, userID string) (*model.AuthCred, error) {
	var filter bson.D
	if len(orgID) > 0 {
		filter = bson.D{
			primitive.E{Key: "org_id", Value: orgID}, primitive.E{Key: "app_id", Value: appID},
			primitive.E{Key: "type", Value: authType}, primitive.E{Key: "user_id", Value: userID},
		}
	} else {
		filter = bson.D{primitive.E{Key: "type", Value: authType}, primitive.E{Key: "user_id", Value: userID}}
	}

	var creds model.AuthCred
	err := sa.db.credentials.FindOne(filter, &creds, nil)
	if err != nil {
		return nil, log.WrapActionError(log.ActionFind, model.TypeAuthCred, nil, err)
	}

	return &creds, nil
}

//Insert credentials inserts a set of credentials
func (sa *Adapter) InsertCredentials(creds *model.AuthCred, context mongo.SessionContext) error {
	if creds == nil {
		return log.DataError(log.StatusInvalid, log.TypeArg, log.StringArgs(model.TypeAuthCred))
	}

	var err error
	if context == nil {
		_, err = sa.db.credentials.InsertOne(creds)
	} else {
		_, err = sa.db.credentials.InsertOneWithContext(context, creds)
	}
	if err != nil {
		return log.WrapActionError(log.ActionInsert, model.TypeAuthCred, nil, err)
	}

	return nil
}

//Update credentials updates a set of credentials
func (sa *Adapter) UpdateCredentials(orgID string, appID string, authType string, creds *model.AuthCred) error {
	if creds == nil {
		return log.DataError(log.StatusInvalid, log.TypeArg, log.StringArgs(model.TypeAuthCred))
	}

	var filter bson.D
	if len(orgID) > 0 {
		filter = bson.D{
			primitive.E{Key: "org_id", Value: orgID}, primitive.E{Key: "app_id", Value: appID},
			primitive.E{Key: "type", Value: authType}, primitive.E{Key: "user_id", Value: creds.UserID},
		}
	} else {
		filter = bson.D{primitive.E{Key: "type", Value: authType}, primitive.E{Key: "user_id", Value: creds.UserID}}
	}

	err := sa.db.serviceRegs.ReplaceOne(filter, creds, nil)
	if err != nil {
		return log.WrapActionError(log.ActionUpdate, model.TypeAuthCred, &log.FieldArgs{"user_id": creds.UserID}, err)
	}

	return nil
}

//FindGlobalRoles finds a set of global user roles
func (sa *Adapter) FindGlobalRoles(ids *[]string, context mongo.SessionContext) (*[]model.GlobalRole, error) {
	rolesFilter := bson.D{primitive.E{Key: "org_id", Value: "global"}, primitive.E{Key: "_id", Value: bson.M{"$in": *ids}}}
	var rolesResult []model.GlobalRole
	var err error
	if context == nil {
		err = sa.db.roles.Find(rolesFilter, &rolesResult, nil)
	} else {
		err = sa.db.roles.FindWithContext(context, rolesFilter, &rolesResult, nil)
	}
	if err != nil {
		return nil, err
	}

	return &rolesResult, nil
}

//FindOrganizationRoles finds a set of organization user roles
func (sa *Adapter) FindOrganizationRoles(ids *[]string, orgID string, context mongo.SessionContext) (*[]model.OrganizationRole, error) {
	rolesFilter := bson.D{primitive.E{Key: "org_id", Value: orgID}, primitive.E{Key: "_id", Value: bson.M{"$in": *ids}}}
	var rolesResult []model.OrganizationRole
	var err error
	if context == nil {
		err = sa.db.roles.Find(rolesFilter, &rolesResult, nil)
	} else {
		err = sa.db.roles.FindWithContext(context, rolesFilter, &rolesResult, nil)
	}
	if err != nil {
		return nil, err
	}

	return &rolesResult, nil
}

//FindGlobalGroups finds a set of global user groups
func (sa *Adapter) FindGlobalGroups(ids *[]string, context mongo.SessionContext) (*[]model.GlobalGroup, error) {
	pipeline := []bson.M{
		{"$match": bson.M{"org_id": "global", "_id": bson.M{"$in": *ids}}},
		{"$lookup": bson.M{
			"from":         "roles",
			"localField":   "roles",
			"foreignField": "_id",
			"as":           "roles",
		}},
	}
	var groupsResult []model.GlobalGroup
	var err error
	if context == nil {
		err = sa.db.groups.Aggregate(pipeline, &groupsResult, nil)
	} else {
		err = sa.db.groups.AggregateWithContext(context, pipeline, &groupsResult, nil)
	}
	if err != nil {
		return nil, err
	}

	return &groupsResult, nil
}

//FindOrganizationGroups finds a set of organization user groups
func (sa *Adapter) FindOrganizationGroups(ids *[]string, orgID string, context mongo.SessionContext) (*[]model.OrganizationGroup, error) {
	pipeline := []bson.M{
		{"$match": bson.M{"org_id": orgID, "_id": bson.M{"$in": *ids}}},
		{"$lookup": bson.M{
			"from":         "roles",
			"localField":   "roles",
			"foreignField": "_id",
			"as":           "roles",
		}},
	}
	var groupsResult []model.OrganizationGroup
	var err error
	if context == nil {
		err = sa.db.groups.Aggregate(pipeline, &groupsResult, nil)
	} else {
		err = sa.db.groups.AggregateWithContext(context, pipeline, &groupsResult, nil)
	}
	if err != nil {
		return nil, err
	}

	return &groupsResult, nil
}

//InsertMembership inserts an organization membership
func (sa *Adapter) InsertMembership(orgMembership *membership, context mongo.SessionContext) error {
	if orgMembership == nil {
		return log.DataError(log.StatusInvalid, log.TypeArg, log.StringArgs(model.TypeOrganizationMembership))
	}

	var err error
	if context == nil {
		_, err = sa.db.memberships.InsertOne(orgMembership)
	} else {
		_, err = sa.db.memberships.InsertOneWithContext(context, orgMembership)
	}

	if err != nil {
		return log.WrapActionError(log.ActionInsert, model.TypeOrganizationMembership, nil, err)
	}
	return nil
}

//FindAuthConfig finds the auth document from DB by orgID and appID
func (sa *Adapter) FindAuthConfig(orgID string, appID string, authType string) (*model.AuthConfig, error) {
	errFields := &log.FieldArgs{"org_id": orgID, "app_id": appID, "auth_type": authType}
	filter := bson.D{primitive.E{Key: "org_id", Value: orgID}, primitive.E{Key: "app_id", Value: appID}, primitive.E{Key: "type", Value: authType}}
	var result *model.AuthConfig
	err := sa.db.authConfigs.FindOne(filter, &result, nil)
	if err != nil {
		return nil, log.WrapActionError(log.ActionFind, model.TypeAuthConfig, errFields, err)
	}
	if result == nil {
		return nil, log.WrapDataError(log.StatusMissing, model.TypeAuthConfig, errFields, err)
	}
	return result, nil
}

//LoadAuthConfigs finds all auth config documents in the DB
func (sa *Adapter) LoadAuthConfigs() (*[]model.AuthConfig, error) {
	filter := bson.D{}
	var result []model.AuthConfig
	err := sa.db.authConfigs.Find(filter, &result, nil)
	if err != nil {
		return nil, log.WrapActionError(log.ActionFind, model.TypeAuthConfig, nil, err)
	}
	if len(result) == 0 {
		return nil, log.WrapDataError(log.StatusMissing, model.TypeAuthConfig, nil, err)
	}

	return &result, nil
}

//CreateGlobalConfig creates global config
func (sa *Adapter) CreateGlobalConfig(setting string) (*model.GlobalConfig, error) {
	globalConfig := model.GlobalConfig{Setting: setting}
	_, err := sa.db.globalConfig.InsertOne(globalConfig)
	if err != nil {
		return nil, log.WrapActionError(log.ActionInsert, model.TypeGlobalConfig, nil, err)
	}
	return &globalConfig, nil
}

//GetGlobalConfig give config
func (sa *Adapter) GetGlobalConfig() (*model.GlobalConfig, error) {
	filter := bson.D{}
	var result []model.GlobalConfig
	err := sa.db.globalConfig.Find(filter, &result, nil)
	if err != nil {
		return nil, log.WrapActionError(log.ActionFind, model.TypeGlobalConfig, nil, err)
	}
	if len(result) == 0 {
		//no record
		return nil, nil
	}
	return &result[0], nil

}

//SaveGlobalConfig saves the global configuration to the storage
func (sa *Adapter) SaveGlobalConfig(gc *model.GlobalConfig) error {
	// transaction
	err := sa.db.dbClient.UseSession(context.Background(), func(sessionContext mongo.SessionContext) error {
		err := sessionContext.StartTransaction()
		if err != nil {
			return log.WrapActionError(log.ActionStart, log.TypeTransaction, nil, err)
		}

		//clear the global config - we always keep only one global config
		delFilter := bson.D{}
		_, err = sa.db.globalConfig.DeleteManyWithContext(sessionContext, delFilter, nil)
		if err != nil {
			abortTransaction(sessionContext)
			return log.WrapActionError(log.ActionDelete, model.TypeGlobalConfig, nil, err)
		}

		//add the new one
		_, err = sa.db.globalConfig.InsertOneWithContext(sessionContext, gc)
		if err != nil {
			abortTransaction(sessionContext)
			return log.WrapActionError(log.ActionInsert, model.TypeGlobalConfig, nil, err)
		}

		err = sessionContext.CommitTransaction(sessionContext)
		if err != nil {
			abortTransaction(sessionContext)
			return log.WrapActionError(log.ActionCommit, log.TypeTransaction, nil, err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

//FindOrganization finds an organization
func (sa *Adapter) FindOrganization(id string) (*model.Organization, error) {
	errFields := &log.FieldArgs{"id": id}
	filter := bson.D{primitive.E{Key: "_id", Value: id}}
	var org model.Organization

	err := sa.db.organizations.FindOne(filter, &org, nil)
	if err != nil {
		return nil, log.WrapActionError(log.ActionFind, model.TypeOrganization, errFields, err)
	}

	return &org, nil
}

//CreateOrganization creates an organization
func (sa *Adapter) CreateOrganization(name string, requestType string, requiresOwnLogin bool, loginTypes []string, organizationDomains []string) (*model.Organization, error) {
	now := time.Now()

	orgConfigID, _ := uuid.NewUUID()
	orgConfig := organizationConfig{ID: orgConfigID.String(), Domains: organizationDomains, DateCreated: now}

	organizationID, _ := uuid.NewUUID()
	organization := organization{ID: organizationID.String(), Name: name, Type: requestType, RequiresOwnLogin: requiresOwnLogin, LoginTypes: loginTypes,
		Config: orgConfig, DateCreated: now}

	_, err := sa.db.organizations.InsertOne(organization)
	if err != nil {
		return nil, log.WrapActionError(log.ActionInsert, model.TypeOrganization, nil, err)
	}

	//return the correct type
	resOrgConfig := model.OrganizationConfig{ID: orgConfig.ID, Domains: orgConfig.Domains}

	resOrg := model.Organization{ID: organization.ID, Name: organization.Name, Type: organization.Type,
		RequiresOwnLogin: organization.RequiresOwnLogin, LoginTypes: organization.LoginTypes, Config: resOrgConfig}
	return &resOrg, nil
}

//GetOrganization gets organization
func (sa *Adapter) GetOrganization(ID string) (*model.Organization, error) {

	filter := bson.D{primitive.E{Key: "_id", Value: ID}}
	var result []organization
	err := sa.db.organizations.Find(filter, &result, nil)
	if err != nil {
		return nil, log.WrapActionError(log.ActionFind, model.TypeOrganization, nil, err)
	}
	if len(result) == 0 {
		//no record
		return nil, nil
	}
	org := result[0]

	//return the correct type
	getOrgConfig := org.Config
	getResOrgConfig := model.OrganizationConfig{ID: getOrgConfig.ID, Domains: getOrgConfig.Domains}

	getResOrg := model.Organization{ID: org.ID, Name: org.Name, Type: org.Type,
		RequiresOwnLogin: org.RequiresOwnLogin, LoginTypes: org.LoginTypes, Config: getResOrgConfig}
	return &getResOrg, nil
}

//UpdateOrganization updates an organization
func (sa *Adapter) UpdateOrganization(ID string, name string, requestType string, requiresOwnLogin bool, loginTypes []string, organizationDomains []string) error {

	now := time.Now()

	updatOrganizationFilter := bson.D{primitive.E{Key: "_id", Value: ID}}
	updateOrganization := bson.D{
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "name", Value: name},
			primitive.E{Key: "type", Value: requestType},
			primitive.E{Key: "requires_own_login", Value: requiresOwnLogin},
			primitive.E{Key: "login_types", Value: loginTypes},
			primitive.E{Key: "config.domains", Value: organizationDomains},
			primitive.E{Key: "config.date_updated", Value: now},
			primitive.E{Key: "date_updated", Value: now},
		}},
	}

	result, err := sa.db.organizations.UpdateOne(updatOrganizationFilter, updateOrganization, nil)
	if err != nil {
		return log.WrapActionError(log.ActionUpdate, model.TypeOrganization, &log.FieldArgs{"id": ID}, err)
	}
	if result.MatchedCount == 0 {
		return log.WrapDataError(log.StatusMissing, model.TypeOrganization, &log.FieldArgs{"id": ID}, err)
	}

	return nil
}

//GetOrganizations gets the organizations
func (sa *Adapter) GetOrganizations() ([]model.Organization, error) {

	filter := bson.D{}
	var result []model.Organization
	err := sa.db.organizations.Find(filter, &result, nil)
	if err != nil {
		return nil, log.WrapActionError(log.ActionFind, model.TypeOrganization, nil, err)
	}

	var resultList []model.Organization
	for _, current := range result {
		item := &model.Organization{ID: current.ID, Name: current.Name, Type: current.Type, RequiresOwnLogin: current.RequiresOwnLogin,
			LoginTypes: current.LoginTypes, Config: current.Config}
		resultList = append(resultList, *item)
	}
	return resultList, nil
}

// ============================== ServiceRegs ==============================

//FindServiceRegs fetches the requested service registration records
func (sa *Adapter) FindServiceRegs(serviceIDs []string) ([]authservice.ServiceReg, error) {
	var filter bson.M
	for _, serviceID := range serviceIDs {
		if serviceID == "all" {
			filter = bson.M{}
			break
		}
	}
	if filter == nil {
		filter = bson.M{"service_id": bson.M{"$in": serviceIDs}}
	}

	var result []authservice.ServiceReg
	err := sa.db.serviceRegs.Find(filter, &result, nil)
	if err != nil {
		return nil, log.WrapActionError(log.ActionFind, model.TypeServiceReg, &log.FieldArgs{"service_id": serviceIDs}, err)
	}

	if result == nil {
		result = []authservice.ServiceReg{}
	}

	return result, nil
}

//FindServiceReg finds the service registration in storage
func (sa *Adapter) FindServiceReg(serviceID string) (*authservice.ServiceReg, error) {
	filter := bson.M{"service_id": serviceID}
	var reg *authservice.ServiceReg
	err := sa.db.serviceRegs.FindOne(filter, &reg, nil)
	if err != nil {
		return nil, log.WrapActionError(log.ActionFind, model.TypeServiceReg, &log.FieldArgs{"service_id": serviceID}, err)
	}

	return reg, nil
}

//InsertServiceReg inserts the service registration to storage
func (sa *Adapter) InsertServiceReg(reg *authservice.ServiceReg) error {
	_, err := sa.db.serviceRegs.InsertOne(reg)
	if err != nil {
		return log.WrapActionError(log.ActionInsert, model.TypeServiceReg, &log.FieldArgs{"service_id": reg.ServiceID}, err)
	}

	return nil
}

//UpdateServiceReg updates the service registration in storage
func (sa *Adapter) UpdateServiceReg(reg *authservice.ServiceReg) error {
	filter := bson.M{"service_id": reg.ServiceID}
	err := sa.db.serviceRegs.ReplaceOne(filter, reg, nil)
	if err != nil {
		return log.WrapActionError(log.ActionInsert, model.TypeServiceReg, &log.FieldArgs{"service_id": reg.ServiceID}, err)
	}

	return nil
}

//SaveServiceReg saves the service registration to the storage
func (sa *Adapter) SaveServiceReg(reg *authservice.ServiceReg) error {
	filter := bson.M{"service_id": reg.ServiceID}
	opts := options.Replace().SetUpsert(true)
	err := sa.db.serviceRegs.ReplaceOne(filter, reg, opts)
	if err != nil {
		return log.WrapActionError(log.ActionSave, model.TypeServiceReg, &log.FieldArgs{"service_id": reg.ServiceID}, err)
	}

	return nil
}

//DeleteServiceReg deletes the service registration from storage
func (sa *Adapter) DeleteServiceReg(serviceID string) error {
	filter := bson.M{"service_id": serviceID}
	result, err := sa.db.serviceRegs.DeleteOne(filter, nil)
	if err != nil {
		return log.WrapActionError(log.ActionDelete, model.TypeServiceReg, &log.FieldArgs{"service_id": serviceID}, err)
	}
	if result == nil {
		return log.WrapDataError(log.StatusInvalid, "result", &log.FieldArgs{"service_id": serviceID}, err)
	}
	deletedCount := result.DeletedCount
	if deletedCount == 0 {
		return log.WrapDataError(log.StatusMissing, model.TypeServiceReg, &log.FieldArgs{"service_id": serviceID}, err)
	}

	return nil
}

func (sa *Adapter) SaveDevice(device *model.Device, context mongo.SessionContext) error {
	if device == nil {
		return log.DataError(log.StatusInvalid, log.TypeArg, log.StringArgs("device"))
	}

	var err error
	filter := bson.M{"_id": device.ID}
	opts := options.Replace().SetUpsert(true)
	if context == nil {
		err = sa.db.devices.ReplaceOne(filter, device, opts)
	} else {
		err = sa.db.devices.ReplaceOneWithContext(context, filter, device, opts)
	}

	if err != nil {
		return log.WrapActionError(log.ActionSave, "device", &log.FieldArgs{"device_id": device.ID}, nil)
	}

	return nil
}

//NewStorageAdapter creates a new storage adapter instance
func NewStorageAdapter(mongoDBAuth string, mongoDBName string, mongoTimeout string, logger *log.Logger) *Adapter {
	timeoutInt, err := strconv.Atoi(mongoTimeout)
	if err != nil {
		logger.Warn("Setting default Mongo timeout - 500")
		timeoutInt = 500
	}
	timeout := time.Millisecond * time.Duration(timeoutInt)

	db := &database{mongoDBAuth: mongoDBAuth, mongoDBName: mongoDBName, mongoTimeout: timeout}
	return &Adapter{db: db}
}

func abortTransaction(sessionContext mongo.SessionContext) {
	err := sessionContext.AbortTransaction(sessionContext)
	if err != nil {
		//TODO - log
	}
}

//Listener represents storage listener
type Listener interface {
	OnAuthConfigUpdated()
	OnServiceRegsUpdated()
}

//DefaultListenerImpl default listener implementation
type DefaultListenerImpl struct{}

//OnAuthConfigUpdated notifies auth configs have been updated
func (d *DefaultListenerImpl) OnAuthConfigUpdated() {}

//OnServiceRegsUpdated notifies services regs have been updated
func (d *DefaultListenerImpl) OnServiceRegsUpdated() {}
