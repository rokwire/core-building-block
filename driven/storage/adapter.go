package storage

import (
	"context"
	"core-building-block/core"
	"core-building-block/core/auth"
	"core-building-block/core/model"
	"errors"
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

type user struct {
	ID string `bson:"_id"`

	Account model.UserAccount `bson:"account"`
	Profile model.UserProfile `bson:"profile"`

	Permissions []string `bson:"permissions"`
	Roles       []string `bson:"roles"`

	Groups []string `bson:"groups"`

	OrganizationsMemberships []string `bson:"memberships"`

	Devices []model.Device `bson:"devices"`
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
	db     *database
	logger *log.StandardLogger
}

//Start starts the storage
func (sa *Adapter) Start() error {
	err := sa.db.start()
	return err
}

//SetStorageListener sets listener for the storage
func (sa *Adapter) SetStorageListener(storageListener core.StorageListener) {
	sa.db.listener = storageListener
}

//ReadTODO TODO TODO
func (sa *Adapter) ReadTODO() error {
	return nil
}

func (sa *Adapter) FindUser(id string) (*model.User, error) {
	var fullUser *model.User
	// transaction
	err := sa.db.dbClient.UseSession(context.Background(), func(sessionContext mongo.SessionContext) error {
		err := sessionContext.StartTransaction()
		if err != nil {
			return err
		}

		// check if there is a user
		userFilter := bson.D{primitive.E{Key: "_id", Value: id}}
		var usersResult []*user
		err = sa.db.users.FindWithContext(sessionContext, userFilter, &usersResult, nil)
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

			rolesResult, err := sa.FindGlobalRoles(&existingUser.Roles, &sessionContext)
			if err != nil {
				abortTransaction(sessionContext)
				return err
			}
			fullUser.Roles = *rolesResult

			groupsResult, err := sa.FindGlobalGroups(&existingUser.Groups, &sessionContext)
			if err != nil {
				abortTransaction(sessionContext)
				return err
			}
			fullUser.Groups = *groupsResult

			membershipsFilter := bson.D{primitive.E{Key: "_id", Value: bson.M{"$in": existingUser.OrganizationsMemberships}}}
			var membershipsResult []model.OrganizationMembership
			err = sa.db.memberships.FindWithContext(sessionContext, membershipsFilter, &membershipsResult, nil)
			if err != nil {
				abortTransaction(sessionContext)
				return err
			}
			fullUser.OrganizationsMemberships = membershipsResult

			// pipeline := []bson.M{
			// 	{"$lookup": bson.M{
			// 		"from":         "roles",
			// 		"localField":   "roles",
			// 		"foreignField": "_id",
			// 		"as":           "roles",
			// 	}},
			// 	{"$match": bson.M{"user_id1": user.ID, "active": true}},
			// 	{"$unwind": "$sub"},
			// 	{"$project": bson.M{
			// 		"clientID": "$sub.clientID", "_id": "$sub._id", "uid": "$sub.uid", "external_id": "$sub.external_id",
			// 		"profile": "$sub.profile", "sub": "$sub.sub", "active": "$sub.active", "date_created": "$sub.date_created",
			// 		"date_updated": "$sub.date_updated", "created_by": "$sub.created_by",
			// 	}}}

			// var userSubsResult []*model.User
			// err := sa.db.usersrelations.Aggregate(pipeline, &userSubsResult, nil)
			// if err != nil {
			// 	abortTransaction(sessionContext)
			// 	return err
			// }
		}

		//commit the transaction
		err = sessionContext.CommitTransaction(sessionContext)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return fullUser, nil
}

//InsertUser inserts a user
func (sa *Adapter) InsertUser(user *model.User) (*model.User, error) {
	return nil, errors.New("unimplemented")
}

//UpdateUser updates an existing user
func (sa *Adapter) UpdateUser(user *model.User) (*model.User, error) {
	return nil, errors.New("unimplemented")
}

//DeleteUser deletes a user
func (sa *Adapter) DeleteUser(id string) error {
	return errors.New("unimplemented")
}

//FindGlobalRoles finds a set of global user roles
func (sa *Adapter) FindGlobalRoles(ids *[]string, context *mongo.SessionContext) (*[]model.GlobalRole, error) {
	rolesFilter := bson.D{primitive.E{Key: "org_id", Value: "global"}, primitive.E{Key: "_id", Value: bson.M{"$in": *ids}}}
	var rolesResult []model.GlobalRole
	var err error
	if context == nil {
		err = sa.db.roles.Find(rolesFilter, &rolesResult, nil)
	} else {
		err = sa.db.roles.FindWithContext(*context, rolesFilter, &rolesResult, nil)
	}
	if err != nil {
		return nil, err
	}

	return &rolesResult, nil
}

//FindOrganizationRoles finds a set of organization user roles
func (sa *Adapter) FindOrganizationRoles(ids *[]string, orgID string, context *mongo.SessionContext) (*[]model.OrganizationRole, error) {
	pipeline := []bson.M{
		{"$match": bson.M{"org_id": orgID, "_id": bson.M{"$in": *ids}}},
		{"$lookup": bson.M{
			"from":         "organizations",
			"localField":   "org_id",
			"foreignField": "_id",
			"as":           "organization",
		}},
		{"$unwind": "$organization"},
		{"$project": bson.M{"org_id": 0}},
	}
	var rolesResult []model.OrganizationRole
	var err error

	if context == nil {
		err = sa.db.roles.Aggregate(pipeline, &rolesResult, nil)
	} else {
		err = sa.db.roles.AggregateWithContext(*context, pipeline, &rolesResult, nil)
	}
	if err != nil {
		return nil, err
	}

	return &rolesResult, nil
}

//FindGlobalGroups finds a set of global user groups
func (sa *Adapter) FindGlobalGroups(ids *[]string, context *mongo.SessionContext) (*[]model.GlobalGroup, error) {
	pipeline := []bson.M{
		{"$match": bson.M{"org_id": "global", "_id": bson.M{"$in": *ids}}},
		{"$lookup": bson.M{
			"from":         "roles",
			"localField":   "roles",
			"foreignField": "_id",
			"as":           "roles",
		}},
		{"$lookup": bson.M{
			"from":         "users",
			"localField":   "users",
			"foreignField": "_id",
			"as":           "users",
		}},
	}
	var groupsResult []model.GlobalGroup
	var err error
	if context == nil {
		err = sa.db.groups.Aggregate(pipeline, &groupsResult, nil)
	} else {
		err = sa.db.groups.AggregateWithContext(*context, pipeline, &groupsResult, nil)
	}
	if err != nil {
		return nil, err
	}

	return &groupsResult, nil
}

//FindOrganizationGroups finds a set of organization user groups
func (sa *Adapter) FindOrganizationGroups(ids *[]string, orgID string, context *mongo.SessionContext) (*[]model.OrganizationGroup, error) {
	pipeline := []bson.M{
		{"$match": bson.M{"org_id": orgID, "_id": bson.M{"$in": *ids}}},
		{"$lookup": bson.M{
			"from":         "roles",
			"localField":   "roles",
			"foreignField": "_id",
			"as":           "roles",
		}},
		{"$lookup": bson.M{
			"from":         "memberships",
			"localField":   "memberships",
			"foreignField": "_id",
			"as":           "memberships",
		}},
		{"$lookup": bson.M{
			"from":         "organizations",
			"localField":   "org_id",
			"foreignField": "_id",
			"as":           "organization",
		}},
		{"$unwind": "$organization"},
		{"$project": bson.M{"org_id": 0}},
	}
	var groupsResult []model.OrganizationGroup
	var err error
	if context == nil {
		err = sa.db.groups.Aggregate(pipeline, &groupsResult, nil)
	} else {
		err = sa.db.groups.AggregateWithContext(*context, pipeline, &groupsResult, nil)
	}
	if err != nil {
		return nil, err
	}

	return &groupsResult, nil
}

// func (sa *Adapter) FindOrganizationMemberships(ids *[]string, context *mongo.SessionContext) (*[]model.OrganizationMembership, error) {
// 	pipeline := []bson.M{
// 		{"$match": bson.M{"org_id": orgID, "_id": bson.M{"$in": *ids}}},
// 		{"$lookup": bson.M{
// 			"from":         "organizations",
// 			"localField":   "org_id",
// 			"foreignField": "_id",
// 			"as":           "organization",
// 		}},
// 		{"$unwind": "$organization"},
// 		{"$project": bson.M{"org_id": 0}},
// 	}
// 	var rolesResult []model.OrganizationRole
// 	var err error

// 	if context == nil {
// 		err = sa.db.roles.Aggregate(pipeline, &rolesResult, nil)
// 	} else {
// 		err = sa.db.roles.AggregateWithContext(*context, pipeline, &rolesResult, nil)
// 	}
// 	if err != nil {
// 		return nil, err
// 	}

// 	return &rolesResult, nil
// }

//FindAuthConfig finds the auth document from DB by orgID and appID
func (sa *Adapter) FindAuthConfig(orgID string, appID string, authType string) (*auth.AuthConfig, error) {
	filter := bson.D{primitive.E{Key: "org_id", Value: orgID}, primitive.E{Key: "app_id", Value: appID}, primitive.E{Key: "type", Value: authType}}
	var result *auth.AuthConfig
	err := sa.db.authConfigs.FindOne(filter, &result, nil)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, fmt.Errorf("no auth config found for orgID %s, appID %s, authType %s:", orgID, appID, authType)
	}
	return result, nil
}

//LoadAuthConfigs finds all auth config documents in the DB
func (sa *Adapter) LoadAuthConfigs() (*[]auth.AuthConfig, error) {
	filter := bson.D{}
	var result []auth.AuthConfig
	err := sa.db.authConfigs.Find(filter, &result, nil)
	if err != nil {
		return nil, err
	}
	if result == nil || len(result) == 0 {
		return nil, errors.New("no auth config documents found")
	}

	return &result, nil
}

//CreateGlobalConfig creates global config
func (sa *Adapter) CreateGlobalConfig(setting string) (*model.GlobalConfig, error) {
	globalConfig := model.GlobalConfig{Setting: setting}
	_, err := sa.db.globalConfig.InsertOne(globalConfig)
	if err != nil {
		return nil, err
	}
	return &globalConfig, nil
}

//GetGlobalConfig give config
func (sa *Adapter) GetGlobalConfig() (*model.GlobalConfig, error) {
	filter := bson.D{}
	var result []model.GlobalConfig
	err := sa.db.globalConfig.Find(filter, &result, nil)
	if err != nil {
		return nil, err
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
			fmt.Println(err)
			return err
		}

		//clear the global config - we always keep only one global config
		delFilter := bson.D{}
		_, err = sa.db.globalConfig.DeleteManyWithContext(sessionContext, delFilter, nil)
		if err != nil {
			abortTransaction(sessionContext)
			return err
		}

		//add the new one
		_, err = sa.db.globalConfig.InsertOneWithContext(sessionContext, gc)
		if err != nil {
			abortTransaction(sessionContext)
			return err
		}

		err = sessionContext.CommitTransaction(sessionContext)
		if err != nil {
			//TODO print
			//log.Printf("error on commiting a transaction - %s", err)
			return err
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
	return nil, errors.New("unimplemented")
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
		return nil, err
	}

	//return the correct type
	resOrgConfig := model.OrganizationConfig{ID: orgConfig.ID, Domains: orgConfig.Domains}

	resOrg := model.Organization{ID: organization.ID, Name: organization.Name, Type: organization.Type,
		RequiresOwnLogin: organization.RequiresOwnLogin, LoginTypes: organization.LoginTypes, Config: resOrgConfig}
	return &resOrg, nil
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
		return err
	}
	if result.MatchedCount == 0 {
		return errors.New("there is no organziation for the provided id")
	}

	return nil
}

//GetServiceRegs fetches the requested service registration records
func (sa *Adapter) GetServiceRegs(serviceIDs []string) ([]authservice.ServiceReg, error) {
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
	return result, err
}

//SaveServiceReg saves the service registration to the storage
func (sa *Adapter) SaveServiceReg(reg *authservice.ServiceReg) error {
	filter := bson.M{"service_id": reg.ServiceID}
	opts := options.Replace().SetUpsert(true)
	err := sa.db.serviceRegs.ReplaceOne(filter, reg, opts)
	if err != nil {
		return fmt.Errorf("error saving service reg for service id %s: %v", reg.ServiceID, err)
	}

	return nil
}

//NewStorageAdapter creates a new storage adapter instance
func NewStorageAdapter(mongoDBAuth string, mongoDBName string, mongoTimeout string, logger *log.StandardLogger) *Adapter {
	timeout, err := strconv.Atoi(mongoTimeout)
	if err != nil {
		logger.Error("Set default timeout - 500")
		timeout = 500
	}
	timeoutMS := time.Millisecond * time.Duration(timeout)

	db := &database{mongoDBAuth: mongoDBAuth, mongoDBName: mongoDBName, mongoTimeout: timeoutMS}
	return &Adapter{db: db, logger: logger}
}

func abortTransaction(sessionContext mongo.SessionContext) {
	err := sessionContext.AbortTransaction(sessionContext)
	if err != nil {
		//TODO - log
	}

}
