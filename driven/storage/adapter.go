package storage

import (
	"context"
	"core-building-block/core/model"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rokmetro/logging-library/errors"
	"github.com/rokmetro/logging-library/logs"
	"github.com/rokmetro/logging-library/logutils"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/sync/syncmap"
	"gopkg.in/go-playground/validator.v9"
)

//Adapter implements the Storage interface
type Adapter struct {
	db *database

	logger *logs.Logger

	cachedOrganizations *syncmap.Map
	organizationsLock   *sync.RWMutex
}

//Start starts the storage
func (sa *Adapter) Start() error {
	//start db
	err := sa.db.start()
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionInitialize, "storage adapter", nil, err)
	}

	//register storage listener
	sl := storageListener{adapter: sa}
	sa.RegisterStorageListener(&sl)

	//cache the organizations
	err = sa.cacheOrganizations()
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionCache, model.TypeOrganization, nil, err)
	}

	return err
}

//RegisterStorageListener registers a data change listener with the storage adapter
func (sa *Adapter) RegisterStorageListener(storageListener Listener) {
	sa.db.listeners = append(sa.db.listeners, storageListener)
}

//cacheOrganizations caches the organizations from the DB
func (sa *Adapter) cacheOrganizations() error {
	sa.logger.Info("cacheOrganizations..")

	organizations, err := sa.GetOrganizations()
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeOrganization, nil, err)
	}

	sa.setCachedOrganizations(&organizations)

	return nil
}

func (sa *Adapter) getCachedOrganization(orgID string) (*model.Organization, error) {
	sa.organizationsLock.RLock()
	defer sa.organizationsLock.RUnlock()

	errArgs := &logutils.FieldArgs{"org_id": orgID}

	item, _ := sa.cachedOrganizations.Load(orgID)
	if item != nil {
		organization, ok := item.(model.Organization)
		if !ok {
			return nil, errors.ErrorAction(logutils.ActionCast, model.TypeOrganization, errArgs)
		}
		return &organization, nil
	}
	return nil, errors.ErrorData(logutils.StatusMissing, model.TypeAuthConfig, errArgs)
}

func (sa *Adapter) setCachedOrganizations(organizations *[]model.Organization) {
	sa.organizationsLock.Lock()
	defer sa.organizationsLock.Unlock()

	sa.cachedOrganizations = &syncmap.Map{}
	validate := validator.New()

	for _, org := range *organizations {
		err := validate.Struct(org)
		if err == nil {
			sa.cachedOrganizations.Store(org.ID, org)
		}
	}
}

//FindUserByID finds an user by id
func (sa *Adapter) FindUserByID(id string) (*model.User, error) {
	return sa.findUser("_id", id)
}

//FindUserByAccountID finds an user by account id
func (sa *Adapter) FindUserByAccountID(accountID string) (*model.User, error) {
	return sa.findUser("account.id", accountID)
}

func (sa *Adapter) findUser(key string, id string) (*model.User, error) {
	filter := bson.M{key: id}
	var user user
	err := sa.db.users.FindOne(filter, &user, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeUser, nil, err)
	}

	modelUser := userFromStorage(&user, sa)
	return &modelUser, nil
}

//InsertUser inserts a user
func (sa *Adapter) InsertUser(user *model.User, authCred *model.AuthCred) (*model.User, error) {
	if user == nil {
		return nil, errors.ErrorData(logutils.StatusInvalid, logutils.TypeArg, logutils.StringArgs(model.TypeUser))
	}

	storageUser := userToStorage(user)
	membership := storageUser.OrganizationsMemberships[0]

	orgID, ok := membership.OrgUserData["orgID"].(string)
	if !ok {
		return nil, errors.ErrorData(logutils.StatusInvalid, logutils.TypeString, logutils.StringArgs("org_id"))
	}

	organizationMembership := organizationMembership{ID: membership.ID, UserID: user.ID, OrgID: orgID,
		OrgUserData: membership.OrgUserData, DateCreated: storageUser.DateCreated}

	// transaction
	err := sa.db.dbClient.UseSession(context.Background(), func(sessionContext mongo.SessionContext) error {
		err := sessionContext.StartTransaction()
		if err != nil {
			sa.abortTransaction(sessionContext)
			return errors.WrapErrorAction(logutils.ActionStart, logutils.TypeTransaction, nil, err)
		}

		_, err = sa.db.users.InsertOneWithContext(sessionContext, storageUser)
		if err != nil {
			sa.abortTransaction(sessionContext)
			return errors.WrapErrorAction(logutils.ActionInsert, model.TypeUser, nil, err)
		}

		authCred.AccountID = storageUser.Account.ID
		err = sa.InsertCredentials(authCred, sessionContext)
		if err != nil {
			return errors.WrapErrorData(logutils.StatusInvalid, model.TypeAuthCred, &logutils.FieldArgs{"user_id": user.Account.Username, "account_id": user.Account.ID}, err)
		}

		err = sa.InsertMembership(&organizationMembership, sessionContext)
		if err != nil {
			sa.abortTransaction(sessionContext)
			return errors.WrapErrorAction(logutils.ActionInsert, model.TypeOrganizationMembership, nil, err)
		}

		//TODO: only save if device info has changed or it is new device
		// err = sa.SaveDevice(&newDevice, sessionContext)
		// if err == nil {
		// 	abortTransaction(sessionContext)
		// 	return log.WrapErrorAction(log.ActionSave, "device", nil, err)
		// }

		//commit the transaction
		err = sessionContext.CommitTransaction(sessionContext)
		if err != nil {
			sa.abortTransaction(sessionContext)
			return errors.WrapErrorAction(logutils.ActionCommit, logutils.TypeTransaction, nil, err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	returnUser := userFromStorage(storageUser, sa)
	return &returnUser, nil
}

//UpdateUser updates an existing user
func (sa *Adapter) UpdateUser(updatedUser *model.User, newOrgData *map[string]interface{}) (*model.User, error) {
	if updatedUser == nil {
		return nil, errors.ErrorData(logutils.StatusInvalid, logutils.TypeArg, logutils.StringArgs(model.TypeUser))
	}

	now := time.Now().UTC()
	newUser := userToStorage(updatedUser)
	newUser.DateUpdated = &now

	// TODO:
	// check for device updates and add possible new device

	var newMembership *organizationMembership
	if newOrgData != nil {
		membershipID, err := uuid.NewUUID()
		if err != nil {
			return nil, errors.WrapErrorData(logutils.StatusInvalid, logutils.TypeString, logutils.StringArgs("membership_id"), err)
		}
		orgID, ok := (*newOrgData)["orgID"].(string)
		if !ok {
			return nil, errors.WrapErrorData(logutils.StatusInvalid, logutils.TypeString, logutils.StringArgs("org_id"), err)
		}
		newOrgMembership := organizationMembership{ID: membershipID.String(), UserID: updatedUser.ID, OrgID: orgID,
			OrgUserData: *newOrgData, DateCreated: now}
		newMembership = &newOrgMembership

		// TODO:
		// possibly set groups based on organization populations

		newUser.OrganizationsMemberships = append(newUser.OrganizationsMemberships,
			userMembership{ID: membershipID.String(), OrgID: orgID, OrgUserData: *newOrgData, DateCreated: now})
	}

	// transaction
	err := sa.db.dbClient.UseSession(context.Background(), func(sessionContext mongo.SessionContext) error {
		err := sessionContext.StartTransaction()
		if err != nil {
			sa.abortTransaction(sessionContext)
			return errors.WrapErrorAction(logutils.ActionStart, logutils.TypeTransaction, nil, err)
		}

		filter := bson.M{"_id": updatedUser.ID}
		err = sa.db.users.ReplaceOneWithContext(sessionContext, filter, newUser, nil)
		if err != nil {
			sa.abortTransaction(sessionContext)
			return errors.WrapErrorAction(logutils.ActionReplace, model.TypeUser, nil, err)
		}

		if newMembership != nil {
			err = sa.InsertMembership(newMembership, sessionContext)
			if err != nil {
				sa.abortTransaction(sessionContext)
				return errors.WrapErrorAction(logutils.ActionInsert, model.TypeOrganizationMembership, nil, err)
			}
		}

		//TODO: save device if some device info has changed or added new device
		// err = sa.SaveDevice(&newDevice, sessionContext)
		// if err == nil {
		// 	abortTransaction(sessionContext)
		// 	return log.WrapErrorAction(log.ActionSave, "device", nil, err)
		// }

		//commit the transaction
		err = sessionContext.CommitTransaction(sessionContext)
		if err != nil {
			sa.abortTransaction(sessionContext)
			return errors.WrapErrorAction(logutils.ActionCommit, logutils.TypeTransaction, nil, err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	returnUser := userFromStorage(newUser, sa)
	return &returnUser, nil
}

//DeleteUser deletes a user
func (sa *Adapter) DeleteUser(id string) error {
	//TODO - we have to decide what we do on delete user operation - removing all user relations, (or) mark the user disabled etc
	filter := bson.M{"_id": id}
	_, err := sa.db.users.DeleteOne(filter, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeUser, nil, err)
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
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAuthCred, nil, err)
	}

	return &creds, nil
}

//InsertCredentials credentials inserts a set of credentials
func (sa *Adapter) InsertCredentials(creds *model.AuthCred, context mongo.SessionContext) error {
	if creds == nil {
		return errors.ErrorData(logutils.StatusInvalid, logutils.TypeArg, logutils.StringArgs(model.TypeAuthCred))
	}

	var err error
	if context == nil {
		_, err = sa.db.credentials.InsertOne(creds)
	} else {
		_, err = sa.db.credentials.InsertOneWithContext(context, creds)
	}
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionInsert, model.TypeAuthCred, nil, err)
	}

	return nil
}

//FindGlobalPermissions finds a set of global user permissions
func (sa *Adapter) FindGlobalPermissions(ids []string) ([]model.GlobalPermission, error) {
	permissionsFilter := bson.D{primitive.E{Key: "_id", Value: bson.M{"$in": ids}}}
	var permissionsResult []model.GlobalPermission
	err := sa.db.globalPermissions.Find(permissionsFilter, &permissionsResult, nil)
	if err != nil {
		return nil, err
	}

	return permissionsResult, nil
}

//FindGlobalRoles finds a set of global user roles
func (sa *Adapter) FindGlobalRoles(ids []string) ([]model.GlobalRole, error) {
	rolesFilter := bson.D{primitive.E{Key: "_id", Value: bson.M{"$in": ids}}}
	var rolesResult []model.GlobalRole
	err := sa.db.globalRoles.Find(rolesFilter, &rolesResult, nil)
	if err != nil {
		return nil, err
	}

	return rolesResult, nil
}

//FindGlobalGroups finds a set of global user groups
func (sa *Adapter) FindGlobalGroups(ids []string) ([]model.GlobalGroup, error) {
	filter := bson.D{primitive.E{Key: "_id", Value: bson.M{"$in": ids}}}
	var groupsResult []model.GlobalGroup
	err := sa.db.globalGroups.Find(filter, &groupsResult, nil)
	if err != nil {
		return nil, err
	}
	return groupsResult, nil
}

//FindOrganizationPermissions finds a set of organization user permissions
func (sa *Adapter) FindOrganizationPermissions(ids []string, orgID string) ([]model.OrganizationPermission, error) {
	permissionsFilter := bson.D{primitive.E{Key: "organization_id", Value: orgID}, primitive.E{Key: "_id", Value: bson.M{"$in": ids}}}
	var permissionsResult []organizationPermission
	err := sa.db.organizationsPermissions.Find(permissionsFilter, &permissionsResult, nil)
	if err != nil {
		return nil, err
	}

	//get the organization from the cached ones
	organization, err := sa.getCachedOrganization(orgID)
	if err != nil {
		return nil, errors.WrapErrorData(logutils.StatusMissing, model.TypeOrganization, &logutils.FieldArgs{"org_id": orgID}, err)
	}

	result := organizationPermissionsFromStorage(permissionsResult, *organization)

	return result, nil
}

//FindOrganizationRoles finds a set of organization user roles
func (sa *Adapter) FindOrganizationRoles(ids []string, orgID string) ([]model.OrganizationRole, error) {
	rolesFilter := bson.D{primitive.E{Key: "organization_id", Value: orgID}, primitive.E{Key: "_id", Value: bson.M{"$in": ids}}}
	var rolesResult []organizationRole
	err := sa.db.organizationsRoles.Find(rolesFilter, &rolesResult, nil)
	if err != nil {
		return nil, err
	}

	//get the organization from the cached ones
	organization, err := sa.getCachedOrganization(orgID)
	if err != nil {
		return nil, errors.WrapErrorData(logutils.StatusMissing, model.TypeOrganization, &logutils.FieldArgs{"org_id": orgID}, err)
	}

	result := organizationRolesFromStorage(rolesResult, *organization)

	return result, nil
}

//FindOrganizationGroups finds a set of organization user groups
func (sa *Adapter) FindOrganizationGroups(ids []string, orgID string) ([]model.OrganizationGroup, error) {
	filter := bson.D{primitive.E{Key: "organization_id", Value: orgID}, primitive.E{Key: "_id", Value: bson.M{"$in": ids}}}
	var groupsResult []organizationGroup
	err := sa.db.organizationsGroups.Find(filter, &groupsResult, nil)
	if err != nil {
		return nil, err
	}

	//get the organization from the cached ones
	organization, err := sa.getCachedOrganization(orgID)
	if err != nil {
		return nil, errors.WrapErrorData(logutils.StatusMissing, model.TypeOrganization, &logutils.FieldArgs{"org_id": orgID}, err)
	}

	result := organizationGroupsFromStorage(groupsResult, *organization)

	return result, nil
}

//InsertMembership inserts an organization membership
func (sa *Adapter) InsertMembership(orgMembership *organizationMembership, context mongo.SessionContext) error {
	if orgMembership == nil {
		return errors.ErrorData(logutils.StatusInvalid, logutils.TypeArg, logutils.StringArgs(model.TypeOrganizationMembership))
	}

	var err error
	if context == nil {
		_, err = sa.db.organizationsMemberships.InsertOne(orgMembership)
	} else {
		_, err = sa.db.organizationsMemberships.InsertOneWithContext(context, orgMembership)
	}

	if err != nil {
		return errors.WrapErrorAction(logutils.ActionInsert, model.TypeOrganizationMembership, nil, err)
	}
	return nil
}

//FindAuthConfig finds the auth document from DB by orgID and appID
func (sa *Adapter) FindAuthConfig(orgID string, appID string, authType string) (*model.AuthConfig, error) {
	errFields := &logutils.FieldArgs{"org_id": orgID, "app_id": appID, "auth_type": authType}
	filter := bson.D{primitive.E{Key: "org_id", Value: orgID}, primitive.E{Key: "app_id", Value: appID}, primitive.E{Key: "type", Value: authType}}
	var result *model.AuthConfig
	err := sa.db.authConfigs.FindOne(filter, &result, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAuthConfig, errFields, err)
	}
	if result == nil {
		return nil, errors.WrapErrorData(logutils.StatusMissing, model.TypeAuthConfig, errFields, err)
	}
	return result, nil
}

//LoadAuthConfigs finds all auth config documents in the DB
func (sa *Adapter) LoadAuthConfigs() (*[]model.AuthConfig, error) {
	filter := bson.D{}
	var result []model.AuthConfig
	err := sa.db.authConfigs.Find(filter, &result, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAuthConfig, nil, err)
	}
	if len(result) == 0 {
		return nil, errors.WrapErrorData(logutils.StatusMissing, model.TypeAuthConfig, nil, err)
	}

	return &result, nil
}

//CreateGlobalConfig creates global config
func (sa *Adapter) CreateGlobalConfig(setting string) (*model.GlobalConfig, error) {
	globalConfig := model.GlobalConfig{Setting: setting}
	_, err := sa.db.globalConfig.InsertOne(globalConfig)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionInsert, model.TypeGlobalConfig, nil, err)
	}
	return &globalConfig, nil
}

//GetGlobalConfig give config
func (sa *Adapter) GetGlobalConfig() (*model.GlobalConfig, error) {
	filter := bson.D{}
	var result []model.GlobalConfig
	err := sa.db.globalConfig.Find(filter, &result, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeGlobalConfig, nil, err)
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
			return errors.WrapErrorAction(logutils.ActionStart, logutils.TypeTransaction, nil, err)
		}

		//clear the global config - we always keep only one global config
		delFilter := bson.D{}
		_, err = sa.db.globalConfig.DeleteManyWithContext(sessionContext, delFilter, nil)
		if err != nil {
			sa.abortTransaction(sessionContext)
			return errors.WrapErrorAction(logutils.ActionDelete, model.TypeGlobalConfig, nil, err)
		}

		//add the new one
		_, err = sa.db.globalConfig.InsertOneWithContext(sessionContext, gc)
		if err != nil {
			sa.abortTransaction(sessionContext)
			return errors.WrapErrorAction(logutils.ActionInsert, model.TypeGlobalConfig, nil, err)
		}

		err = sessionContext.CommitTransaction(sessionContext)
		if err != nil {
			sa.abortTransaction(sessionContext)
			return errors.WrapErrorAction(logutils.ActionCommit, logutils.TypeTransaction, nil, err)
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
	//no transactions for get operations..

	//1. find organization
	orgFilter := bson.D{primitive.E{Key: "_id", Value: id}}
	var org organization

	err := sa.db.organizations.FindOne(orgFilter, &org, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeOrganization, &logutils.FieldArgs{"id": id}, err)
	}

	//2. find the organization applications
	var applications []model.Application
	if len(org.Applications) > 0 {
		appsFilter := bson.D{primitive.E{Key: "_id", Value: bson.M{"$in": org.Applications}}}
		err := sa.db.applications.Find(appsFilter, &applications, nil)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplication, nil, err)
		}
	}

	organization := organizationFromStorage(&org, applications)
	return &organization, nil
}

//InsertOrganization inserts an organization
func (sa *Adapter) InsertOrganization(organization model.Organization) (*model.Organization, error) {
	org := organizationToStorage(&organization)
	_, err := sa.db.organizations.InsertOne(org)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionInsert, model.TypeOrganization, nil, err)
	}

	return &organization, nil
}

//UpdateOrganization updates an organization
func (sa *Adapter) UpdateOrganization(ID string, name string, requestType string, requiresOwnLogin bool, loginTypes []string, organizationDomains []string) error {

	now := time.Now()
	//TODO - use pointers and update only what not nil
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
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeOrganization, &logutils.FieldArgs{"id": ID}, err)
	}
	if result.MatchedCount == 0 {
		return errors.WrapErrorData(logutils.StatusMissing, model.TypeOrganization, &logutils.FieldArgs{"id": ID}, err)
	}

	return nil
}

//GetOrganizations gets the organizations
func (sa *Adapter) GetOrganizations() ([]model.Organization, error) {
	//no transactions for get operations..

	//1. find the organizations
	orgsFilter := bson.D{}
	var orgsResult []organization
	err := sa.db.organizations.Find(orgsFilter, &orgsResult, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeOrganization, nil, err)
	}
	if len(orgsResult) == 0 {
		//no data
		return make([]model.Organization, 0), nil
	}

	//2. find the applications for the organization
	var applicationsIDs []string
	for _, org := range orgsResult {
		if len(org.Applications) > 0 {
			applicationsIDs = append(applicationsIDs, org.Applications...)
		}
	}
	var applicationsResult []model.Application
	if len(applicationsIDs) > 0 {
		orgsAppsFilter := bson.D{primitive.E{Key: "_id", Value: bson.M{"$in": applicationsIDs}}}
		err := sa.db.applications.Find(orgsAppsFilter, &applicationsResult, nil)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplication, nil, err)
		}
	}

	//3. prepare the response
	organizations := organizationsFromStorage(orgsResult, applicationsResult)
	return organizations, nil
}

//GetApplication gets application
func (sa *Adapter) GetApplication(ID string) (*model.Application, error) {
	filter := bson.D{primitive.E{Key: "_id", Value: ID}}
	var result []model.Application
	err := sa.db.applications.Find(filter, &result, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplication, nil, err)
	}
	if len(result) == 0 {
		//no record
		return nil, nil
	}

	appRes := result[0]

	getResApp := model.Application{ID: appRes.ID, Name: appRes.Name, Versions: appRes.Versions}
	return &getResApp, nil
}

//UpdateGlobalPermission saves the global permission to the storage
func (sa *Adapter) UpdateGlobalPermission(ID string, name string) error {
	// transaction
	err := sa.db.dbClient.UseSession(context.Background(), func(sessionContext mongo.SessionContext) error {
		err := sessionContext.StartTransaction()
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionStart, logutils.TypeTransaction, nil, err)
		}

		updateGlobalPermissionsFilter := bson.D{primitive.E{Key: "name", Value: name}}
		_, err = sa.db.globalPermissions.DeleteManyWithContext(sessionContext, updateGlobalPermissionsFilter, nil)
		if err != nil {
			sa.abortTransaction(sessionContext)
			return errors.WrapErrorAction(logutils.ActionDelete, model.TypeGlobalPermission, nil, err)
		}

		//add the new one
		_, err = sa.db.globalPermissions.InsertOneWithContext(sessionContext, name)
		if err != nil {
			sa.abortTransaction(sessionContext)
			return errors.WrapErrorAction(logutils.ActionInsert, model.TypeGlobalPermission, nil, err)
		}

		err = sessionContext.CommitTransaction(sessionContext)
		if err != nil {
			sa.abortTransaction(sessionContext)
			return errors.WrapErrorAction(logutils.ActionCommit, logutils.TypeTransaction, nil, err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

// ============================== ServiceRegs ==============================

//FindServiceRegs fetches the requested service registration records
func (sa *Adapter) FindServiceRegs(serviceIDs []string) ([]model.ServiceReg, error) {
	var filter bson.M
	for _, serviceID := range serviceIDs {
		if serviceID == "all" {
			filter = bson.M{}
			break
		}
	}
	if filter == nil {
		filter = bson.M{"registration.service_id": bson.M{"$in": serviceIDs}}
	}

	var result []model.ServiceReg
	err := sa.db.serviceRegs.Find(filter, &result, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeServiceReg, &logutils.FieldArgs{"service_id": serviceIDs}, err)
	}

	if result == nil {
		result = []model.ServiceReg{}
	}

	return result, nil
}

//FindServiceReg finds the service registration in storage
func (sa *Adapter) FindServiceReg(serviceID string) (*model.ServiceReg, error) {
	filter := bson.M{"registration.service_id": serviceID}
	var reg *model.ServiceReg
	err := sa.db.serviceRegs.FindOne(filter, &reg, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeServiceReg, &logutils.FieldArgs{"service_id": serviceID}, err)
	}

	return reg, nil
}

//InsertServiceReg inserts the service registration to storage
func (sa *Adapter) InsertServiceReg(reg *model.ServiceReg) error {
	_, err := sa.db.serviceRegs.InsertOne(reg)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionInsert, model.TypeServiceReg, &logutils.FieldArgs{"service_id": reg.Registration.ServiceID}, err)
	}

	return nil
}

//UpdateServiceReg updates the service registration in storage
func (sa *Adapter) UpdateServiceReg(reg *model.ServiceReg) error {
	filter := bson.M{"registration.service_id": reg.Registration.ServiceID}
	err := sa.db.serviceRegs.ReplaceOne(filter, reg, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionInsert, model.TypeServiceReg, &logutils.FieldArgs{"service_id": reg.Registration.ServiceID}, err)
	}

	return nil
}

//SaveServiceReg saves the service registration to the storage
func (sa *Adapter) SaveServiceReg(reg *model.ServiceReg) error {
	filter := bson.M{"registration.service_id": reg.Registration.ServiceID}
	opts := options.Replace().SetUpsert(true)
	err := sa.db.serviceRegs.ReplaceOne(filter, reg, opts)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionSave, model.TypeServiceReg, &logutils.FieldArgs{"service_id": reg.Registration.ServiceID}, err)
	}

	return nil
}

//DeleteServiceReg deletes the service registration from storage
func (sa *Adapter) DeleteServiceReg(serviceID string) error {
	filter := bson.M{"registration.service_id": serviceID}
	result, err := sa.db.serviceRegs.DeleteOne(filter, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeServiceReg, &logutils.FieldArgs{"service_id": serviceID}, err)
	}
	if result == nil {
		return errors.WrapErrorData(logutils.StatusInvalid, "result", &logutils.FieldArgs{"service_id": serviceID}, err)
	}
	deletedCount := result.DeletedCount
	if deletedCount == 0 {
		return errors.WrapErrorData(logutils.StatusMissing, model.TypeServiceReg, &logutils.FieldArgs{"service_id": serviceID}, err)
	}

	return nil
}

//FindServiceAuthorization finds the service authorization in storage
func (sa *Adapter) FindServiceAuthorization(userID string, serviceID string) (*model.ServiceAuthorization, error) {
	filter := bson.M{"user_id": userID, "service_id": serviceID}
	var reg *model.ServiceAuthorization
	err := sa.db.serviceAuthorizations.FindOne(filter, &reg, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeServiceAuthorization, &logutils.FieldArgs{"user_id": userID, "service_id": serviceID}, err)
	}

	return reg, nil
}

//SaveServiceAuthorization saves the service authorization to storage
func (sa *Adapter) SaveServiceAuthorization(authorization *model.ServiceAuthorization) error {
	filter := bson.M{"user_id": authorization.UserID, "service_id": authorization.ServiceID}
	opts := options.Replace().SetUpsert(true)
	err := sa.db.serviceAuthorizations.ReplaceOne(filter, authorization, opts)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionSave, model.TypeServiceAuthorization, &logutils.FieldArgs{"user_id": authorization.UserID, "service_id": authorization.ServiceID}, err)
	}

	return nil
}

//DeleteServiceAuthorization deletes the service authorization from storage
func (sa *Adapter) DeleteServiceAuthorization(userID string, serviceID string) error {
	filter := bson.M{"user_id": userID, "service_id": serviceID}
	result, err := sa.db.serviceAuthorizations.DeleteOne(filter, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeServiceAuthorization, &logutils.FieldArgs{"user_id": userID, "service_id": serviceID}, err)
	}
	if result == nil {
		return errors.WrapErrorData(logutils.StatusInvalid, "result", &logutils.FieldArgs{"user_id": userID, "service_id": serviceID}, err)
	}
	deletedCount := result.DeletedCount
	if deletedCount == 0 {
		return errors.WrapErrorData(logutils.StatusMissing, model.TypeServiceAuthorization, &logutils.FieldArgs{"user_id": userID, "service_id": serviceID}, err)
	}

	return nil
}

//SaveDevice saves device
func (sa *Adapter) SaveDevice(device *model.Device, context mongo.SessionContext) error {
	if device == nil {
		return errors.ErrorData(logutils.StatusInvalid, logutils.TypeArg, logutils.StringArgs("device"))
	}

	storageDevice := deviceToStorage(device)

	var err error
	filter := bson.M{"_id": device.ID}
	opts := options.Replace().SetUpsert(true)
	if context == nil {
		err = sa.db.devices.ReplaceOne(filter, storageDevice, opts)
	} else {
		err = sa.db.devices.ReplaceOneWithContext(context, filter, storageDevice, opts)
	}

	if err != nil {
		return errors.WrapErrorAction(logutils.ActionSave, "device", &logutils.FieldArgs{"device_id": device.ID}, nil)
	}

	return nil
}

func (sa *Adapter) abortTransaction(sessionContext mongo.SessionContext) {
	err := sessionContext.AbortTransaction(sessionContext)
	if err != nil {
		sa.logger.Errorf("error aborting a transaction - %s", err)
	}
}

//NewStorageAdapter creates a new storage adapter instance
func NewStorageAdapter(mongoDBAuth string, mongoDBName string, mongoTimeout string, logger *logs.Logger) *Adapter {
	timeoutInt, err := strconv.Atoi(mongoTimeout)
	if err != nil {
		logger.Warn("Setting default Mongo timeout - 500")
		timeoutInt = 500
	}
	timeout := time.Millisecond * time.Duration(timeoutInt)

	cachedOrganizations := &syncmap.Map{}
	organizationsLock := &sync.RWMutex{}

	db := &database{mongoDBAuth: mongoDBAuth, mongoDBName: mongoDBName, mongoTimeout: timeout, logger: logger}
	return &Adapter{db: db, logger: logger, cachedOrganizations: cachedOrganizations, organizationsLock: organizationsLock}
}

type storageListener struct {
	adapter *Adapter
	DefaultListenerImpl
}

func (sl *storageListener) OnOrganizationsUpdated() {
	sl.adapter.cacheOrganizations()
}

func (sl *storageListener) OnApplicationsUpdated() {
	sl.adapter.cacheOrganizations()
}

//Listener represents storage listener
type Listener interface {
	OnAuthConfigUpdated()
	OnServiceRegsUpdated()
	OnOrganizationsUpdated()
	OnApplicationsUpdated()
}

//DefaultListenerImpl default listener implementation
type DefaultListenerImpl struct{}

//OnAuthConfigUpdated notifies auth configs have been updated
func (d *DefaultListenerImpl) OnAuthConfigUpdated() {}

//OnServiceRegsUpdated notifies services regs have been updated
func (d *DefaultListenerImpl) OnServiceRegsUpdated() {}

//OnOrganizationsUpdated notifies organizations have been updated
func (d *DefaultListenerImpl) OnOrganizationsUpdated() {}

//OnApplicationsUpdated notifies applications have been updated
func (d *DefaultListenerImpl) OnApplicationsUpdated() {}
