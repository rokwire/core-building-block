package storage

import (
	"context"
	"core-building-block/core/model"
	"strconv"
	"sync"
	"time"

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

	cachedApplications *syncmap.Map
	applicationsLock   *sync.RWMutex
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

	//cache the applications
	err = sa.cacheApplications()
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionCache, model.TypeApplication, nil, err)
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

	organizations, err := sa.LoadOrganizations()
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeOrganization, nil, err)
	}

	sa.setCachedOrganizations(&organizations)

	return nil
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
		} else {
			sa.logger.Errorf("failed to validate and cache organization with org_id %s: %s", org.ID, err.Error())
		}
	}
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
	return nil, errors.ErrorData(logutils.StatusMissing, model.TypeOrganization, errArgs)
}

func (sa *Adapter) getCachedOrganizations() ([]model.Organization, error) {
	sa.organizationsLock.RLock()
	defer sa.organizationsLock.RUnlock()

	var err error
	organizationList := make([]model.Organization, 0)
	sa.cachedOrganizations.Range(func(key, item interface{}) bool {
		errArgs := &logutils.FieldArgs{"org_id": key}
		if item == nil {
			err = errors.ErrorData(logutils.StatusInvalid, model.TypeOrganization, errArgs)
			return false
		}

		organization, ok := item.(model.Organization)
		if !ok {
			err = errors.ErrorAction(logutils.ActionCast, model.TypeOrganization, errArgs)
			return false
		}
		organizationList = append(organizationList, organization)
		return true
	})

	return organizationList, err
}

//cacheApplications caches the applications
func (sa *Adapter) cacheApplications() error {
	sa.logger.Info("cacheApplications..")

	applications, err := sa.LoadApplications()
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeApplication, nil, err)
	}

	sa.setCachedApplications(&applications)

	return nil
}

func (sa *Adapter) setCachedApplications(applications *[]model.Application) {
	sa.applicationsLock.Lock()
	defer sa.applicationsLock.Unlock()

	sa.cachedApplications = &syncmap.Map{}
	validate := validator.New()

	for _, app := range *applications {
		err := validate.Struct(app)
		if err == nil {
			sa.cachedApplications.Store(app.ID, app)
		} else {
			sa.logger.Errorf("failed to validate and cache application with id %s: %s", app.ID, err.Error())
		}
	}
}

func (sa *Adapter) getCachedApplication(appID string) (*model.Application, error) {
	sa.applicationsLock.RLock()
	defer sa.applicationsLock.RUnlock()

	errArgs := &logutils.FieldArgs{"app_id": appID}

	item, _ := sa.cachedApplications.Load(appID)
	if item != nil {
		application, ok := item.(model.Application)
		if !ok {
			return nil, errors.ErrorAction(logutils.ActionCast, model.TypeApplication, errArgs)
		}
		return &application, nil
	}
	return nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplication, errArgs)
}

func (sa *Adapter) getCachedApplicationTypeByIdentifier(appTypeIdentifier string) (*model.Application, *model.ApplicationType, error) {
	sa.applicationsLock.RLock()
	defer sa.applicationsLock.RUnlock()

	var app *model.Application
	var appType *model.ApplicationType

	sa.cachedApplications.Range(func(key, value interface{}) bool {
		application, ok := value.(model.Application)
		if !ok {
			return false //break the iteration
		}

		applicationType := application.FindApplicationType(appTypeIdentifier)
		if applicationType != nil {
			app = &application
			appType = applicationType
			return false //break the iteration
		}

		// this will continue iterating
		return true
	})

	if app != nil && appType != nil {
		return app, appType, nil
	}

	return nil, nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationType, &logutils.FieldArgs{"identifier": appTypeIdentifier})
}

//LoadAuthTypes loads all auth types
func (sa *Adapter) LoadAuthTypes() ([]model.AuthType, error) {
	filter := bson.D{}
	var result []model.AuthType
	err := sa.db.authTypes.Find(filter, &result, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAuthType, nil, err)
	}
	if len(result) == 0 {
		return nil, errors.WrapErrorData(logutils.StatusMissing, model.TypeAuthType, nil, err)
	}

	return result, nil
}

//FindUser finds an user for app, auth type and auth type identifier
func (sa *Adapter) FindUser(appID string, authTypeID string, authTypeIdentifier string) (*model.User, error) {
	filter := bson.D{primitive.E{Key: "applications_accounts.app_id", Value: appID},
		primitive.E{Key: "applications_accounts.auth_types.auth_type_id", Value: authTypeID},
		primitive.E{Key: "applications_accounts.auth_types.params.identifier", Value: authTypeIdentifier}}
	var users []user
	err := sa.db.users.Find(filter, &users, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeUser, nil, err)
	}
	if len(users) == 0 {
		//not found
		return nil, nil
	}
	user := users[0]
	modelUser := userFromStorage(&user, sa)
	return &modelUser, nil
}

//FindUserByID finds an user by id
func (sa *Adapter) FindUserByID(id string) (*model.User, error) {
	return sa.findUser("_id", id)
}

func (sa *Adapter) findUser(key string, id string) (*model.User, error) {
	filter := bson.M{key: id}
	var users []user
	err := sa.db.users.Find(filter, &users, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeUser, nil, err)
	}
	if len(users) == 0 {
		//not found
		return nil, nil
	}

	user := users[0]

	modelUser := userFromStorage(&user, sa)
	return &modelUser, nil
}

//InsertUser inserts a user
func (sa *Adapter) InsertUser(user model.User) (*model.User, error) {
	storageUser := userToStorage(&user)

	_, err := sa.db.users.InsertOne(storageUser)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionInsert, model.TypeUser, nil, err)
	}

	return &user, nil
	/*
		if user == nil {
			return nil, errors.ErrorData(logutils.StatusInvalid, logutils.TypeArg, logutils.StringArgs(model.TypeUser))
		}

		storageUser := userToStorage(user)
		membership := storageUser.OrganizationsMemberships[0]
		organizationMembership := organizationMembership{ID: membership.ID, UserID: user.ID, OrgID: membership.OrgID,
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
			authCred.DateCreated = time.Now().UTC()
			err = sa.InsertCredentials(authCred, sessionContext)
			if err != nil {
				sa.abortTransaction(sessionContext)
				return errors.WrapErrorData(logutils.StatusInvalid, model.TypeAuthCred, &logutils.FieldArgs{"user_id": storageUser.Account.Username, "account_id": storageUser.Account.ID}, err)
			}

			err = sa.InsertMembership(&organizationMembership, sessionContext)
			if err != nil {
				sa.abortTransaction(sessionContext)
				return errors.WrapErrorAction(logutils.ActionInsert, model.TypeOrganizationMembership, nil, err)
			}

			//TODO: only save if device info has changed or it is new device
			err = sa.SaveDevice(&user.Devices[0], sessionContext)
			if err != nil {
				sa.abortTransaction(sessionContext)
				return errors.WrapErrorAction(logutils.ActionSave, "device", nil, err)
			}

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
	*/
}

//UpdateUser updates an existing user
func (sa *Adapter) UpdateUser(updatedUser *model.User, orgID string, newOrgData *map[string]interface{}) (*model.User, error) {
	return nil, nil
	/*if updatedUser == nil {
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
	*/
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

//UpdateUserAuthType updates user auth type
func (sa *Adapter) UpdateUserAuthType(item model.UserAuthType) error {

	//1. first find the user record

	//2. find the user auth type

	//3. update the user auth type

	//4. set the updated user auth type to the user

	//5. update the user record
	return nil
}

//FindCredentialsByID finds a set of credentials by ID
func (sa *Adapter) FindCredentialsByID(ID string) (*model.AuthCreds, error) {
	filter := bson.D{primitive.E{Key: "_id", Value: ID}}

	var creds model.AuthCreds
	err := sa.db.credentials.FindOne(filter, &creds, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAuthCred, nil, err)
	}

	return &creds, nil
}

//FindCredentials find a set of credentials
func (sa *Adapter) FindCredentials(orgID string, authType string, params map[string]interface{}) (*model.AuthCreds, error) {
	filter := bson.D{primitive.E{Key: "org_id", Value: orgID}, primitive.E{Key: "auth_type", Value: authType}}
	for k, v := range params {
		filter = append(filter, primitive.E{Key: "creds." + k, Value: v})
	}

	var creds model.AuthCreds
	err := sa.db.credentials.FindOne(filter, &creds, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAuthCred, nil, err)
	}

	return &creds, nil
}

//InsertCredentials inserts a set of credentials
func (sa *Adapter) InsertCredentials(creds *model.AuthCreds, context mongo.SessionContext) error {
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

//FindRefreshToken finds a refresh token
func (sa *Adapter) FindRefreshToken(token string) (*model.AuthRefresh, error) {
	conditions := []bson.M{{"current_token": token}, {"previous_token": token}}
	filter := bson.M{"$or": conditions}

	var refresh model.AuthRefresh
	err := sa.db.refreshTokens.FindOne(filter, &refresh, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAuthRefresh, nil, err)
	}

	return &refresh, nil
}

//LoadRefreshTokens loads refresh tokens by an ID triple
func (sa *Adapter) LoadRefreshTokens(orgID string, appID string, credsID string) ([]model.AuthRefresh, error) {
	filter := bson.D{primitive.E{Key: "org_id", Value: orgID}, primitive.E{Key: "app_id", Value: appID}, primitive.E{Key: "creds_id", Value: credsID}}
	opts := options.Find().SetSort(bson.D{primitive.E{Key: "exp", Value: 1}})

	var refresh []model.AuthRefresh
	err := sa.db.refreshTokens.Find(filter, &refresh, opts)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAuthRefresh, nil, err)
	}

	return refresh, nil
}

//InsertRefreshToken inserts a refresh token
func (sa *Adapter) InsertRefreshToken(refresh *model.AuthRefresh) error {
	if refresh == nil {
		return errors.ErrorData(logutils.StatusInvalid, model.TypeAuthRefresh, nil)
	}

	_, err := sa.db.refreshTokens.InsertOne(refresh)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionInsert, model.TypeAuthRefresh, nil, err)
	}

	return nil
}

//UpdateRefreshToken updates a refresh token
func (sa *Adapter) UpdateRefreshToken(token string, refresh *model.AuthRefresh) error {
	filter := bson.D{primitive.E{Key: "current_token", Value: token}}
	update := bson.D{
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "previous_token", Value: refresh.PreviousToken},
			primitive.E{Key: "current_token", Value: refresh.CurrentToken},
			primitive.E{Key: "exp", Value: refresh.Expires},
			primitive.E{Key: "params", Value: refresh.Params},
			primitive.E{Key: "date_updated", Value: refresh.DateUpdated},
		}},
	}

	res, err := sa.db.refreshTokens.UpdateOne(filter, update, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeAuthRefresh, nil, err)
	}
	if res.ModifiedCount != 1 {
		return errors.ErrorAction(logutils.ActionUpdate, model.TypeAuthRefresh, logutils.StringArgs("unexpected modified count"))
	}

	return nil
}

//DeleteRefreshToken updates a refresh token
func (sa *Adapter) DeleteRefreshToken(token string) error {
	filter := bson.D{primitive.E{Key: "current_token", Value: token}}

	res, err := sa.db.refreshTokens.DeleteOne(filter, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeAuthRefresh, nil, err)
	}
	if res.DeletedCount != 1 {
		return errors.ErrorAction(logutils.ActionDelete, model.TypeAuthRefresh, logutils.StringArgs("unexpected deleted count"))
	}

	return nil
}

//DeleteExpiredRefreshTokens deletes expired refresh tokens
func (sa *Adapter) DeleteExpiredRefreshTokens(now *time.Time) error {
	filter := bson.M{"exp": bson.M{"$lte": now}}

	_, err := sa.db.refreshTokens.DeleteMany(filter, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeAuthRefresh, &logutils.FieldArgs{"exp": now}, err)
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

//UpdateGlobalPermission updates global permission
func (sa *Adapter) UpdateGlobalPermission(item model.GlobalPermission) error {
	//TODO
	//This will be slow operation as we keep a copy of the entity in the users collection without index.
	//Maybe we need to up the transaction timeout for this operation because of this.
	return errors.New(logutils.Unimplemented)
}

//DeleteGlobalPermission deletes global permission
func (sa *Adapter) DeleteGlobalPermission(id string) error {
	//TODO
	//This will be slow operation as we keep a copy of the entity in the users collection without index.
	//Maybe we need to up the transaction timeout for this operation because of this.
	return errors.New(logutils.Unimplemented)
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

//UpdateGlobalRole updates global role
func (sa *Adapter) UpdateGlobalRole(item model.GlobalRole) error {
	//TODO
	//This will be slow operation as we keep a copy of the entity in the users collection without index.
	//Maybe we need to up the transaction timeout for this operation because of this.
	return errors.New(logutils.Unimplemented)
}

//DeleteGlobalRole deletes global role
func (sa *Adapter) DeleteGlobalRole(id string) error {
	//TODO
	//This will be slow operation as we keep a copy of the entity in the users collection without index.
	//Maybe we need to up the transaction timeout for this operation because of this.
	return errors.New(logutils.Unimplemented)
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

//UpdateGlobalGroup updates global group
func (sa *Adapter) UpdateGlobalGroup(item model.GlobalGroup) error {
	//TODO
	//This will be slow operation as we keep a copy of the entity in the users collection without index.
	//Maybe we need to up the transaction timeout for this operation because of this.
	return errors.New(logutils.Unimplemented)
}

//DeleteGlobalGroup deletes global group
func (sa *Adapter) DeleteGlobalGroup(id string) error {
	//TODO
	//This will be slow operation as we keep a copy of the entity in the users collection without index.
	//Maybe we need to up the transaction timeout for this operation because of this.
	return errors.New(logutils.Unimplemented)
}

//FindApplicationPermissions finds a set of application permissions
func (sa *Adapter) FindApplicationPermissions(ids []string, appID string) ([]model.ApplicationPermission, error) {
	permissionsFilter := bson.D{primitive.E{Key: "app_id", Value: appID}, primitive.E{Key: "_id", Value: bson.M{"$in": ids}}}
	var permissionsResult []applicationPermission
	err := sa.db.applicationsPermissions.Find(permissionsFilter, &permissionsResult, nil)
	if err != nil {
		return nil, err
	}

	//get the application from the cached ones
	application, err := sa.getCachedApplication(appID)
	if err != nil {
		return nil, errors.WrapErrorData(logutils.StatusMissing, model.TypeOrganization, &logutils.FieldArgs{"app_id": application}, err)
	}

	result := applicationPermissionsFromStorage(permissionsResult, *application)

	return result, nil
}

//UpdateApplicationPermission updates application permission
func (sa *Adapter) UpdateApplicationPermission(item model.ApplicationPermission) error {
	//TODO
	//This will be slow operation as we keep a copy of the entity in the users collection without index.
	//Maybe we need to up the transaction timeout for this operation because of this.
	return errors.New(logutils.Unimplemented)
}

//DeleteApplicationPermission deletes application permission
func (sa *Adapter) DeleteApplicationPermission(id string) error {
	//TODO
	//This will be slow operation as we keep a copy of the entity in the users collection without index.
	//Maybe we need to up the transaction timeout for this operation because of this.
	return errors.New(logutils.Unimplemented)
}

//FindApplicationRoles finds a set of application roles
func (sa *Adapter) FindApplicationRoles(ids []string, appID string) ([]model.ApplicationRole, error) {
	rolesFilter := bson.D{primitive.E{Key: "app_id", Value: appID}, primitive.E{Key: "_id", Value: bson.M{"$in": ids}}}
	var rolesResult []applicationRole
	err := sa.db.applicationsRoles.Find(rolesFilter, &rolesResult, nil)
	if err != nil {
		return nil, err
	}

	//get the application from the cached ones
	application, err := sa.getCachedApplication(appID)
	if err != nil {
		return nil, errors.WrapErrorData(logutils.StatusMissing, model.TypeOrganization, &logutils.FieldArgs{"app_id": application}, err)
	}

	result := applicationRolesFromStorage(rolesResult, *application)

	return result, nil
}

//UpdateApplicationRole updates application role
func (sa *Adapter) UpdateApplicationRole(item model.ApplicationRole) error {
	//TODO
	//This will be slow operation as we keep a copy of the entity in the users collection without index.
	//Maybe we need to up the transaction timeout for this operation because of this.
	return errors.New(logutils.Unimplemented)
}

//DeleteApplicationRole deletes application role
func (sa *Adapter) DeleteApplicationRole(id string) error {
	//TODO
	//This will be slow operation as we keep a copy of the entity in the users collection without index.
	//Maybe we need to up the transaction timeout for this operation because of this.
	return errors.New(logutils.Unimplemented)
}

//FindApplicationGroups finds a set of application groups
func (sa *Adapter) FindApplicationGroups(ids []string, appID string) ([]model.ApplicationGroup, error) {
	filter := bson.D{primitive.E{Key: "app_id", Value: appID}, primitive.E{Key: "_id", Value: bson.M{"$in": ids}}}
	var groupsResult []applicationGroup
	err := sa.db.applicationsGroups.Find(filter, &groupsResult, nil)
	if err != nil {
		return nil, err
	}

	application, err := sa.getCachedApplication(appID)
	if err != nil {
		return nil, errors.WrapErrorData(logutils.StatusMissing, model.TypeOrganization, &logutils.FieldArgs{"app_id": application}, err)
	}

	result := applicationGroupsFromStorage(groupsResult, *application)

	return result, nil
}

//UpdateApplicationGroup updates application group
func (sa *Adapter) UpdateApplicationGroup(item model.ApplicationGroup) error {
	//TODO
	//This will be slow operation as we keep a copy of the entity in the users collection without index.
	//Maybe we need to up the transaction timeout for this operation because of this.
	return errors.New(logutils.Unimplemented)
}

//DeleteApplicationGroup deletes application group
func (sa *Adapter) DeleteApplicationGroup(id string) error {
	//TODO
	//This will be slow operation as we keep a copy of the entity in the users collection without index.
	//Maybe we need to up the transaction timeout for this operation because of this.
	return errors.New(logutils.Unimplemented)
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

//LoadIdentityProviders finds all identity providers documents in the DB
func (sa *Adapter) LoadIdentityProviders() ([]model.IdentityProvider, error) {
	filter := bson.D{}
	var result []model.IdentityProvider
	err := sa.db.identityProviders.Find(filter, &result, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeIdentityProvider, nil, err)
	}
	if len(result) == 0 {
		return nil, errors.WrapErrorData(logutils.StatusMissing, model.TypeIdentityProvider, nil, err)
	}

	return result, nil
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
	cachedOrg, err := sa.getCachedOrganization(id)
	if cachedOrg != nil && err == nil {
		return cachedOrg, nil
	}
	sa.logger.Warn(err.Error())

	//1. find organization
	orgFilter := bson.D{primitive.E{Key: "_id", Value: id}}
	var org organization

	err = sa.db.organizations.FindOne(orgFilter, &org, nil)
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
func (sa *Adapter) UpdateOrganization(ID string, name string, requestType string, organizationDomains []string) error {

	now := time.Now()
	//TODO - use pointers and update only what not nil
	updatOrganizationFilter := bson.D{primitive.E{Key: "_id", Value: ID}}
	updateOrganization := bson.D{
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "name", Value: name},
			primitive.E{Key: "type", Value: requestType},
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

//LoadOrganizations gets the organizations
func (sa *Adapter) LoadOrganizations() ([]model.Organization, error) {
	//no transactions for get operations..
	cachedOrgs, err := sa.getCachedOrganizations()
	if err != nil {
		sa.logger.Warn(err.Error())
	} else if len(cachedOrgs) > 0 {
		return cachedOrgs, nil
	}

	//1. find the organizations
	orgsFilter := bson.D{}
	var orgsResult []organization
	err = sa.db.organizations.Find(orgsFilter, &orgsResult, nil)
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

//LoadApplications loads all applications
func (sa *Adapter) LoadApplications() ([]model.Application, error) {
	filter := bson.D{}
	var result []model.Application
	err := sa.db.applications.Find(filter, &result, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplication, nil, err)
	}
	if len(result) == 0 {
		return nil, errors.WrapErrorData(logutils.StatusMissing, model.TypeApplication, nil, err)
	}

	return result, nil
}

//InsertApplication inserts an application
func (sa *Adapter) InsertApplication(application model.Application) (*model.Application, error) {
	_, err := sa.db.applications.InsertOne(application)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionInsert, model.TypeApplication, &logutils.FieldArgs{"id": application.ID}, err)
	}

	return &application, nil
}

//FindApplication finds application
func (sa *Adapter) FindApplication(ID string) (*model.Application, error) {
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
	return &appRes, nil
}

//FindApplications finds applications
func (sa *Adapter) FindApplications() ([]model.Application, error) {
	filter := bson.D{}
	var result []model.Application
	err := sa.db.applications.Find(filter, &result, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplication, nil, err)
	}

	if len(result) == 0 {
		//no data
		return make([]model.Application, 0), nil
	}

	return result, nil
}

//FindApplicationTypeByIdentifier finds an application type by identifier
func (sa *Adapter) FindApplicationTypeByIdentifier(identifier string) (*model.ApplicationType, error) {
	app, appType, err := sa.getCachedApplicationTypeByIdentifier(identifier)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationType, nil, err)
	}

	appType.Application = *app

	return appType, nil
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

	cachedApplications := &syncmap.Map{}
	applicationsLock := &sync.RWMutex{}

	db := &database{mongoDBAuth: mongoDBAuth, mongoDBName: mongoDBName, mongoTimeout: timeout, logger: logger}
	return &Adapter{db: db, logger: logger, cachedOrganizations: cachedOrganizations, organizationsLock: organizationsLock,
		cachedApplications: cachedApplications, applicationsLock: applicationsLock}
}

type storageListener struct {
	adapter *Adapter
	DefaultListenerImpl
}

func (sl *storageListener) OnOrganizationsUpdated() {
	sl.adapter.cacheOrganizations()
}

func (sl *storageListener) OnApplicationsUpdated() {
	sl.adapter.cacheApplications()
	sl.adapter.cacheOrganizations()
}

//Listener represents storage listener
type Listener interface {
	OnAuthTypesUpdated()
	OnIdentityProvidersUpdated()
	OnServiceRegsUpdated()
	OnOrganizationsUpdated()
	OnApplicationsUpdated()
}

//DefaultListenerImpl default listener implementation
type DefaultListenerImpl struct{}

//OnAuthTypesUpdated notifies auth types have been updated
func (d *DefaultListenerImpl) OnAuthTypesUpdated() {}

//OnIdentityProvidersUpdated notifies identity providers have been updated
func (d *DefaultListenerImpl) OnIdentityProvidersUpdated() {}

//OnServiceRegsUpdated notifies services regs have been updated
func (d *DefaultListenerImpl) OnServiceRegsUpdated() {}

//OnOrganizationsUpdated notifies organizations have been updated
func (d *DefaultListenerImpl) OnOrganizationsUpdated() {}

//OnApplicationsUpdated notifies applications have been updated
func (d *DefaultListenerImpl) OnApplicationsUpdated() {}
