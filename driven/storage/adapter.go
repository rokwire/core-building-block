package storage

import (
	"context"
	"core-building-block/core/model"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
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

	cachedAuthTypes *syncmap.Map
	authTypesLock   *sync.RWMutex

	cachedApplicationsOrganizations *syncmap.Map //cache applications organizations
	applicationsOrganizationsLock   *sync.RWMutex
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

	//cache the auth types
	err = sa.cacheAuthTypes()
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionCache, model.TypeAuthType, nil, err)
	}

	//cache the application organization
	err = sa.cacheApplicationsOrganizations()
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionCache, model.TypeApplicationOrganization, nil, err)
	}

	return err
}

//RegisterStorageListener registers a data change listener with the storage adapter
func (sa *Adapter) RegisterStorageListener(storageListener Listener) {
	sa.db.listeners = append(sa.db.listeners, storageListener)
}

//PerformTransaction performs a transaction
func (sa *Adapter) PerformTransaction(transaction func(context TransactionContext) error) error {
	// transaction
	err := sa.db.dbClient.UseSession(context.Background(), func(sessionContext mongo.SessionContext) error {
		err := sessionContext.StartTransaction()
		if err != nil {
			sa.abortTransaction(sessionContext)
			return errors.WrapErrorAction(logutils.ActionStart, logutils.TypeTransaction, nil, err)
		}

		err = transaction(sessionContext)
		if err != nil {
			sa.abortTransaction(sessionContext)
			return errors.WrapErrorAction("performing", logutils.TypeTransaction, nil, err)
		}

		err = sessionContext.CommitTransaction(sessionContext)
		if err != nil {
			sa.abortTransaction(sessionContext)
			return errors.WrapErrorAction(logutils.ActionCommit, logutils.TypeTransaction, nil, err)
		}
		return nil
	})

	return err
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

//cacheAuthTypes caches the auth types
func (sa *Adapter) cacheAuthTypes() error {
	sa.logger.Info("cacheAuthTypes..")

	authTypes, err := sa.LoadAuthTypes()
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeAuthType, nil, err)
	}
	sa.setCachedAuthTypes(authTypes)

	return nil
}

func (sa *Adapter) setCachedAuthTypes(authProviders []model.AuthType) {
	sa.authTypesLock.Lock()
	defer sa.authTypesLock.Unlock()

	sa.cachedAuthTypes = &syncmap.Map{}
	validate := validator.New()

	for _, authType := range authProviders {
		err := validate.Struct(authType)
		if err == nil {
			//we will get it by id and code as well
			sa.cachedAuthTypes.Store(authType.ID, authType)
			sa.cachedAuthTypes.Store(authType.Code, authType)
		} else {
			sa.logger.Errorf("failed to validate and cache auth type with code %s: %s", authType.Code, err.Error())
		}
	}
}

func (sa *Adapter) getCachedAuthType(key string) (*model.AuthType, error) {
	sa.authTypesLock.RLock()
	defer sa.authTypesLock.RUnlock()

	errArgs := &logutils.FieldArgs{"code or id": key}

	item, _ := sa.cachedAuthTypes.Load(key)
	if item != nil {
		authType, ok := item.(model.AuthType)
		if !ok {
			return nil, errors.ErrorAction(logutils.ActionCast, model.TypeAuthType, errArgs)
		}
		return &authType, nil
	}
	return nil, errors.ErrorData(logutils.StatusMissing, model.TypeAuthType, errArgs)
}

//cacheApplicationsOrganizations caches the applications organizations
func (sa *Adapter) cacheApplicationsOrganizations() error {
	sa.logger.Info("cacheApplicationsOrganizations..")

	applicationsOrganizations, err := sa.LoadApplicationsOrganizations()
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationOrganization, nil, err)
	}

	sa.setCachedApplicationsOrganizations(applicationsOrganizations)
	return nil
}

func (sa *Adapter) setCachedApplicationsOrganizations(applicationsOrganization []model.ApplicationOrganization) {
	sa.applicationsOrganizationsLock.Lock()
	defer sa.applicationsOrganizationsLock.Unlock()

	sa.cachedApplicationsOrganizations = &syncmap.Map{}
	validate := validator.New()

	for _, appOrg := range applicationsOrganization {
		err := validate.Struct(appOrg)
		if err == nil {
			//key 1 - appID_orgID
			key := fmt.Sprintf("%s_%s", appOrg.Application.ID, appOrg.Organization.ID)
			sa.cachedApplicationsOrganizations.Store(key, appOrg)

			//key 2 - app_org_id
			sa.cachedApplicationsOrganizations.Store(appOrg.ID, appOrg)
		} else {
			sa.logger.Errorf("failed to validate and cache applications organizations with ids %s-%s: %s",
				appOrg.Application.ID, appOrg.Organization.ID, err.Error())
		}
	}
}

func (sa *Adapter) getCachedApplicationOrganization(appID string, orgID string) (*model.ApplicationOrganization, error) {
	key := fmt.Sprintf("%s_%s", appID, orgID)
	return sa.getCachedApplicationOrganizationByKey(key)
}

func (sa *Adapter) getCachedApplicationOrganizationByKey(key string) (*model.ApplicationOrganization, error) {
	sa.applicationsOrganizationsLock.RLock()
	defer sa.applicationsOrganizationsLock.RUnlock()

	errArgs := &logutils.FieldArgs{"key": key}

	item, _ := sa.cachedApplicationsOrganizations.Load(key)
	if item != nil {
		appOrg, ok := item.(model.ApplicationOrganization)
		if !ok {
			return nil, errors.ErrorAction(logutils.ActionCast, model.TypeApplicationOrganization, errArgs)
		}
		return &appOrg, nil
	}
	return nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationOrganization, errArgs)
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

//FindAuthType finds auth type by id or code
func (sa *Adapter) FindAuthType(codeOrID string) (*model.AuthType, error) {
	return sa.getCachedAuthType(codeOrID)
}

//InsertLoginSession inserts login session
func (sa *Adapter) InsertLoginSession(context TransactionContext, session model.LoginSession) error {
	storageLoginSession := loginSessionToStorage(session)

	var err error
	if context != nil {
		_, err = sa.db.loginsSessions.InsertOneWithContext(context, storageLoginSession)
	} else {
		_, err = sa.db.loginsSessions.InsertOne(storageLoginSession)
	}

	if err != nil {
		return errors.WrapErrorAction(logutils.ActionInsert, model.TypeLoginSession, nil, err)
	}

	return nil
}

//FindLoginSessions finds login sessions by identifier and sorts by expiration
func (sa *Adapter) FindLoginSessions(context TransactionContext, identifier string) ([]model.LoginSession, error) {
	filter := bson.D{primitive.E{Key: "identifier", Value: identifier}}
	opts := options.Find()
	opts.SetSort(bson.D{primitive.E{Key: "expires", Value: 1}})

	var loginSessions []loginSession
	var err error
	if context != nil {
		err = sa.db.loginsSessions.FindWithContext(context, filter, &loginSessions, opts)
	} else {
		err = sa.db.loginsSessions.Find(filter, &loginSessions, opts)
	}

	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeLoginSession, &logutils.FieldArgs{"identifier": identifier}, err)
	}

	//account - from storage
	account, err := sa.FindAccountByID(context, identifier)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, &logutils.FieldArgs{"_id": identifier}, err)
	}

	sessions := make([]model.LoginSession, len(loginSessions))
	for i, session := range loginSessions {
		//auth type - from cache
		authType, err := sa.getCachedAuthType(session.AuthTypeCode)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAuthType, &logutils.FieldArgs{"code": session.AuthTypeCode}, err)
		}

		//application organization - from cache
		appOrg, err := sa.getCachedApplicationOrganization(session.AppID, session.OrgID)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationOrganization, &logutils.FieldArgs{"app_id": session.AppID, "org_id": session.OrgID}, err)
		}

		sessions[i] = loginSessionFromStorage(session, *authType, account, *appOrg)
	}

	return sessions, nil
}

//FindLoginSession finds a login session
func (sa *Adapter) FindLoginSession(refreshToken string) (*model.LoginSession, error) {
	//find loggin session
	filter := bson.D{primitive.E{Key: "refresh_tokens", Value: refreshToken}}
	var loginsSessions []loginSession
	err := sa.db.loginsSessions.Find(filter, &loginsSessions, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeLoginSession, nil, err)
	}
	if len(loginsSessions) == 0 {
		//not found
		return nil, nil
	}
	loginSession := loginsSessions[0]

	return sa.buildLoginSession(&loginSession)
}

//FindAndUpdateLoginSession finds and updates a login session
func (sa *Adapter) FindAndUpdateLoginSession(context TransactionContext, id string) (*model.LoginSession, error) {
	//find loggin session
	filter := bson.D{primitive.E{Key: "_id", Value: id}}
	update := bson.D{
		primitive.E{Key: "$inc", Value: bson.D{
			primitive.E{Key: "mfa_attempts", Value: 1},
		}},
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "date_updated", Value: time.Now().UTC()},
		}},
	}
	opts := options.FindOneAndUpdateOptions{}
	opts.SetReturnDocument(options.Before)

	var loginSession loginSession
	var err error
	if context != nil {
		err = sa.db.loginsSessions.FindOneAndUpdateWithContext(context, filter, update, &loginSession, &opts)
	} else {
		err = sa.db.loginsSessions.FindOneAndUpdate(filter, update, &loginSession, &opts)
	}

	if err != nil {
		return nil, errors.WrapErrorAction("finding and updating", model.TypeLoginSession, &logutils.FieldArgs{"_id": id}, err)
	}

	return sa.buildLoginSession(&loginSession)
}

func (sa *Adapter) buildLoginSession(ls *loginSession) (*model.LoginSession, error) {
	//account - from storage
	var account *model.Account
	var err error
	if ls.AccountAuthTypeID != nil {
		account, err = sa.FindAccountByID(nil, ls.Identifier)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, &logutils.FieldArgs{"_id": ls.Identifier}, err)
		}
	}

	//auth type - from cache
	authType, err := sa.getCachedAuthType(ls.AuthTypeCode)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAuthType, &logutils.FieldArgs{"code": ls.AuthTypeCode}, err)
	}

	//application organization - from cache
	appOrg, err := sa.getCachedApplicationOrganization(ls.AppID, ls.OrgID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationOrganization, &logutils.FieldArgs{"app_id": ls.AppID, "org_id": ls.OrgID}, err)
	}

	modelLoginSession := loginSessionFromStorage(*ls, *authType, account, *appOrg)
	return &modelLoginSession, nil
}

//UpdateLoginSession updates login session
func (sa *Adapter) UpdateLoginSession(context TransactionContext, loginSession model.LoginSession) error {
	storageLoginSession := loginSessionToStorage(loginSession)

	filter := bson.D{primitive.E{Key: "_id", Value: storageLoginSession.ID}}
	var err error
	if context != nil {
		err = sa.db.loginsSessions.ReplaceOneWithContext(context, filter, storageLoginSession, nil)
	} else {
		err = sa.db.loginsSessions.ReplaceOne(filter, storageLoginSession, nil)
	}

	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeLoginSession, &logutils.FieldArgs{"_id": storageLoginSession.ID}, err)
	}

	return nil
}

//DeleteLoginSession deletes login session
func (sa *Adapter) DeleteLoginSession(context TransactionContext, id string) error {
	filter := bson.M{"_id": id}

	var res *mongo.DeleteResult
	var err error
	if context != nil {
		res, err = sa.db.loginsSessions.DeleteOneWithContext(context, filter, nil)
	} else {
		res, err = sa.db.loginsSessions.DeleteOne(filter, nil)
	}

	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeLoginSession, &logutils.FieldArgs{"_id": id}, err)
	}
	if res.DeletedCount != 1 {
		return errors.ErrorAction(logutils.ActionDelete, model.TypeLoginSession, logutils.StringArgs("unexpected deleted count"))
	}
	return nil
}

//DeleteLoginSessions deletes all login sessions with the identifier
func (sa *Adapter) DeleteLoginSessions(context TransactionContext, identifier string) error {
	filter := bson.M{"identifier": identifier}

	var res *mongo.DeleteResult
	var err error
	if context != nil {
		res, err = sa.db.loginsSessions.DeleteManyWithContext(context, filter, nil)
	} else {
		res, err = sa.db.loginsSessions.DeleteMany(filter, nil)
	}

	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeLoginSession, &logutils.FieldArgs{"identifier": identifier}, err)
	}
	if res.DeletedCount < 1 {
		return errors.ErrorAction(logutils.ActionDelete, model.TypeLoginSession, logutils.StringArgs("unexpected deleted count"))
	}
	return nil
}

//DeleteExpiredSessions deletes expired sessions
func (sa *Adapter) DeleteExpiredSessions(now *time.Time) error {
	filter := bson.D{primitive.E{Key: "$or", Value: []interface{}{
		bson.M{"expires": bson.M{"$lte": now}},
		bson.M{"force_expires": bson.M{"$lte": now}},
		bson.M{"state_expires": bson.M{"$lte": now}},
	}}}

	_, err := sa.db.loginsSessions.DeleteMany(filter, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeLoginSession, &logutils.FieldArgs{"expires": now}, err)
	}

	return nil
}

//FindAccount finds an account for app, org, auth type and account auth type identifier
func (sa *Adapter) FindAccount(appOrgID string, authTypeID string, accountAuthTypeIdentifier string) (*model.Account, error) {
	filter := bson.D{primitive.E{Key: "app_org_id", Value: appOrgID},
		primitive.E{Key: "auth_types.auth_type_id", Value: authTypeID},
		primitive.E{Key: "auth_types.identifier", Value: accountAuthTypeIdentifier}}
	var accounts []account
	err := sa.db.accounts.Find(filter, &accounts, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}
	if len(accounts) == 0 {
		//not found
		return nil, nil
	}
	account := accounts[0]

	//application organization - from cache
	appOrg, err := sa.getCachedApplicationOrganizationByKey(account.AppOrgID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplication, nil, err)
	}

	modelAccount := accountFromStorage(account, *appOrg)
	return &modelAccount, nil
}

//FindAccounts finds accounts
func (sa *Adapter) FindAccounts(appID string, orgID string, accountID *string, authTypeIdentifier *string) ([]model.Account, error) {
	//find app org id
	appOrg, err := sa.getCachedApplicationOrganization(appID, orgID)
	if err != nil {
		return nil, errors.WrapErrorAction("error getting cached application organization", "", nil, err)
	}

	//find the accounts
	filter := bson.D{primitive.E{Key: "app_org_id", Value: appOrg.ID}}

	if accountID != nil {
		filter = append(filter, primitive.E{Key: "_id", Value: *accountID})
	}
	if authTypeIdentifier != nil {
		filter = append(filter, primitive.E{Key: "auth_types.identifier", Value: *authTypeIdentifier})
	}

	var list []account
	err = sa.db.accounts.Find(filter, &list, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}

	accounts := accountsFromStorage(list, *appOrg)
	return accounts, nil
}

//FindAccountByID finds an account by id
func (sa *Adapter) FindAccountByID(context TransactionContext, id string) (*model.Account, error) {
	return sa.findAccount(context, "_id", id)
}

//FindAccountByAuthTypeID finds an account by auth type id
func (sa *Adapter) FindAccountByAuthTypeID(context TransactionContext, id string) (*model.Account, error) {
	return sa.findAccount(context, "auth_types.id", id)
}

func (sa *Adapter) findAccount(context TransactionContext, key string, id string) (*model.Account, error) {
	account, err := sa.findStorageAccount(context, key, id)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}

	if account == nil {
		return nil, nil
	}

	//application organization - from cache
	appOrg, err := sa.getCachedApplicationOrganizationByKey(account.AppOrgID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplication, nil, err)
	}

	modelAccount := accountFromStorage(*account, *appOrg)

	return &modelAccount, nil
}

func (sa *Adapter) findStorageAccount(context TransactionContext, key string, id string) (*account, error) {
	filter := bson.M{key: id}
	var accounts []account
	var err error
	if context != nil {
		err = sa.db.accounts.FindWithContext(context, filter, &accounts, nil)
	} else {
		err = sa.db.accounts.Find(filter, &accounts, nil)
	}

	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, &logutils.FieldArgs{key: id}, err)
	}
	if len(accounts) == 0 {
		//not found
		return nil, nil
	}

	account := accounts[0]
	return &account, nil
}

//InsertAccount inserts an account
func (sa *Adapter) InsertAccount(account model.Account) (*model.Account, error) {
	storageAccount := accountToStorage(&account)

	_, err := sa.db.accounts.InsertOne(storageAccount)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionInsert, model.TypeAccount, nil, err)
	}

	return &account, nil
}

//SaveAccount saves an existing account
func (sa *Adapter) SaveAccount(context TransactionContext, account *model.Account) error {
	if account == nil {
		return errors.ErrorData(logutils.StatusInvalid, logutils.TypeArg, logutils.StringArgs("account"))
	}

	storageAccount := accountToStorage(account)

	var err error
	filter := bson.M{"_id": account.ID}
	if context != nil {
		err = sa.db.accounts.ReplaceOneWithContext(context, filter, storageAccount, nil)
	} else {
		err = sa.db.accounts.ReplaceOne(filter, storageAccount, nil)
	}

	if err != nil {
		return errors.WrapErrorAction(logutils.ActionSave, model.TypeAccount, &logutils.FieldArgs{"_id": account.ID}, nil)
	}

	return nil
}

//DeleteAccount deletes an account
func (sa *Adapter) DeleteAccount(context TransactionContext, id string) error {
	//TODO - we have to decide what we do on delete user operation - removing all user relations, (or) mark the user disabled etc

	filter := bson.M{"_id": id}
	var res *mongo.DeleteResult
	var err error
	if context != nil {
		res, err = sa.db.accounts.DeleteOneWithContext(context, filter, nil)
	} else {
		res, err = sa.db.accounts.DeleteOne(filter, nil)
	}

	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeAccount, nil, err)
	}
	if res.DeletedCount != 1 {
		return errors.ErrorAction(logutils.ActionDelete, model.TypeAccount, logutils.StringArgs("unexpected deleted count"))
	}

	return nil
}

//UpdateAccountPreferences updates account preferences
func (sa *Adapter) UpdateAccountPreferences(accountID string, preferences map[string]interface{}) error {
	filter := bson.D{primitive.E{Key: "_id", Value: accountID}}
	update := bson.D{
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "preferences", Value: preferences},
		}},
	}

	res, err := sa.db.accounts.UpdateOne(filter, update, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeAccountPreferences, nil, err)
	}
	if res.ModifiedCount != 1 {
		return errors.ErrorAction(logutils.ActionUpdate, model.TypeAccountPreferences, &logutils.FieldArgs{"unexpected modified count": res.ModifiedCount})
	}

	return nil
}

//InsertAccountPermissions inserts account permissions
func (sa *Adapter) InsertAccountPermissions(accountID string, permissions []model.Permission) error {
	filter := bson.D{primitive.E{Key: "_id", Value: accountID}}
	update := bson.D{
		primitive.E{Key: "$push", Value: bson.D{
			primitive.E{Key: "permissions", Value: bson.M{"$each": permissions}},
		}},
	}

	res, err := sa.db.accounts.UpdateOne(filter, update, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}
	if res.ModifiedCount != 1 {
		return errors.ErrorAction(logutils.ActionUpdate, model.TypeAccount, &logutils.FieldArgs{"unexpected modified count": res.ModifiedCount})
	}

	return nil
}

//InsertAccountRoles inserts account roles
func (sa *Adapter) InsertAccountRoles(accountID string, appOrgID string, roles []model.AccountRole) error {
	stgRoles := accountRolesToStorage(roles)

	//appID included in search to prevent accidentally assigning permissions to account from different application
	filter := bson.D{primitive.E{Key: "_id", Value: accountID}, primitive.E{Key: "app_org_id", Value: appOrgID}}
	update := bson.D{
		primitive.E{Key: "$push", Value: bson.D{
			primitive.E{Key: "roles", Value: bson.M{"$each": stgRoles}},
		}},
	}

	res, err := sa.db.accounts.UpdateOne(filter, update, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}
	if res.ModifiedCount != 1 {
		return errors.ErrorAction(logutils.ActionUpdate, model.TypeAccount, &logutils.FieldArgs{"unexpected modified count": res.ModifiedCount})
	}

	return nil
}

//UpdateAccountRoles updates the account roles
func (sa *Adapter) UpdateAccountRoles(accountID string, roles []model.AccountRole) error {
	stgRoles := accountRolesToStorage(roles)

	filter := bson.D{primitive.E{Key: "_id", Value: accountID}}
	update := bson.D{
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "roles", Value: stgRoles},
		}},
	}

	res, err := sa.db.accounts.UpdateOne(filter, update, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}
	if res.ModifiedCount != 1 {
		return errors.ErrorAction(logutils.ActionUpdate, model.TypeAccount, &logutils.FieldArgs{"unexpected modified count": res.ModifiedCount})
	}

	return nil
}

//DeleteAccountRoles deletes account roles
func (sa *Adapter) DeleteAccountRoles(accountID string, roleIDs []string) error {
	filter := bson.D{primitive.E{Key: "_id", Value: accountID}}
	update := bson.D{
		primitive.E{Key: "$pull", Value: bson.D{
			primitive.E{Key: "roles", Value: bson.M{"$each": roleIDs}},
		}},
	}

	res, err := sa.db.accounts.UpdateOne(filter, update, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}
	if res.ModifiedCount != 1 {
		return errors.ErrorAction(logutils.ActionUpdate, model.TypeAccount, &logutils.FieldArgs{"unexpected modified count": res.ModifiedCount})
	}

	return nil
}

//UpdateAccountGroups updates the account groups
func (sa *Adapter) UpdateAccountGroups(accountID string, groups []model.AccountGroup) error {
	stgGroups := accountGroupsToStorage(groups)

	filter := bson.D{primitive.E{Key: "_id", Value: accountID}}
	update := bson.D{
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "groups", Value: stgGroups},
		}},
	}

	res, err := sa.db.accounts.UpdateOne(filter, update, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}
	if res.ModifiedCount != 1 {
		return errors.ErrorAction(logutils.ActionUpdate, model.TypeAccount, &logutils.FieldArgs{"unexpected modified count": res.ModifiedCount})
	}

	return nil
}

//InsertAccountAuthType inserts am account auth type
func (sa *Adapter) InsertAccountAuthType(item model.AccountAuthType) error {
	storageItem := accountAuthTypeToStorage(item)

	//3. first find the account record
	filter := bson.M{"_id": item.Account.ID}
	update := bson.D{
		primitive.E{Key: "$push", Value: bson.D{
			primitive.E{Key: "auth_types", Value: storageItem},
		}},
	}

	res, err := sa.db.accounts.UpdateOne(filter, update, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionInsert, model.TypeAccountAuthType, nil, err)
	}
	if res.ModifiedCount != 1 {
		return errors.ErrorAction(logutils.ActionUpdate, model.TypeAccountAuthType, &logutils.FieldArgs{"unexpected modified count": res.ModifiedCount})
	}

	return nil
}

//UpdateAccountAuthType updates account auth type
func (sa *Adapter) UpdateAccountAuthType(item model.AccountAuthType) error {
	// transaction
	err := sa.db.dbClient.UseSession(context.Background(), func(sessionContext mongo.SessionContext) error {
		err := sessionContext.StartTransaction()
		if err != nil {
			sa.abortTransaction(sessionContext)
			return errors.WrapErrorAction(logutils.ActionStart, logutils.TypeTransaction, nil, err)
		}

		//1. set time updated to the item
		now := time.Now()
		item.DateUpdated = &now

		//2 convert to storage item
		storageItem := accountAuthTypeToStorage(item)

		//3. first find the account record
		findFilter := bson.M{"auth_types.id": item.ID}
		var accounts []account
		err = sa.db.accounts.FindWithContext(sessionContext, findFilter, &accounts, nil)
		if err != nil {
			sa.abortTransaction(sessionContext)
			return errors.WrapErrorAction(logutils.ActionFind, model.TypeUserAuth, &logutils.FieldArgs{"account auth type id": item.ID}, err)
		}
		if len(accounts) == 0 {
			sa.abortTransaction(sessionContext)
			return errors.ErrorAction(logutils.ActionFind, "for some reasons account is nil for account auth type", &logutils.FieldArgs{"acccount auth type id": item.ID})
		}
		account := accounts[0]

		//4. update the account auth type in the account record
		accountAuthTypes := account.AuthTypes
		newAccountAuthTypes := make([]accountAuthType, len(accountAuthTypes))
		for j, aAuthType := range accountAuthTypes {
			if aAuthType.ID == storageItem.ID {
				newAccountAuthTypes[j] = storageItem
			} else {
				newAccountAuthTypes[j] = aAuthType
			}
		}
		account.AuthTypes = newAccountAuthTypes

		//4. update the account record
		replaceFilter := bson.M{"_id": account.ID}
		err = sa.db.accounts.ReplaceOneWithContext(sessionContext, replaceFilter, account, nil)
		if err != nil {
			sa.abortTransaction(sessionContext)
			return errors.WrapErrorAction(logutils.ActionReplace, model.TypeAccount, nil, err)
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
		return err
	}

	return nil
}

//FindCredential finds a credential by ID
func (sa *Adapter) FindCredential(context TransactionContext, ID string) (*model.Credential, error) {
	filter := bson.D{primitive.E{Key: "_id", Value: ID}}

	var creds credential
	var err error
	if context != nil {
		err = sa.db.credentials.FindOneWithContext(context, filter, &creds, nil)
	} else {
		err = sa.db.credentials.FindOne(filter, &creds, nil)
	}

	if err != nil {
		if err.Error() == "mongo: no documents in result" {
			return nil, nil
		}
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeCredential, &logutils.FieldArgs{"_id": ID}, err)
	}

	modelCreds := credentialFromStorage(creds)
	return &modelCreds, nil
}

//InsertCredential inserts a set of credential
func (sa *Adapter) InsertCredential(creds *model.Credential) error {
	storageCreds := credentialToStorage(creds)

	if storageCreds == nil {
		return errors.ErrorData(logutils.StatusInvalid, logutils.TypeArg, logutils.StringArgs(model.TypeCredential))
	}

	_, err := sa.db.credentials.InsertOne(storageCreds)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionInsert, model.TypeCredential, nil, err)
	}

	return nil
}

//UpdateCredential updates a set of credentials
func (sa *Adapter) UpdateCredential(context TransactionContext, creds *model.Credential) error {
	storageCreds := credentialToStorage(creds)

	if storageCreds == nil {
		return errors.ErrorData(logutils.StatusInvalid, logutils.TypeArg, logutils.StringArgs(model.TypeCredential))
	}

	filter := bson.D{primitive.E{Key: "_id", Value: storageCreds.ID}}
	var err error
	if context != nil {
		err = sa.db.credentials.ReplaceOneWithContext(context, filter, storageCreds, nil)
	} else {
		err = sa.db.credentials.ReplaceOne(filter, storageCreds, nil)
	}

	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeCredential, &logutils.FieldArgs{"_id": storageCreds.ID}, err)
	}

	return nil
}

//UpdateCredentialValue updates the value in credentials collection
func (sa *Adapter) UpdateCredentialValue(ID string, value map[string]interface{}) error {
	filter := bson.D{primitive.E{Key: "_id", Value: ID}}
	update := bson.D{
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "value", Value: value},
		}},
	}

	res, err := sa.db.credentials.UpdateOne(filter, update, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeCredential, nil, err)
	}
	if res.ModifiedCount != 1 {
		return errors.ErrorAction(logutils.ActionUpdate, model.TypeCredential, &logutils.FieldArgs{"unexpected modified count": res.ModifiedCount})
	}

	return nil
}

//DeleteCredential deletes a credential
func (sa *Adapter) DeleteCredential(context TransactionContext, ID string) error {
	filter := bson.D{primitive.E{Key: "_id", Value: ID}}

	var res *mongo.DeleteResult
	var err error
	if context != nil {
		res, err = sa.db.credentials.DeleteOneWithContext(context, filter, nil)
	} else {
		res, err = sa.db.credentials.DeleteOne(filter, nil)
	}

	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeCredential, &logutils.FieldArgs{"_id": ID}, err)
	}
	if res.DeletedCount != 1 {
		return errors.ErrorAction(logutils.ActionDelete, model.TypeCredential, &logutils.FieldArgs{"unexpected deleted count": res.DeletedCount})
	}

	return nil
}

//FindMFAType finds one MFA type for an account
func (sa *Adapter) FindMFAType(context TransactionContext, accountID string, identifier string, mfaType string) (*model.MFAType, error) {
	filter := bson.D{
		primitive.E{Key: "_id", Value: accountID},
		primitive.E{Key: "mfa_types.type", Value: mfaType},
		primitive.E{Key: "mfa_types.params.identifier", Value: identifier},
	}

	var account account
	var err error
	if context != nil {
		err = sa.db.accounts.FindOneWithContext(context, filter, &account, nil)
	} else {
		err = sa.db.accounts.FindOne(filter, &account, nil)
	}

	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}

	mfaList := mfaTypesFromStorage(account.MFATypes)
	for _, mfa := range mfaList {
		if mfa.Type == mfaType && mfa.Params != nil && mfa.Params["identifier"] == identifier {
			return &mfa, nil
		}
	}

	return nil, errors.ErrorData(logutils.StatusMissing, model.TypeMFAType, nil)
}

//FindMFATypes finds all MFA types for an account
func (sa *Adapter) FindMFATypes(accountID string) ([]model.MFAType, error) {
	filter := bson.D{primitive.E{Key: "_id", Value: accountID}}

	var account account
	err := sa.db.accounts.FindOne(filter, &account, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}

	return mfaTypesFromStorage(account.MFATypes), nil
}

//InsertMFAType inserts a MFA type
func (sa *Adapter) InsertMFAType(context TransactionContext, mfa *model.MFAType, accountID string) error {
	if mfa == nil {
		return errors.ErrorData(logutils.StatusMissing, model.TypeMFAType, nil)
	}
	if mfa.Params == nil || mfa.Params["identifier"] == nil {
		return errors.ErrorData(logutils.StatusMissing, "mfa identifier", nil)
	}

	storageMfa := mfaTypeToStorage(mfa)

	filter := bson.D{
		primitive.E{Key: "_id", Value: accountID},
		primitive.E{Key: "mfa_types.params.identifier", Value: bson.M{"$ne": mfa.Params["identifier"]}},
	}
	update := bson.D{
		primitive.E{Key: "$push", Value: bson.D{
			primitive.E{Key: "mfa_types", Value: storageMfa},
		}},
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "date_updated", Value: time.Now().UTC()},
		}},
	}

	var res *mongo.UpdateResult
	var err error
	if context != nil {
		res, err = sa.db.accounts.UpdateOneWithContext(context, filter, update, nil)
	} else {
		res, err = sa.db.accounts.UpdateOne(filter, update, nil)
	}

	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccount, logutils.StringArgs("inserting mfa type"), err)
	}
	if res.ModifiedCount != 1 {
		return errors.ErrorAction(logutils.ActionUpdate, model.TypeAccount, &logutils.FieldArgs{"unexpected modified count": res.ModifiedCount})
	}

	return nil
}

//UpdateMFAType updates one MFA type
func (sa *Adapter) UpdateMFAType(context TransactionContext, mfa *model.MFAType, accountID string) error {
	if mfa.Params == nil || mfa.Params["identifier"] == nil {
		return errors.ErrorData(logutils.StatusMissing, "mfa identifier", nil)
	}

	now := time.Now().UTC()
	filter := bson.D{
		primitive.E{Key: "_id", Value: accountID},
		primitive.E{Key: "mfa_types.id", Value: mfa.ID},
	}
	update := bson.D{
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "mfa_types.$.verified", Value: mfa.Verified},
			primitive.E{Key: "mfa_types.$.params", Value: mfa.Params},
			primitive.E{Key: "mfa_types.$.date_updated", Value: now},
			primitive.E{Key: "date_updated", Value: now},
		}},
	}

	var res *mongo.UpdateResult
	var err error
	if context != nil {
		res, err = sa.db.accounts.UpdateOneWithContext(context, filter, update, nil)
	} else {
		res, err = sa.db.accounts.UpdateOne(filter, update, nil)
	}

	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccount, logutils.StringArgs("updating mfa type"), err)
	}
	if res.ModifiedCount == 0 {
		return errors.ErrorAction(logutils.ActionUpdate, model.TypeAccount, logutils.StringArgs("item to update not found"))
	}
	if res.ModifiedCount != 1 {
		return errors.ErrorAction(logutils.ActionUpdate, model.TypeAccount, &logutils.FieldArgs{"unexpected modified count": res.ModifiedCount})
	}

	return nil
}

//DeleteMFAType deletes a MFA type
func (sa *Adapter) DeleteMFAType(context TransactionContext, accountID string, identifier string, mfaType string) error {
	filter := bson.D{primitive.E{Key: "_id", Value: accountID}}
	update := bson.D{
		primitive.E{Key: "$pull", Value: bson.D{
			primitive.E{Key: "mfa_types", Value: bson.M{"type": mfaType, "params.identifier": identifier}},
		}},
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "date_updated", Value: time.Now().UTC()},
		}},
	}

	var res *mongo.UpdateResult
	var err error
	if context != nil {
		res, err = sa.db.accounts.UpdateOneWithContext(context, filter, update, nil)
	} else {
		res, err = sa.db.accounts.UpdateOne(filter, update, nil)
	}

	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccount, logutils.StringArgs("deleting mfa type"), err)
	}
	if res.ModifiedCount == 0 {
		return errors.ErrorAction(logutils.ActionUpdate, model.TypeAccount, logutils.StringArgs("item to remove not found"))
	}
	if res.ModifiedCount != 1 {
		return errors.ErrorAction(logutils.ActionUpdate, model.TypeAccount, &logutils.FieldArgs{"unexpected modified count": res.ModifiedCount})
	}

	return nil
}

//FindPermissions finds a set of permissions
func (sa *Adapter) FindPermissions(ids []string) ([]model.Permission, error) {
	permissionsFilter := bson.D{primitive.E{Key: "_id", Value: bson.M{"$in": ids}}}
	var permissionsResult []model.Permission
	err := sa.db.permissions.Find(permissionsFilter, &permissionsResult, nil)
	if err != nil {
		return nil, err
	}

	return permissionsResult, nil
}

//FindPermissionsByServiceID finds permissions
func (sa *Adapter) FindPermissionsByServiceIDs(serviceIDs []string) ([]model.Permission, error) {
	filter := bson.D{primitive.E{Key: "service_id", Value: bson.M{"$in": serviceIDs}}}
	var permissionsResult []model.Permission
	err := sa.db.permissions.Find(filter, &permissionsResult, nil)
	if err != nil {
		return nil, err
	}

	return permissionsResult, nil
}

//FindPermissionsByName finds a set of permissions
func (sa *Adapter) FindPermissionsByName(names []string) ([]model.Permission, error) {
	permissionsFilter := bson.D{primitive.E{Key: "name", Value: bson.M{"$in": names}}}
	var permissionsResult []model.Permission
	err := sa.db.permissions.Find(permissionsFilter, &permissionsResult, nil)
	if err != nil {
		return nil, err
	}

	return permissionsResult, nil
}

//InsertPermission inserts a new  permission
func (sa *Adapter) InsertPermission(permission model.Permission) error {
	_, err := sa.db.permissions.InsertOne(permission)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionInsert, model.TypePermission, nil, err)
	}
	return nil
}

//UpdatePermission updates permission
func (sa *Adapter) UpdatePermission(item model.Permission) error {
	//TODO
	//This will be slow operation as we keep a copy of the entity in the users collection without index.
	//Maybe we need to up the transaction timeout for this operation because of this.
	//TODO
	//Update the permission in all collection where there is a copy of it - accounts, application_roles, application_groups

	// Update serviceIDs
	filter := bson.D{primitive.E{Key: "name", Value: item.Name}}

	now := time.Now().UTC()
	permissionUpdate := bson.D{
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "service_id", Value: item.ServiceID},
			primitive.E{Key: "assigners", Value: item.Assigners},
			primitive.E{Key: "date_updated", Value: &now},
		}},
	}

	res, err := sa.db.permissions.UpdateOne(filter, permissionUpdate, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypePermission, &logutils.FieldArgs{"name": item.Name}, err)
	}

	if res.ModifiedCount != 1 {
		return errors.ErrorAction(logutils.ActionUpdate, model.TypePermission, logutils.StringArgs("unexpected modified count"))
	}

	return nil
}

//DeletePermission deletes permission
func (sa *Adapter) DeletePermission(id string) error {
	//TODO
	//This will be slow operation as we keep a copy of the entity in the users collection without index.
	//Maybe we need to up the transaction timeout for this operation because of this.
	return errors.New(logutils.Unimplemented)
}

//FindAppOrgRoles finds a set of application organization roles
func (sa *Adapter) FindAppOrgRoles(ids []string, appOrgID string) ([]model.AppOrgRole, error) {
	if len(ids) == 0 {
		return []model.AppOrgRole{}, nil
	}

	rolesFilter := bson.D{primitive.E{Key: "app_org_id", Value: appOrgID}, primitive.E{Key: "_id", Value: bson.M{"$in": ids}}}
	var rolesResult []appOrgRole
	err := sa.db.applicationsOrganizationsRoles.Find(rolesFilter, &rolesResult, nil)
	if err != nil {
		return nil, err
	}

	//get the application organization from the cached ones
	appOrg, err := sa.getCachedApplicationOrganizationByKey(appOrgID)
	if err != nil {
		return nil, errors.WrapErrorData(logutils.StatusMissing, model.TypeOrganization, &logutils.FieldArgs{"app_org_id": appOrg}, err)
	}

	result := appOrgRolesFromStorage(rolesResult, *appOrg)

	return result, nil
}

//InsertAppOrgRole inserts a new application organization role
func (sa *Adapter) InsertAppOrgRole(item model.AppOrgRole) error {
	_, err := sa.getCachedApplicationOrganizationByKey(item.AppOrg.ID)
	if err != nil {
		return errors.WrapErrorData(logutils.StatusMissing, model.TypeApplication, &logutils.FieldArgs{"app_org_id": item.AppOrg.ID}, err)
	}

	role := appOrgRoleToStorage(item)
	_, err = sa.db.applicationsOrganizationsRoles.InsertOne(role)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionInsert, model.TypeAppOrgRole, nil, err)
	}
	return nil
}

//UpdateAppOrgRole updates application organization role
func (sa *Adapter) UpdateAppOrgRole(item model.AppOrgRole) error {
	//TODO
	//This will be slow operation as we keep a copy of the entity in the users collection without index.
	//Maybe we need to up the transaction timeout for this operation because of this.
	return errors.New(logutils.Unimplemented)
}

//DeleteAppOrgRole deletes application organization role
func (sa *Adapter) DeleteAppOrgRole(id string) error {
	//TODO
	//This will be slow operation as we keep a copy of the entity in the users collection without index.
	//Maybe we need to up the transaction timeout for this operation because of this.
	return errors.New(logutils.Unimplemented)
}

//FindAppOrgGroups finds a set of application organization groups
func (sa *Adapter) FindAppOrgGroups(ids []string, appOrgID string) ([]model.AppOrgGroup, error) {
	if len(ids) == 0 {
		return []model.AppOrgGroup{}, nil
	}

	filter := bson.D{primitive.E{Key: "app_org_id", Value: appOrgID}, primitive.E{Key: "_id", Value: bson.M{"$in": ids}}}
	var groupsResult []appOrgGroup
	err := sa.db.applicationsOrganizationsGroups.Find(filter, &groupsResult, nil)
	if err != nil {
		return nil, err
	}

	appOrg, err := sa.getCachedApplicationOrganizationByKey(appOrgID)
	if err != nil {
		return nil, errors.WrapErrorData(logutils.StatusMissing, model.TypeOrganization, &logutils.FieldArgs{"app_org_id": appOrg}, err)
	}

	result := appOrgGroupsFromStorage(groupsResult, *appOrg)

	return result, nil
}

//InsertAppOrgGroup inserts a new application organization group
func (sa *Adapter) InsertAppOrgGroup(item model.AppOrgGroup) error {
	group := appOrgGroupToStorage(item)
	_, err := sa.db.applicationsOrganizationsGroups.InsertOne(group)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionInsert, model.TypeAppOrgGroup, nil, err)
	}
	return nil
}

//UpdateAppOrgGroup updates application organization group
func (sa *Adapter) UpdateAppOrgGroup(item model.AppOrgGroup) error {
	//TODO
	//This will be slow operation as we keep a copy of the entity in the users collection without index.
	//Maybe we need to up the transaction timeout for this operation because of this.
	return errors.New(logutils.Unimplemented)
}

//DeleteAppOrgGroup deletes application organization group
func (sa *Adapter) DeleteAppOrgGroup(id string) error {
	//TODO
	//This will be slow operation as we keep a copy of the entity in the users collection without index.
	//Maybe we need to up the transaction timeout for this operation because of this.
	return errors.New(logutils.Unimplemented)
}

//LoadAPIKeys finds all api key documents in the DB
func (sa *Adapter) LoadAPIKeys() ([]model.APIKey, error) {
	filter := bson.D{}
	var result []model.APIKey
	err := sa.db.apiKeys.Find(filter, &result, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplication, nil, err)
	}

	return result, nil
}

//FindApplicationAPIKeys finds the api key documents from storage for an appID
func (sa *Adapter) FindApplicationAPIKeys(appID string) ([]model.APIKey, error) {
	filter := bson.D{primitive.E{Key: "app_id", Value: appID}}
	var result []model.APIKey
	err := sa.db.apiKeys.Find(filter, &result, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAPIKey, &logutils.FieldArgs{"app_id": appID}, err)
	}
	return result, nil
}

//FindAPIKey finds the api key documents from storage
func (sa *Adapter) FindAPIKey(ID string) (*model.APIKey, error) {
	filter := bson.D{primitive.E{Key: "_id", Value: ID}}
	var result *model.APIKey
	err := sa.db.apiKeys.FindOne(filter, &result, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAPIKey, &logutils.FieldArgs{"_id": ID}, err)
	}
	return result, nil
}

//InsertAPIKey inserts an API key
func (sa *Adapter) InsertAPIKey(apiKey model.APIKey) (*model.APIKey, error) {
	_, err := sa.db.apiKeys.InsertOne(apiKey)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionInsert, model.TypeAPIKey, &logutils.FieldArgs{"_id": apiKey.ID}, err)
	}
	return &apiKey, nil
}

//UpdateAPIKey updates the API key in storage
func (sa *Adapter) UpdateAPIKey(apiKey model.APIKey) error {
	filter := bson.M{"_id": apiKey.ID}
	err := sa.db.apiKeys.ReplaceOne(filter, apiKey, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAPIKey, &logutils.FieldArgs{"_id": apiKey.ID}, err)
	}

	return nil
}

//DeleteAPIKey deletes the API key from storage
func (sa *Adapter) DeleteAPIKey(ID string) error {
	filter := bson.M{"_id": ID}
	result, err := sa.db.apiKeys.DeleteOne(filter, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeAPIKey, &logutils.FieldArgs{"_id": ID}, err)
	}
	if result == nil {
		return errors.WrapErrorData(logutils.StatusInvalid, "result", &logutils.FieldArgs{"_id": ID}, err)
	}
	deletedCount := result.DeletedCount
	if deletedCount == 0 {
		return errors.WrapErrorData(logutils.StatusMissing, model.TypeAPIKey, &logutils.FieldArgs{"_id": ID}, err)
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

//UpdateProfile updates an account profile
func (sa *Adapter) UpdateProfile(id string, profile *model.Profile) error {
	filter := bson.D{primitive.E{Key: "_id", Value: id}}

	now := time.Now().UTC()
	if profile == nil {
		return errors.ErrorData(logutils.StatusInvalid, logutils.TypeArg, logutils.StringArgs(model.TypeProfile))
	}
	profileUpdate := bson.D{
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "profile.photo_url", Value: profile.PhotoURL},
			primitive.E{Key: "profile.first_name", Value: profile.FirstName},
			primitive.E{Key: "profile.last_name", Value: profile.LastName},
			primitive.E{Key: "profile.email", Value: profile.Email},
			primitive.E{Key: "profile.phone", Value: profile.Phone},
			primitive.E{Key: "profile.birth_year", Value: profile.BirthYear},
			primitive.E{Key: "profile.address", Value: profile.Address},
			primitive.E{Key: "profile.zip_code", Value: profile.ZipCode},
			primitive.E{Key: "profile.state", Value: profile.State},
			primitive.E{Key: "profile.country", Value: profile.Country},
			primitive.E{Key: "profile.date_updated", Value: &now},
		}},
	}

	res, err := sa.db.accounts.UpdateOne(filter, profileUpdate, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeProfile, nil, err)
	}
	if res.ModifiedCount != 1 {
		return errors.ErrorAction(logutils.ActionUpdate, model.TypeProfile, logutils.StringArgs("unexpected modified count"))
	}

	return nil
}

//CreateGlobalConfig creates global config
func (sa *Adapter) CreateGlobalConfig(context TransactionContext, globalConfig *model.GlobalConfig) error {
	if globalConfig == nil {
		return errors.ErrorData(logutils.StatusInvalid, logutils.TypeArg, logutils.StringArgs("global_config"))
	}

	var err error
	if context != nil {
		_, err = sa.db.globalConfig.InsertOneWithContext(context, globalConfig)
	} else {
		_, err = sa.db.globalConfig.InsertOne(globalConfig)
	}

	if err != nil {
		return errors.WrapErrorAction(logutils.ActionInsert, model.TypeGlobalConfig, &logutils.FieldArgs{"setting": globalConfig.Setting}, err)
	}

	return nil
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

//DeleteGlobalConfig deletes the global configuration from storage
func (sa *Adapter) DeleteGlobalConfig(context TransactionContext) error {
	delFilter := bson.D{}
	var err error
	if context != nil {
		_, err = sa.db.globalConfig.DeleteManyWithContext(context, delFilter, nil)
	} else {
		_, err = sa.db.globalConfig.DeleteMany(delFilter, nil)
	}

	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeGlobalConfig, nil, err)
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

	//TODO
	//2. find the organization applications
	/*	var applications []model.Application
			if len(org.Applications) > 0 {
				appsFilter := bson.D{primitive.E{Key: "_id", Value: bson.M{"$in": org.Applications}}}
				err := sa.db.applications.Find(appsFilter, &applications, nil)
				if err != nil {
					return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplication, nil, err)
				}
			}

		organization := organizationFromStorage(&org, applications)
		return &organization, nil */
	return nil, nil
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
	//1. check the cached organizations
	cachedOrgs, err := sa.getCachedOrganizations()
	if err != nil {
		sa.logger.Warn(err.Error())
	} else if len(cachedOrgs) > 0 {
		return cachedOrgs, nil
	}

	//no transactions for get operations..

	//2. find the organizations
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

	//3. prepare the response
	organizations := organizationsFromStorage(orgsResult)
	return organizations, nil
}

//LoadApplications loads all applications
func (sa *Adapter) LoadApplications() ([]model.Application, error) {
	filter := bson.D{}
	var result []application
	err := sa.db.applications.Find(filter, &result, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplication, nil, err)
	}

	if len(result) == 0 {
		//no data
		return make([]model.Application, 0), nil
	}

	applications := applicationsFromStorage(result)
	return applications, nil
}

//InsertApplication inserts an application
func (sa *Adapter) InsertApplication(application model.Application) (*model.Application, error) {
	app := applicationToStorage(&application)
	_, err := sa.db.applications.InsertOne(app)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionInsert, model.TypeApplication, nil, err)
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

//LoadApplicationsOrganizations loads all applications organizations
func (sa *Adapter) LoadApplicationsOrganizations() ([]model.ApplicationOrganization, error) {
	filter := bson.D{}
	var list []applicationOrganization
	err := sa.db.applicationsOrganizations.Find(filter, &list, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationOrganization, nil, err)
	}
	if len(list) == 0 {
		//no data
		return nil, nil
	}

	result := make([]model.ApplicationOrganization, len(list))
	for i, item := range list {
		//we have organizations and applications cached
		application, err := sa.getCachedApplication(item.AppID)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplication, nil, err)
		}
		organization, err := sa.getCachedOrganization(item.OrgID)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeOrganization, nil, err)
		}

		result[i] = applicationOrganizationFromStorage(item, *application, *organization)
	}
	return result, nil

}

//FindApplicationOrganizations finds application organization
func (sa *Adapter) FindApplicationOrganizations(appID string, orgID string) (*model.ApplicationOrganization, error) {
	return sa.getCachedApplicationOrganization(appID, orgID)
}

//FindDevice finds a device by device id and account id
func (sa *Adapter) FindDevice(context TransactionContext, deviceID string, accountID string) (*model.Device, error) {
	filter := bson.D{primitive.E{Key: "device_id", Value: deviceID},
		primitive.E{Key: "account_id", Value: accountID}}
	var result []device

	var err error
	if context != nil {
		err = sa.db.devices.FindWithContext(context, filter, &result, nil)
	} else {
		err = sa.db.devices.Find(filter, &result, nil)
	}

	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeDevice, nil, err)
	}
	if len(result) == 0 {
		//no record
		return nil, nil
	}
	device := result[0]

	deviceRes := deviceFromStorage(device)
	return &deviceRes, nil
}

//InsertDevice inserts a device
func (sa *Adapter) InsertDevice(context TransactionContext, device model.Device) (*model.Device, error) {
	//insert in devices
	storageDevice := deviceToStorage(&device)
	var err error
	if context != nil {
		_, err = sa.db.devices.InsertOneWithContext(context, storageDevice)
	} else {
		_, err = sa.db.devices.InsertOne(storageDevice)
	}
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionInsert, model.TypeDevice, nil, err)
	}

	//insert in account record - we keep a device copy there too
	filter := bson.M{"_id": device.Account.ID}
	update := bson.D{
		primitive.E{Key: "$push", Value: bson.D{
			primitive.E{Key: "devices", Value: storageDevice},
		}},
	}
	var res *mongo.UpdateResult
	if context != nil {
		res, err = sa.db.accounts.UpdateOneWithContext(context, filter, update, nil)
	} else {
		res, err = sa.db.accounts.UpdateOne(filter, update, nil)
	}
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccount, logutils.StringArgs("inserting device"), err)
	}
	if res.ModifiedCount != 1 {
		return nil, errors.ErrorAction(logutils.ActionUpdate, model.TypeAccount, &logutils.FieldArgs{"unexpected modified count": res.ModifiedCount})
	}

	return &device, nil
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
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeServiceReg, &logutils.FieldArgs{"service_id": reg.Registration.ServiceID}, err)
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
func (sa *Adapter) SaveDevice(context TransactionContext, device *model.Device) error {
	if device == nil {
		return errors.ErrorData(logutils.StatusInvalid, logutils.TypeArg, logutils.StringArgs("device"))
	}

	storageDevice := deviceToStorage(device)

	var err error
	filter := bson.M{"_id": device.ID}
	opts := options.Replace().SetUpsert(true)
	if context != nil {
		err = sa.db.devices.ReplaceOneWithContext(context, filter, storageDevice, opts)
	} else {
		err = sa.db.devices.ReplaceOne(filter, storageDevice, opts)
	}

	if err != nil {
		return errors.WrapErrorAction(logutils.ActionSave, "device", &logutils.FieldArgs{"device_id": device.ID}, nil)
	}

	return nil
}

//DeleteDevice deletes a device
func (sa *Adapter) DeleteDevice(context TransactionContext, id string) error {
	filter := bson.M{"_id": id}
	var res *mongo.DeleteResult
	var err error
	if context != nil {
		res, err = sa.db.devices.DeleteOneWithContext(context, filter, nil)
	} else {
		res, err = sa.db.devices.DeleteOne(filter, nil)
	}

	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeDevice, nil, err)
	}
	if res.DeletedCount != 1 {
		return errors.ErrorAction(logutils.ActionDelete, model.TypeDevice, logutils.StringArgs("unexpected deleted count"))
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

	cachedAuthTypes := &syncmap.Map{}
	authTypesLock := &sync.RWMutex{}

	cachedApplicationsOrganizations := &syncmap.Map{}
	applicationsOrganizationsLock := &sync.RWMutex{}

	db := &database{mongoDBAuth: mongoDBAuth, mongoDBName: mongoDBName, mongoTimeout: timeout, logger: logger}
	return &Adapter{db: db, logger: logger, cachedOrganizations: cachedOrganizations, organizationsLock: organizationsLock,
		cachedApplications: cachedApplications, applicationsLock: applicationsLock,
		cachedAuthTypes: cachedAuthTypes, authTypesLock: authTypesLock,
		cachedApplicationsOrganizations: cachedApplicationsOrganizations, applicationsOrganizationsLock: applicationsOrganizationsLock}
}

type storageListener struct {
	adapter *Adapter
	DefaultListenerImpl
}

func (sl *storageListener) OnAuthTypesUpdated() {
	sl.adapter.cacheAuthTypes()
}

func (sl *storageListener) OnOrganizationsUpdated() {
	sl.adapter.cacheOrganizations()
}

func (sl *storageListener) OnApplicationsUpdated() {
	sl.adapter.cacheApplications()
	sl.adapter.cacheOrganizations()
}

func (sl *storageListener) OnApplicationsOrganizationsUpdated() {
	sl.adapter.cacheApplications()
	sl.adapter.cacheOrganizations()
	sl.adapter.cacheApplicationsOrganizations()
}

//Listener represents storage listener
type Listener interface {
	OnAPIKeysUpdated()
	OnAuthTypesUpdated()
	OnIdentityProvidersUpdated()
	OnServiceRegsUpdated()
	OnOrganizationsUpdated()
	OnApplicationsUpdated()
	OnApplicationsOrganizationsUpdated()
}

//DefaultListenerImpl default listener implementation
type DefaultListenerImpl struct{}

//OnAPIKeysUpdated notifies api keys have been updated
func (d *DefaultListenerImpl) OnAPIKeysUpdated() {}

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

//OnApplicationsOrganizationsUpdated notifies applications organizations have been updated
func (d *DefaultListenerImpl) OnApplicationsOrganizationsUpdated() {}

//TransactionContext wraps mongo.SessionContext for use by external packages
type TransactionContext interface {
	mongo.SessionContext
}
