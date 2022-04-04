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

	cachedApplicationConfigs *syncmap.Map
	applicationConfigsLock   *sync.RWMutex
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

	// cache application configs
	err = sa.cacheApplicationConfigs()
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionCache, model.TypeApplicationConfig, nil, err)
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

func (sa *Adapter) updateCachedOrganizations(docID string, operation string, org model.Organization) {
	sa.organizationsLock.RLock()
	defer sa.organizationsLock.RUnlock()

	switch operation {
	case "insert":
		sa.cachedOrganizations.Store(docID, org)
	case "replace":
		sa.cachedOrganizations.Store(docID, org)
	case "update":
		sa.cachedOrganizations.Store(docID, org)
	case "delete":
		sa.cachedOrganizations.Delete(docID)
	}
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

func (sa *Adapter) updateCachedApplications(docID string, operation string, app model.Application) {
	sa.applicationsLock.RLock()
	defer sa.applicationsLock.RUnlock()

	switch operation {
	case "insert":
		sa.cachedApplications.Store(docID, app)
	case "replace":
		sa.cachedApplications.Store(docID, app)
	case "update":
		sa.cachedApplications.Store(docID, app)
	case "delete":
		sa.cachedApplications.Delete(docID)
	}
}

func (sa *Adapter) getCachedApplicationType(id string) (*model.Application, *model.ApplicationType, error) {
	sa.applicationsLock.RLock()
	defer sa.applicationsLock.RUnlock()

	var app *model.Application
	var appType *model.ApplicationType

	sa.cachedApplications.Range(func(key, value interface{}) bool {
		application, ok := value.(model.Application)
		if !ok {
			return false //break the iteration
		}

		applicationType := application.FindApplicationType(id)
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

	return nil, nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationType, &logutils.FieldArgs{"id": id})
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

func (sa *Adapter) updateCachedAuthTypes(docID string, operation string, authType model.AuthType) {
	sa.authTypesLock.RLock()
	defer sa.authTypesLock.RUnlock()

	//TODO: may need to remove auth types cached by code on replace and update
	switch operation {
	case "insert":
		sa.cachedAuthTypes.Store(docID, authType)
		sa.cachedAuthTypes.Store(authType.Code, authType)
	case "replace":
		sa.cachedAuthTypes.Store(docID, authType)
		sa.cachedAuthTypes.Store(authType.Code, authType)
	case "update":
		sa.cachedAuthTypes.Store(docID, authType)
		sa.cachedAuthTypes.Store(authType.Code, authType)
	case "delete":
		item, loaded := sa.cachedAuthTypes.LoadAndDelete(docID)
		if loaded {
			if cachedAuthType, ok := item.(model.AuthType); ok {
				sa.cachedAuthTypes.Delete(cachedAuthType.Code)
			}
		}
	}
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

func (sa *Adapter) updateCachedApplicationsOrganizations(docID string, operation string, appOrg model.ApplicationOrganization) {
	sa.applicationsOrganizationsLock.RLock()
	defer sa.applicationsOrganizationsLock.RUnlock()

	appOrgKey := fmt.Sprintf("%s_%s", appOrg.Application.ID, appOrg.Organization.ID)

	//TODO: may need to remove app orgs cached by appID_orgID on replace and update
	switch operation {
	case "insert":
		sa.cachedApplicationsOrganizations.Store(docID, appOrg)
		sa.cachedApplicationsOrganizations.Store(appOrgKey, appOrg)
	case "replace":
		sa.cachedApplicationsOrganizations.Store(docID, appOrg)
		sa.cachedApplicationsOrganizations.Store(appOrgKey, appOrg)
	case "update":
		sa.cachedApplicationsOrganizations.Store(docID, appOrg)
		sa.cachedApplicationsOrganizations.Store(appOrgKey, appOrg)
	case "delete":
		item, loaded := sa.cachedApplicationsOrganizations.LoadAndDelete(docID)
		if loaded {
			if cachedAppOrg, ok := item.(model.ApplicationOrganization); ok {
				sa.cachedApplicationsOrganizations.Delete(fmt.Sprintf("%s_%s", cachedAppOrg.Application.ID, cachedAppOrg.Organization.ID))
			}
		}
	}
}

func (sa *Adapter) cacheApplicationConfigs() error {
	sa.logger.Info("cacheApplicationConfigs..")

	applicationConfigs, err := sa.LoadAppConfigs()
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationConfig, nil, err)
	}

	sa.setCachedApplicationConfigs(&applicationConfigs)

	return nil
}

func (sa *Adapter) setCachedApplicationConfigs(applicationConfigs *[]model.ApplicationConfig) {
	sa.applicationConfigsLock.Lock()
	defer sa.applicationConfigsLock.Unlock()

	sa.cachedApplicationConfigs = &syncmap.Map{}
	validate := validator.New()

	var currentKey string
	var currentConfigList []model.ApplicationConfig
	for _, config := range *applicationConfigs {

		err := validate.Struct(config)
		if err != nil {
			sa.logger.Errorf("failed to validate and cache application config with appID_version %s_%s: %s", config.AppOrg.ID, config.Version.VersionNumbers.String(), err.Error())
		} else {
			// key 1 - ID
			sa.cachedApplicationConfigs.Store(config.ID, config)

			// key 2 - cahce pair {appTypeID_appOrgID: []model.ApplicationConfigs}
			appTypeID := config.ApplicationType.ID
			key := appTypeID
			if config.AppOrg != nil {
				appOrgID := config.AppOrg.ID
				key = fmt.Sprintf("%s_%s", appTypeID, appOrgID)
			}

			if currentKey == "" {
				currentKey = key
			} else if currentKey != key {
				// cache processed list
				sa.cachedApplicationConfigs.Store(currentKey, currentConfigList)
				// init new key and configList
				currentKey = key
				currentConfigList = make([]model.ApplicationConfig, 0)
			}

			currentConfigList = append(currentConfigList, config)
		}
	}

	sa.cachedApplicationConfigs.Store(currentKey, currentConfigList)
}

func (sa *Adapter) getCachedApplicationConfigByAppTypeIDAndVersion(appTypeID string, appOrgID *string, versionNumbers *model.VersionNumbers) ([]model.ApplicationConfig, error) {
	sa.applicationConfigsLock.RLock()
	defer sa.applicationConfigsLock.RUnlock()

	var err error
	appConfigs := make([]model.ApplicationConfig, 0)

	key := appTypeID
	errArgs := &logutils.FieldArgs{"appTypeID": key, "version": versionNumbers.String()}
	if appOrgID != nil {
		key = fmt.Sprintf("%s_%s", appTypeID, *appOrgID)
		errArgs = &logutils.FieldArgs{"appTypeID_appOrgID": key, "version": versionNumbers.String()}
	}

	item, ok := sa.cachedApplicationConfigs.Load(key)
	if !ok {
		return nil, errors.ErrorAction(logutils.ActionLoadCache, model.TypeApplicationConfig, errArgs)
	}

	if item != nil {
		configList, ok := item.([]model.ApplicationConfig)
		if !ok {
			return nil, errors.ErrorAction(logutils.ActionCast, model.TypeApplicationConfig, errArgs)
		}

		if versionNumbers == nil {
			return configList, nil
		}

		// return highest version <= versionNumbers
		for _, config := range configList {
			if config.Version.VersionNumbers.LessThanOrEqualTo(versionNumbers) {
				appConfigs = append(appConfigs, config)
				break
			}
		}
	}

	return appConfigs, err
}

// get app config by id
func (sa *Adapter) getCachedApplicationConfigByID(id string) (*model.ApplicationConfig, error) {
	sa.applicationConfigsLock.RLock()
	defer sa.applicationConfigsLock.RUnlock()

	errArgs := &logutils.FieldArgs{"id": id}

	item, ok := sa.cachedApplicationConfigs.Load(id)
	if !ok {
		return nil, errors.ErrorAction(logutils.ActionLoadCache, model.TypeApplicationConfig, errArgs)
	}
	if item != nil {
		config, ok := item.(model.ApplicationConfig)
		if !ok {
			return nil, errors.ErrorAction(logutils.ActionCast, model.TypeApplicationConfig, errArgs)
		}
		return &config, nil
	}

	return nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationConfig, errArgs)
}

func (sa *Adapter) updateCachedApplicationConfigs(docID string, operation string, appConfig model.ApplicationConfig) {
	sa.applicationConfigsLock.RLock()
	defer sa.applicationConfigsLock.RUnlock()

	appTypeID := appConfig.ApplicationType.ID
	key := appTypeID
	if appConfig.AppOrg != nil {
		appOrgID := appConfig.AppOrg.ID
		key = fmt.Sprintf("%s_%s", appTypeID, appOrgID)
	}

	//TODO: may need to remove app configs cached by appTypeID or appTypeID_appOrgID on replace and update
	switch operation {
	case "insert":
		sa.cachedApplicationConfigs.Store(docID, appConfig)
		sa.cachedApplicationConfigs.Store(key, appConfig)
	case "replace":
		sa.cachedApplicationConfigs.Store(docID, appConfig)
		sa.cachedApplicationConfigs.Store(key, appConfig)
	case "update":
		sa.cachedApplicationConfigs.Store(docID, appConfig)
		sa.cachedApplicationConfigs.Store(key, appConfig)
	case "delete":
		item, loaded := sa.cachedApplicationConfigs.LoadAndDelete(docID)
		if loaded {
			if cachedAppConfig, ok := item.(model.ApplicationConfig); ok {
				appTypeID := cachedAppConfig.ApplicationType.ID
				key := appTypeID
				if cachedAppConfig.AppOrg != nil {
					appOrgID := cachedAppConfig.AppOrg.ID
					key = fmt.Sprintf("%s_%s", appTypeID, appOrgID)
				}
				sa.cachedApplicationConfigs.Delete(key)
			}
		}
	}
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

	_, err := sa.db.loginsSessions.InsertOneWithContext(context, storageLoginSession)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionInsert, model.TypeLoginSession, nil, err)
	}

	return nil
}

//FindLoginSessions finds login sessions by identifier and sorts by date created
func (sa *Adapter) FindLoginSessions(context TransactionContext, identifier string) ([]model.LoginSession, error) {
	filter := bson.D{primitive.E{Key: "identifier", Value: identifier}}
	opts := options.Find()
	opts.SetSort(bson.D{primitive.E{Key: "date_created", Value: 1}})

	var loginSessions []loginSession
	err := sa.db.loginsSessions.FindWithContext(context, filter, &loginSessions, opts)
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

//FindLoginSessionsByParams finds login sessions by params
func (sa *Adapter) FindLoginSessionsByParams(appID string, orgID string, sessionID *string, identifier *string, accountAuthTypeIdentifier *string,
	appTypeID *string, appTypeIdentifier *string, anonymous *bool, deviceID *string, ipAddress *string) ([]model.LoginSession, error) {
	filter := bson.D{primitive.E{Key: "app_id", Value: appID},
		primitive.E{Key: "org_id", Value: orgID}}

	if sessionID != nil {
		filter = append(filter, primitive.E{Key: "_id", Value: *sessionID})
	}

	if identifier != nil {
		filter = append(filter, primitive.E{Key: "identifier", Value: *identifier})
	}

	if accountAuthTypeIdentifier != nil {
		filter = append(filter, primitive.E{Key: "account_auth_type_identifier", Value: *accountAuthTypeIdentifier})
	}

	if appTypeID != nil {
		filter = append(filter, primitive.E{Key: "app_type_id", Value: appTypeID})
	}

	if appTypeIdentifier != nil {
		filter = append(filter, primitive.E{Key: "app_type_identifier", Value: appTypeIdentifier})
	}

	if anonymous != nil {
		filter = append(filter, primitive.E{Key: "anonymous", Value: anonymous})
	}

	if deviceID != nil {
		filter = append(filter, primitive.E{Key: "device_id", Value: deviceID})
	}

	if ipAddress != nil {
		filter = append(filter, primitive.E{Key: "ip_address", Value: ipAddress})
	}

	var result []loginSession
	options := options.Find()
	limitLoginSession := int64(20)
	options.SetLimit(limitLoginSession)
	err := sa.db.loginsSessions.Find(filter, &result, options)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeLoginSession, nil, err)
	}

	if len(result) == 0 {
		//no data
		return make([]model.LoginSession, 0), nil
	}

	loginSessions := make([]model.LoginSession, len(result))
	for i, ls := range result {
		//we could allow calling buildLoginSession function as we have limitted the items to max 20
		loginSession, err := sa.buildLoginSession(&ls)
		if err != nil {
			return nil, errors.WrapErrorAction("build", model.TypeLoginSession, nil, err)
		}
		loginSessions[i] = *loginSession
	}
	return loginSessions, nil
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
	err := sa.db.loginsSessions.FindOneAndUpdateWithContext(context, filter, update, &loginSession, &opts)
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
	err := sa.db.loginsSessions.ReplaceOneWithContext(context, filter, storageLoginSession, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeLoginSession, &logutils.FieldArgs{"_id": storageLoginSession.ID}, err)
	}

	return nil
}

//DeleteLoginSession deletes login session
func (sa *Adapter) DeleteLoginSession(context TransactionContext, id string) error {
	filter := bson.M{"_id": id}

	res, err := sa.db.loginsSessions.DeleteOneWithContext(context, filter, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeLoginSession, &logutils.FieldArgs{"_id": id}, err)
	}
	if res.DeletedCount != 1 {
		return errors.ErrorAction(logutils.ActionDelete, model.TypeLoginSession, logutils.StringArgs("unexpected deleted count"))
	}

	return nil
}

//DeleteLoginSessionsByIDs deletes login sessions by ids
func (sa *Adapter) DeleteLoginSessionsByIDs(transaction TransactionContext, ids []string) error {
	filter := bson.D{primitive.E{Key: "_id", Value: bson.M{"$in": ids}}}

	var res *mongo.DeleteResult
	var err error
	timeout := time.Millisecond * time.Duration(5000) //5 seconds
	if transaction != nil {
		res, err = sa.db.loginsSessions.DeleteManyWithParams(transaction, filter, nil, &timeout)
	} else {
		res, err = sa.db.loginsSessions.DeleteManyWithParams(context.Background(), filter, nil, &timeout)
	}

	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeLoginSession,
			&logutils.FieldArgs{"identifier": ids}, err)
	}

	sa.logger.Infof("%d were deleted", res.DeletedCount)
	return nil
}

//DeleteLoginSessionsByIdentifier deletes all login sessions with the identifier
func (sa *Adapter) DeleteLoginSessionsByIdentifier(context TransactionContext, identifier string) error {
	return sa.deleteLoginSessions(context, "identifier", identifier, false)
}

//DeleteLoginSessionByID deletes a login session by id
func (sa *Adapter) DeleteLoginSessionByID(context TransactionContext, id string) error {
	return sa.deleteLoginSessions(context, "_id", id, true)
}

//DeleteLoginSessionsByAccountAuthTypeID deletes login sessions by account auth type ID
func (sa *Adapter) DeleteLoginSessionsByAccountAuthTypeID(context TransactionContext, id string) error {
	return sa.deleteLoginSessions(context, "account_auth_type_id", id, false)
}

func (sa *Adapter) deleteLoginSessions(context TransactionContext, key string, value string, checkDeletedCount bool) error {
	filter := bson.M{key: value}

	res, err := sa.db.loginsSessions.DeleteManyWithContext(context, filter, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeLoginSession, &logutils.FieldArgs{key: value}, err)
	}
	if checkDeletedCount && res.DeletedCount < 1 {
		return errors.ErrorAction(logutils.ActionDelete, model.TypeLoginSession, logutils.StringArgs("unexpected deleted count"))
	}

	return nil
}

//DeleteLoginSessionsByAccountAndSessionID deletes all login sessions with the identifier and sessionID
func (sa *Adapter) DeleteLoginSessionsByAccountAndSessionID(context TransactionContext, identifier string, sessionID string) error {
	filter := bson.M{"identifier": identifier, "_id": sessionID}
	result, err := sa.db.loginsSessions.DeleteOne(filter, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeLoginSession, &logutils.FieldArgs{"identifier": identifier, "_id": sessionID}, err)
	}
	if result == nil {
		return errors.WrapErrorData(logutils.StatusInvalid, "result", &logutils.FieldArgs{"identifier": identifier, "_id": sessionID}, err)
	}
	deletedCount := result.DeletedCount
	if deletedCount == 0 {
		return errors.WrapErrorData(logutils.StatusMissing, model.TypeLoginSession, &logutils.FieldArgs{"identifier": identifier, "_id": sessionID}, err)
	}

	return nil
}

//DeleteMFAExpiredSessions deletes MFA expired sessions
func (sa *Adapter) DeleteMFAExpiredSessions() error {
	now := time.Now().UTC()

	filter := bson.D{primitive.E{Key: "state_expires", Value: bson.M{"$lte": now}}}

	_, err := sa.db.loginsSessions.DeleteMany(filter, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeLoginSession, &logutils.FieldArgs{"expires": now}, err)
	}

	return nil
}

//FindSessionsLazy finds all sessions for app/org but lazy filled.
// - lazy means that we make only one request to the logins sessions collection and fill the objects with what we have there.
// - i.e. we do not apply any relations
// - this partly filled is enough for some cases(expiration policy checks for example) but in the same time it give very good performace
func (sa *Adapter) FindSessionsLazy(appID string, orgID string) ([]model.LoginSession, error) {
	filter := bson.D{primitive.E{Key: "app_id", Value: appID}, primitive.E{Key: "org_id", Value: orgID}}

	var loginSessions []loginSession
	timeout := time.Millisecond * time.Duration(5000) //5 seconds
	err := sa.db.loginsSessions.FindWithParams(context.Background(), filter, &loginSessions, nil, &timeout)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeLoginSession,
			&logutils.FieldArgs{"app_id": appID, "org_id": orgID}, err)
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

		sessions[i] = loginSessionFromStorage(session, *authType, nil, *appOrg)
	}

	return sessions, nil
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
	options := options.Find()
	limitAccounts := int64(20)
	options.SetLimit(limitAccounts)
	err = sa.db.accounts.Find(filter, &list, options)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}

	accounts := accountsFromStorage(list, *appOrg)
	return accounts, nil
}

//FindAccountsByAccountID finds accounts
func (sa *Adapter) FindAccountsByAccountID(appID string, orgID string, accountIDs []string) ([]model.Account, error) {

	//find app org id
	appOrg, err := sa.getCachedApplicationOrganization(appID, orgID)
	if err != nil {
		return nil, errors.WrapErrorAction("error getting cached application organization", "", nil, err)
	}

	accountFilter := bson.D{primitive.E{Key: "_id", Value: bson.M{"$in": accountIDs}}}
	var accountResult []account
	err = sa.db.accounts.Find(accountFilter, &accountResult, nil)
	if err != nil {
		return nil, err
	}
	accounts := accountsFromStorage(accountResult, *appOrg)
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
	err := sa.db.accounts.FindWithContext(context, filter, &accounts, nil)
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

	filter := bson.M{"_id": account.ID}
	err := sa.db.accounts.ReplaceOneWithContext(context, filter, storageAccount, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionSave, model.TypeAccount, &logutils.FieldArgs{"_id": account.ID}, nil)
	}

	return nil
}

//DeleteAccount deletes an account
func (sa *Adapter) DeleteAccount(context TransactionContext, id string) error {
	//TODO - we have to decide what we do on delete user operation - removing all user relations, (or) mark the user disabled etc

	filter := bson.M{"_id": id}

	res, err := sa.db.accounts.DeleteOneWithContext(context, filter, nil)
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
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "date_updated", Value: time.Now().UTC()},
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

//DeleteAccountPermissions deletes permissions from an account
func (sa *Adapter) DeleteAccountPermissions(context TransactionContext, accountID string, permissions []model.Permission) error {
	//filter
	filter := bson.D{primitive.E{Key: "_id", Value: accountID}}

	//update
	permissionsIDs := make([]string, len(permissions))
	for i, permission := range permissions {
		permissionsIDs[i] = permission.ID
	}
	update := bson.D{
		primitive.E{Key: "$pull", Value: bson.D{
			primitive.E{Key: "permissions", Value: bson.M{"_id": bson.M{"$in": permissionsIDs}}},
		}},
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "date_updated", Value: time.Now().UTC()},
		}},
	}

	res, err := sa.db.accounts.UpdateOneWithContext(context, filter, update, nil)
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

//InsertAccountsGroup inserts accounts into a group
func (sa *Adapter) InsertAccountsGroup(group model.AccountGroup, accounts []model.Account) error {
	//prepare filter
	accountsIDs := make([]string, len(accounts))
	for i, cur := range accounts {
		accountsIDs[i] = cur.ID
	}
	filter := bson.D{primitive.E{Key: "_id", Value: bson.M{"$in": accountsIDs}}}

	//update
	storageGroup := accountGroupToStorage(group)
	update := bson.D{
		primitive.E{Key: "$push", Value: bson.D{
			primitive.E{Key: "groups", Value: storageGroup},
		}},
	}

	res, err := sa.db.accounts.UpdateMany(filter, update, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccount, nil, err)
	}
	sa.logger.Infof("modified %d accounts with added group", res.ModifiedCount)
	return nil
}

//RemoveAccountsGroup removes accounts from a group
func (sa *Adapter) RemoveAccountsGroup(groupID string, accounts []model.Account) error {
	//prepare filter
	accountsIDs := make([]string, len(accounts))
	for i, cur := range accounts {
		accountsIDs[i] = cur.ID
	}
	filter := bson.D{primitive.E{Key: "_id", Value: bson.M{"$in": accountsIDs}}}
	//update
	update := bson.D{
		primitive.E{Key: "$pull", Value: bson.D{
			primitive.E{Key: "groups", Value: bson.M{"group._id": groupID}},
		}},
	}

	res, err := sa.db.accounts.UpdateMany(filter, update, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccount, nil, err)
	}
	sa.logger.Infof("modified %d accounts with removed group", res.ModifiedCount)
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
func (sa *Adapter) DeleteAccountRoles(context TransactionContext, accountID string, roleIDs []string) error {
	//filter
	filter := bson.D{primitive.E{Key: "_id", Value: accountID}}

	//update
	update := bson.D{
		primitive.E{Key: "$pull", Value: bson.D{
			primitive.E{Key: "roles", Value: bson.M{"role._id": bson.M{"$in": roleIDs}}},
		}},
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "date_updated", Value: time.Now().UTC()},
		}},
	}

	res, err := sa.db.accounts.UpdateOneWithContext(context, filter, update, nil)
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

//DeleteAccountAuthType deletes an account auth type
func (sa *Adapter) DeleteAccountAuthType(context TransactionContext, item model.AccountAuthType) error {
	filter := bson.M{"_id": item.Account.ID}
	update := bson.D{
		primitive.E{Key: "$pull", Value: bson.D{
			primitive.E{Key: "auth_types", Value: bson.M{"auth_type_code": item.AuthType.Code, "identifier": item.Identifier}},
		}},
	}

	res, err := sa.db.accounts.UpdateOneWithContext(context, filter, update, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeAccountAuthType, nil, err)
	}
	if res.ModifiedCount != 1 {
		return errors.ErrorAction(logutils.ActionUpdate, model.TypeAccount, &logutils.FieldArgs{"unexpected modified count": res.ModifiedCount})
	}

	return nil
}

//UpdateAccountExternalIDs updates account external IDs
func (sa *Adapter) UpdateAccountExternalIDs(accountID string, externalIDs map[string]string) error {
	filter := bson.D{primitive.E{Key: "_id", Value: accountID}}
	now := time.Now().UTC()
	update := bson.D{
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "external_ids", Value: externalIDs},
			primitive.E{Key: "date_updated", Value: &now},
		}},
	}

	res, err := sa.db.accounts.UpdateOne(filter, update, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, "account external IDs", &logutils.FieldArgs{"_id": accountID}, err)
	}
	if res.ModifiedCount != 1 {
		return errors.ErrorAction(logutils.ActionUpdate, "account external IDs", &logutils.FieldArgs{"_id": accountID, "unexpected modified count": res.ModifiedCount})
	}

	return nil
}

//UpdateLoginSessionExternalIDs updates login session external IDs
func (sa *Adapter) UpdateLoginSessionExternalIDs(accountID string, externalIDs map[string]string) error {
	filter := bson.D{primitive.E{Key: "identifier", Value: accountID}}
	now := time.Now().UTC()
	update := bson.D{
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "external_ids", Value: externalIDs},
			primitive.E{Key: "date_updated", Value: &now},
		}},
	}

	_, err := sa.db.loginsSessions.UpdateMany(filter, update, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, "login session external IDs", &logutils.FieldArgs{"identifier": accountID}, err)
	}

	return nil
}

//CountAccountsByRoleID counts how many accounts there are with the passed role id
func (sa *Adapter) CountAccountsByRoleID(roleID string) (*int64, error) {
	filter := bson.D{primitive.E{Key: "roles._id", Value: roleID}}

	count, err := sa.db.accounts.CountDocuments(filter)
	if err != nil {
		return nil, errors.WrapErrorAction("error counting accounts for role id", "", &logutils.FieldArgs{"roles._id": roleID}, err)
	}
	return &count, nil
}

//CountAccountsByGroupID counts how many accounts there are with the passed group id
func (sa *Adapter) CountAccountsByGroupID(groupID string) (*int64, error) {
	filter := bson.D{primitive.E{Key: "groups._id", Value: groupID}}

	count, err := sa.db.accounts.CountDocuments(filter)
	if err != nil {
		return nil, errors.WrapErrorAction("error counting accounts for group id", "", &logutils.FieldArgs{"groups._id": groupID}, err)
	}
	return &count, nil
}

//FindCredential finds a credential by ID
func (sa *Adapter) FindCredential(context TransactionContext, ID string) (*model.Credential, error) {
	filter := bson.D{primitive.E{Key: "_id", Value: ID}}

	var creds credential
	err := sa.db.credentials.FindOneWithContext(context, filter, &creds, nil)
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
	err := sa.db.credentials.ReplaceOneWithContext(context, filter, storageCreds, nil)
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

	res, err := sa.db.credentials.DeleteOneWithContext(context, filter, nil)
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
	err := sa.db.accounts.FindOneWithContext(context, filter, &account, nil)
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

	res, err := sa.db.accounts.UpdateOneWithContext(context, filter, update, nil)
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

	res, err := sa.db.accounts.UpdateOneWithContext(context, filter, update, nil)
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

	res, err := sa.db.accounts.UpdateOneWithContext(context, filter, update, nil)
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

//FindPermissionsByServiceIDs finds permissions
func (sa *Adapter) FindPermissionsByServiceIDs(serviceIDs []string) ([]model.Permission, error) {
	if len(serviceIDs) == 0 {
		return nil, nil
	}

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

//FindAppOrgRoles finds all application organization roles fora given AppOrg ID
func (sa *Adapter) FindAppOrgRoles(appOrgID string) ([]model.AppOrgRole, error) {
	rolesFilter := bson.D{primitive.E{Key: "app_org_id", Value: appOrgID}}
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

//FindAppOrgRolesByIDs finds a set of application organization roles for the provided IDs
func (sa *Adapter) FindAppOrgRolesByIDs(ids []string, appOrgID string) ([]model.AppOrgRole, error) {
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

//FindAppOrgRole finds an application organization role
func (sa *Adapter) FindAppOrgRole(id string, appOrgID string) (*model.AppOrgRole, error) {
	filter := bson.D{primitive.E{Key: "_id", Value: id}, primitive.E{Key: "app_org_id", Value: appOrgID}}
	var rolesResult []appOrgRole
	err := sa.db.applicationsOrganizationsRoles.Find(filter, &rolesResult, nil)
	if err != nil {
		return nil, err
	}
	if len(rolesResult) == 0 {
		//no data
		return nil, nil
	}

	roles := rolesResult[0]

	appOrg, err := sa.getCachedApplicationOrganizationByKey(appOrgID)
	if err != nil {
		return nil, errors.WrapErrorData(logutils.StatusMissing, model.TypeOrganization, &logutils.FieldArgs{"app_org_id": appOrg}, err)
	}
	result := appOrgRoleFromStorage(&roles, *appOrg)
	return &result, nil
}

//InsertAppOrgRole inserts a new application organization role
func (sa *Adapter) InsertAppOrgRole(item model.AppOrgRole) error {
	role := appOrgRoleToStorage(item)
	_, err := sa.db.applicationsOrganizationsRoles.InsertOne(role)
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
//	- make sure to call this function once you have verified that there is no any relations
//	in other collections for the role which is supposed to be deleted.
func (sa *Adapter) DeleteAppOrgRole(id string) error {
	filter := bson.M{"_id": id}
	result, err := sa.db.applicationsOrganizationsRoles.DeleteOne(filter, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeAppOrgRole, &logutils.FieldArgs{"_id": id}, err)
	}
	if result == nil {
		return errors.WrapErrorData(logutils.StatusInvalid, "result", &logutils.FieldArgs{"_id": id}, err)
	}
	deletedCount := result.DeletedCount
	if deletedCount == 0 {
		return errors.WrapErrorData(logutils.StatusMissing, model.TypeAppOrgRole, &logutils.FieldArgs{"_id": id}, err)
	}
	return nil
}

//InsertAppOrgRolePermissions inserts permissions to role
func (sa *Adapter) InsertAppOrgRolePermissions(context TransactionContext, roleID string, permissions []model.Permission) error {

	filter := bson.D{primitive.E{Key: "_id", Value: roleID}}
	update := bson.D{
		primitive.E{Key: "$push", Value: bson.D{
			primitive.E{Key: "permissions", Value: bson.M{"$each": permissions}},
		}},
	}

	res, err := sa.db.applicationsOrganizationsRoles.UpdateOne(filter, update, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeAppOrgRole, nil, err)
	}
	if res.ModifiedCount != 1 {
		return errors.ErrorAction(logutils.ActionUpdate, model.TypeAppOrgRole, &logutils.FieldArgs{"unexpected modified count": res.ModifiedCount})
	}

	return nil
}

//FindAppOrgGroups finds all application organization groups for the provided AppOrg ID
func (sa *Adapter) FindAppOrgGroups(appOrgID string) ([]model.AppOrgGroup, error) {
	filter := bson.D{primitive.E{Key: "app_org_id", Value: appOrgID}}
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

//FindAppOrgGroupsByIDs finds a set of application organization groups for the provided IDs
func (sa *Adapter) FindAppOrgGroupsByIDs(ids []string, appOrgID string) ([]model.AppOrgGroup, error) {
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

//FindAppOrgGroup finds a application organization group
func (sa *Adapter) FindAppOrgGroup(id string, appOrgID string) (*model.AppOrgGroup, error) {
	filter := bson.D{primitive.E{Key: "_id", Value: id}, primitive.E{Key: "app_org_id", Value: appOrgID}}
	var groupsResult []appOrgGroup
	err := sa.db.applicationsOrganizationsGroups.Find(filter, &groupsResult, nil)
	if err != nil {
		return nil, err
	}
	if len(groupsResult) == 0 {
		//no data
		return nil, nil
	}

	group := groupsResult[0]

	appOrg, err := sa.getCachedApplicationOrganizationByKey(appOrgID)
	if err != nil {
		return nil, errors.WrapErrorData(logutils.StatusMissing, model.TypeOrganization, &logutils.FieldArgs{"app_org_id": appOrg}, err)
	}
	result := appOrgGroupFromStorage(&group, *appOrg)
	return &result, nil
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
//	- make sure to call this function once you have verified that there is no any relations
//	in other collections for the group which is supposed to be deleted.
func (sa *Adapter) DeleteAppOrgGroup(id string) error {
	filter := bson.M{"_id": id}
	result, err := sa.db.applicationsOrganizationsGroups.DeleteOne(filter, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeAppOrgGroup, &logutils.FieldArgs{"_id": id}, err)
	}
	if result == nil {
		return errors.WrapErrorData(logutils.StatusInvalid, "result", &logutils.FieldArgs{"_id": id}, err)
	}
	deletedCount := result.DeletedCount
	if deletedCount == 0 {
		return errors.WrapErrorData(logutils.StatusMissing, model.TypeAppOrgGroup, &logutils.FieldArgs{"_id": id}, err)
	}

	return nil
}

//CountGroupsByRoleID counts how many groups there are with the passed role id
func (sa *Adapter) CountGroupsByRoleID(roleID string) (*int64, error) {
	filter := bson.D{primitive.E{Key: "roles._id", Value: roleID}}

	count, err := sa.db.applicationsOrganizationsGroups.CountDocuments(filter)
	if err != nil {
		return nil, errors.WrapErrorAction("error counting groups for role id", "", &logutils.FieldArgs{"roles._id": roleID}, err)
	}
	return &count, nil
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

//UpdateProfile updates a profile
func (sa *Adapter) UpdateProfile(profile model.Profile) error {
	filter := bson.D{primitive.E{Key: "profile.id", Value: profile.ID}}

	now := time.Now().UTC()
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

	res, err := sa.db.accounts.UpdateMany(filter, profileUpdate, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeProfile, nil, err)
	}
	sa.logger.Infof("modified %d profile copies", res.ModifiedCount)

	return nil
}

//FindProfiles finds profiles by app id, authtype id and account auth type identifier
func (sa *Adapter) FindProfiles(appID string, authTypeID string, accountAuthTypeIdentifier string) ([]model.Profile, error) {
	pipeline := []bson.M{
		{"$lookup": bson.M{
			"from":         "applications_organizations",
			"localField":   "app_org_id",
			"foreignField": "_id",
			"as":           "app_org",
		}},
		{"$match": bson.M{"app_org.app_id": appID, "auth_types.auth_type_id": authTypeID, "auth_types.identifier": accountAuthTypeIdentifier}},
	}
	var accounts []account
	err := sa.db.accounts.Aggregate(pipeline, &accounts, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}
	if len(accounts) == 0 {
		//not found
		return nil, nil
	}

	result := profilesFromStorage(accounts, *sa)
	return result, nil
}

//CreateGlobalConfig creates global config
func (sa *Adapter) CreateGlobalConfig(context TransactionContext, globalConfig *model.GlobalConfig) error {
	if globalConfig == nil {
		return errors.ErrorData(logutils.StatusInvalid, logutils.TypeArg, logutils.StringArgs("global_config"))
	}

	_, err := sa.db.globalConfig.InsertOneWithContext(context, globalConfig)
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

	_, err := sa.db.globalConfig.DeleteManyWithContext(context, delFilter, nil)
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

//LoadAppConfigs loads all application configs
func (sa *Adapter) LoadAppConfigs() ([]model.ApplicationConfig, error) {
	filter := bson.D{}
	options := options.Find()
	options.SetSort(bson.D{primitive.E{Key: "app_type_id", Value: 1}, primitive.E{Key: "app_org_id", Value: 1}, primitive.E{Key: "version.version_numbers.major", Value: -1}, primitive.E{Key: "version.version_numbers.minor", Value: -1}, primitive.E{Key: "version.version_numbers.patch", Value: -1}}) //sort by version numbers
	var list []applicationConfig

	err := sa.db.applicationConfigs.Find(filter, &list, options)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationConfig, nil, err)
	}

	if len(list) == 0 {
		//no data
		return make([]model.ApplicationConfig, 0), nil
	}

	result := make([]model.ApplicationConfig, len(list))
	for i, item := range list {
		var appOrg *model.ApplicationOrganization
		if item.AppOrgID != nil {
			appOrg, err = sa.getCachedApplicationOrganizationByKey(*item.AppOrgID)
			if err != nil {
				return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationOrganization, nil, err)
			}
		}

		_, appType, err := sa.getCachedApplicationType(item.AppTypeID)
		if err != nil || appType == nil {
			return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationType, nil, err)
		}
		result[i] = appConfigFromStorage(&item, appOrg, *appType)
	}

	return result, nil
}

//FindAppConfigs finds appconfigs
func (sa *Adapter) FindAppConfigs(appTypeID string, appOrgID *string, versionNumbers *model.VersionNumbers) ([]model.ApplicationConfig, error) {
	return sa.getCachedApplicationConfigByAppTypeIDAndVersion(appTypeID, appOrgID, versionNumbers)
}

//FindAppConfigByVersion finds the most recent app config for the specified version
func (sa *Adapter) FindAppConfigByVersion(appTypeID string, appOrgID *string, versionNumbers model.VersionNumbers) (*model.ApplicationConfig, error) {
	configs, err := sa.getCachedApplicationConfigByAppTypeIDAndVersion(appTypeID, appOrgID, &versionNumbers)
	if err != nil {
		return nil, err
	}
	if len(configs) == 0 {
		return nil, nil
	}
	return &configs[0], nil
}

//FindAppConfigByID finds appconfig by ID
func (sa *Adapter) FindAppConfigByID(ID string) (*model.ApplicationConfig, error) {
	return sa.getCachedApplicationConfigByID(ID)
}

// InsertAppConfig inserts an appconfig
func (sa *Adapter) InsertAppConfig(item model.ApplicationConfig) (*model.ApplicationConfig, error) {
	appConfig := appConfigToStorage(item)
	_, err := sa.db.applicationConfigs.InsertOne(appConfig)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionInsert, model.TypeApplicationConfig, nil, err)
	}

	return &item, nil
}

// UpdateAppConfig updates an appconfig
func (sa *Adapter) UpdateAppConfig(ID string, appType model.ApplicationType, appOrg *model.ApplicationOrganization, version model.Version, data map[string]interface{}) error {
	now := time.Now()
	//TODO - use pointers and update only what not nil
	updatAppConfigFilter := bson.D{primitive.E{Key: "_id", Value: ID}}
	updateItem := bson.D{primitive.E{Key: "date_updated", Value: now}, primitive.E{Key: "app_type_id", Value: appType.ID}, primitive.E{Key: "version", Value: version}}
	// if version != "" {
	// 	updateItem = append(updateItem, primitive.E{Key: "version.date_updated", Value: now}, primitive.E{Key: "version.version_numbers", Value: versionNumbers}, primitive.E{Key: "version.app_type", Value: appType})
	// }
	if appOrg != nil {
		updateItem = append(updateItem, primitive.E{Key: "app_org_id", Value: appOrg.ID})
	} else {
		updateItem = append(updateItem, primitive.E{Key: "app_org_id", Value: nil})
	}

	if data != nil {
		updateItem = append(updateItem, primitive.E{Key: "data", Value: data})
	}

	updateAppConfig := bson.D{
		primitive.E{Key: "$set", Value: updateItem},
	}
	result, err := sa.db.applicationConfigs.UpdateOne(updatAppConfigFilter, updateAppConfig, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeApplicationConfig, &logutils.FieldArgs{"id": ID}, err)
	}
	if result.MatchedCount == 0 {
		return errors.WrapErrorData(logutils.StatusMissing, model.TypeApplicationConfig, &logutils.FieldArgs{"id": ID}, err)
	}

	return nil
}

// DeleteAppConfig deletes an appconfig
func (sa *Adapter) DeleteAppConfig(ID string) error {
	filter := bson.M{"_id": ID}
	result, err := sa.db.applicationConfigs.DeleteOne(filter, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeApplicationConfig, &logutils.FieldArgs{"_id": ID}, err)
	}
	if result == nil {
		return errors.WrapErrorData(logutils.StatusInvalid, "result", &logutils.FieldArgs{"_id": ID}, err)
	}
	deletedCount := result.DeletedCount
	if deletedCount == 0 {
		return errors.WrapErrorData(logutils.StatusMissing, model.TypeApplicationConfig, &logutils.FieldArgs{"_id": ID}, err)
	}

	return nil
}

//FindApplicationType finds an application type by ID or identifier
func (sa *Adapter) FindApplicationType(id string) (*model.ApplicationType, error) {
	app, appType, err := sa.getCachedApplicationType(id)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationType, nil, err)
	}

	appType.Application = *app

	return appType, nil
}

//FindApplicationsOrganizationsByOrgID finds a set of applications organizations
func (sa *Adapter) FindApplicationsOrganizationsByOrgID(orgID string) ([]model.ApplicationOrganization, error) {
	applicationsOrgFilter := bson.D{primitive.E{Key: "org_id", Value: orgID}}
	var applicationsOrgResult []applicationOrganization
	err := sa.db.applicationsOrganizations.Find(applicationsOrgFilter, &applicationsOrgResult, nil)
	if err != nil {
		return nil, err
	}

	if len(applicationsOrgResult) == 0 {
		//no data
		return make([]model.ApplicationOrganization, 0), nil
	}

	result := make([]model.ApplicationOrganization, len(applicationsOrgResult))
	organization, err := sa.getCachedOrganization(orgID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeOrganization, nil, err)
	}
	for i, item := range applicationsOrgResult {
		//we have organizations and applications cached
		application, err := sa.getCachedApplication(item.AppID)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplication, nil, err)
		}

		result[i] = applicationOrganizationFromStorage(item, *application, *organization)
	}
	return result, nil
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

//FindApplicationOrganization finds application organization
func (sa *Adapter) FindApplicationOrganization(appID string, orgID string) (*model.ApplicationOrganization, error) {
	return sa.getCachedApplicationOrganization(appID, orgID)
}

//FindDevice finds a device by device id and account id
func (sa *Adapter) FindDevice(context TransactionContext, deviceID string, accountID string) (*model.Device, error) {
	filter := bson.D{primitive.E{Key: "device_id", Value: deviceID},
		primitive.E{Key: "account_id", Value: accountID}}
	var result []device

	err := sa.db.devices.FindWithContext(context, filter, &result, nil)
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

	_, err := sa.db.devices.InsertOneWithContext(context, storageDevice)
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

	res, err := sa.db.accounts.UpdateOneWithContext(context, filter, update, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccount, logutils.StringArgs("inserting device"), err)
	}
	if res.ModifiedCount != 1 {
		return nil, errors.ErrorAction(logutils.ActionUpdate, model.TypeAccount, &logutils.FieldArgs{"unexpected modified count": res.ModifiedCount})
	}

	return &device, nil
}

//InsertAuthType inserts an auth type
func (sa *Adapter) InsertAuthType(authType model.AuthType) (*model.AuthType, error) {
	_, err := sa.db.authTypes.InsertOne(authType)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionInsert, model.TypeAuthType, nil, err)
	}

	return &authType, nil
}

//UpdateAuthTypes updates an auth type
func (sa *Adapter) UpdateAuthTypes(ID string, code string, description string, isExternal bool, isAnonymous bool,
	useCredentials bool, ignoreMFA bool, params map[string]interface{}) error {

	now := time.Now()
	updateAuthTypeFilter := bson.D{primitive.E{Key: "_id", Value: ID}}
	updateAuthType := bson.D{
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "code", Value: code},
			primitive.E{Key: "description", Value: description},
			primitive.E{Key: "is_external", Value: isExternal},
			primitive.E{Key: "is_anonymous", Value: isAnonymous},
			primitive.E{Key: "use_credentials", Value: useCredentials},
			primitive.E{Key: "ignore_mfa", Value: ignoreMFA},
			primitive.E{Key: "params", Value: params},
			primitive.E{Key: "date_updated", Value: now},
		}},
	}

	result, err := sa.db.authTypes.UpdateOne(updateAuthTypeFilter, updateAuthType, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAuthType, &logutils.FieldArgs{"id": ID}, err)
	}
	if result.MatchedCount == 0 {
		return errors.WrapErrorData(logutils.StatusMissing, model.TypeAuthType, &logutils.FieldArgs{"id": ID}, err)
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

	filter := bson.M{"_id": device.ID}
	opts := options.Replace().SetUpsert(true)

	err := sa.db.devices.ReplaceOneWithContext(context, filter, storageDevice, opts)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionSave, "device", &logutils.FieldArgs{"device_id": device.ID}, nil)
	}

	return nil
}

//DeleteDevice deletes a device
func (sa *Adapter) DeleteDevice(context TransactionContext, id string) error {
	filter := bson.M{"_id": id}

	res, err := sa.db.devices.DeleteOneWithContext(context, filter, nil)
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

	cachedApplicationConfigs := &syncmap.Map{}
	applicationConfigsLock := &sync.RWMutex{}

	db := &database{mongoDBAuth: mongoDBAuth, mongoDBName: mongoDBName, mongoTimeout: timeout, logger: logger}
	return &Adapter{db: db, logger: logger, cachedOrganizations: cachedOrganizations, organizationsLock: organizationsLock,
		cachedApplications: cachedApplications, applicationsLock: applicationsLock,
		cachedAuthTypes: cachedAuthTypes, authTypesLock: authTypesLock,
		cachedApplicationsOrganizations: cachedApplicationsOrganizations, applicationsOrganizationsLock: applicationsOrganizationsLock, cachedApplicationConfigs: cachedApplicationConfigs, applicationConfigsLock: applicationConfigsLock}
}

type storageListener struct {
	adapter *Adapter
	DefaultListenerImpl
}

func (sl *storageListener) OnAuthTypesUpdated(docID string, operation string, authType model.AuthType) {
	sl.adapter.updateCachedAuthTypes(docID, operation, authType)
}

func (sl *storageListener) OnOrganizationsUpdated(docID string, operation string, org organization) {
	sl.adapter.updateCachedOrganizations(docID, operation, organizationFromStorage(&org))
}

func (sl *storageListener) OnApplicationsUpdated(docID string, operation string, app application) {
	sl.adapter.updateCachedApplications(docID, operation, applicationFromStorage(&app))
}

func (sl *storageListener) OnApplicationsOrganizationsUpdated(docID string, operation string, appOrg applicationOrganization) {
	app, err := sl.adapter.getCachedApplication(appOrg.AppID)
	if err != nil {
		sl.adapter.logger.Errorf("error loading application from cache: %v", err)
		return
	}
	if app == nil {
		sl.adapter.logger.Errorf("application %s missing from cache", appOrg.AppID)
		return
	}

	org, err := sl.adapter.getCachedOrganization(appOrg.OrgID)
	if err != nil {
		sl.adapter.logger.Errorf("error loading organization from cache: %v", err)
		return
	}
	if org == nil {
		sl.adapter.logger.Errorf("organization %s missing from cache", appOrg.OrgID)
		return
	}

	sl.adapter.updateCachedApplicationsOrganizations(docID, operation, applicationOrganizationFromStorage(appOrg, *app, *org))
}

func (sl *storageListener) OnApplicationConfigsUpdated(docID string, operation string, appConfig applicationConfig) {
	var appOrg *model.ApplicationOrganization
	var err error
	if appConfig.AppOrgID != nil {
		appOrg, err = sl.adapter.getCachedApplicationOrganizationByKey(*appConfig.AppOrgID)
		if err != nil {
			sl.adapter.logger.Errorf("error loading application organization from cache: %v", err)
			return
		}
		if appOrg == nil {
			sl.adapter.logger.Errorf("application organization %s missing from cache", *appConfig.AppOrgID)
			return
		}
	}
	_, appType, err := sl.adapter.getCachedApplicationType(appConfig.AppTypeID)
	if err != nil {
		sl.adapter.logger.Errorf("error loading application type from cache: %v", err)
		return
	}
	if appType == nil {
		sl.adapter.logger.Errorf("application type %s missing from cache", appConfig.AppTypeID)
		return
	}

	sl.adapter.updateCachedApplicationConfigs(docID, operation, appConfigFromStorage(&appConfig, appOrg, *appType))
}

//Listener represents storage listener
type Listener interface {
	OnAPIKeysUpdated(docID string, operation string, apiKey model.APIKey)
	OnAuthTypesUpdated(docID string, operation string, authType model.AuthType)
	OnIdentityProvidersUpdated(docID string, operation string, idPr model.IdentityProvider)
	OnServiceRegsUpdated(docID string, operation string, serviceReg model.ServiceReg)
	OnOrganizationsUpdated(docID string, operation string, org organization)
	OnApplicationsUpdated(docID string, operation string, app application)
	OnApplicationsOrganizationsUpdated(docID string, operation string, appOrg applicationOrganization)
	OnApplicationConfigsUpdated(docID string, operation string, appConfig applicationConfig)
}

//DefaultListenerImpl default listener implementation
type DefaultListenerImpl struct{}

//OnAPIKeysUpdated notifies api keys have been updated
func (d *DefaultListenerImpl) OnAPIKeysUpdated(docID string, operation string, apiKey model.APIKey) {
}

//OnAuthTypesUpdated notifies auth types have been updated
func (d *DefaultListenerImpl) OnAuthTypesUpdated(docID string, operation string, authType model.AuthType) {
}

//OnIdentityProvidersUpdated notifies identity providers have been updated
func (d *DefaultListenerImpl) OnIdentityProvidersUpdated(docID string, operation string, idPr model.IdentityProvider) {
}

//OnServiceRegsUpdated notifies services regs have been updated
func (d *DefaultListenerImpl) OnServiceRegsUpdated(docID string, operation string, serviceReg model.ServiceReg) {
}

//OnOrganizationsUpdated notifies organizations have been updated
func (d *DefaultListenerImpl) OnOrganizationsUpdated(docID string, operation string, org organization) {
}

//OnApplicationsUpdated notifies applications have been updated
func (d *DefaultListenerImpl) OnApplicationsUpdated(docID string, operation string, app application) {
}

//OnApplicationsOrganizationsUpdated notifies applications organizations have been updated
func (d *DefaultListenerImpl) OnApplicationsOrganizationsUpdated(docID string, operation string, appOrg applicationOrganization) {
}

//OnApplicationConfigsUpdated notifies application configs have been updated
func (d *DefaultListenerImpl) OnApplicationConfigsUpdated(docID string, operation string, appConfig applicationConfig) {
}

//TransactionContext wraps mongo.SessionContext for use by external packages
type TransactionContext interface {
	mongo.SessionContext
}
