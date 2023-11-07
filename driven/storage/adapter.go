// Copyright 2022 Board of Trustees of the University of Illinois.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package storage

import (
	"context"
	"core-building-block/core/model"
	"core-building-block/utils"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rokwire/core-auth-library-go/v3/authutils"
	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logs"
	"github.com/rokwire/logging-library-go/v2/logutils"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/sync/syncmap"
	"gopkg.in/go-playground/validator.v9"
)

// Adapter implements the Storage interface
type Adapter struct {
	db *database

	host string

	logger *logs.Logger

	cachedServiceRegs *syncmap.Map
	serviceRegsLock   *sync.RWMutex

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

	cachedConfigs *syncmap.Map
	configsLock   *sync.RWMutex
}

// Start starts the storage
func (sa *Adapter) Start() error {
	//start db
	err := sa.db.start()
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionInitialize, "storage adapter", nil, err)
	}

	//register storage listener
	sl := storageListener{adapter: sa}
	sa.RegisterStorageListener(&sl)

	//cache the service regs
	err = sa.cacheServiceRegs()
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionCache, model.TypeServiceReg, nil, err)
	}

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

	// cache configs
	err = sa.cacheConfigs()
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionCache, model.TypeConfig, nil, err)
	}

	return err
}

// RegisterStorageListener registers a data change listener with the storage adapter
func (sa *Adapter) RegisterStorageListener(storageListener Listener) {
	sa.db.listeners = append(sa.db.listeners, storageListener)
}

// PerformTransaction performs a transaction
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

// cacheServiceRegs caches the service regs from the DB
func (sa *Adapter) cacheServiceRegs() error {
	sa.logger.Info("cacheServiceRegs..")

	serviceRegs, err := sa.loadServiceRegs()
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeServiceReg, nil, err)
	}

	sa.setCachedServiceRegs(&serviceRegs)

	return nil
}

func (sa *Adapter) setCachedServiceRegs(serviceRegs *[]model.ServiceRegistration) {
	sa.serviceRegsLock.Lock()
	defer sa.serviceRegsLock.Unlock()

	sa.cachedServiceRegs = &syncmap.Map{}
	for _, serviceReg := range *serviceRegs {
		sa.cacheServiceReg(serviceReg)
	}
}

func (sa *Adapter) cacheServiceReg(reg model.ServiceRegistration) {
	sa.cachedServiceRegs.Store(reg.Registration.ServiceID, reg)
}

func (sa *Adapter) getCachedServiceReg(serviceID string) (*model.ServiceRegistration, error) {
	sa.serviceRegsLock.RLock()
	defer sa.serviceRegsLock.RUnlock()

	errArgs := &logutils.FieldArgs{"registration.service_id": serviceID}

	item, _ := sa.cachedServiceRegs.Load(serviceID)
	if item != nil {
		serviceReg, ok := item.(model.ServiceRegistration)
		if !ok {
			return nil, errors.ErrorAction(logutils.ActionCast, model.TypeServiceReg, errArgs)
		}
		return &serviceReg, nil
	}
	return nil, nil
}

func (sa *Adapter) getCachedServiceRegs(serviceIDs []string) []model.ServiceRegistration {
	sa.serviceRegsLock.RLock()
	defer sa.serviceRegsLock.RUnlock()

	serviceRegList := make([]model.ServiceRegistration, 0)
	if !utils.Contains(serviceIDs, "all") {
		for _, serviceID := range serviceIDs {
			item, _ := sa.cachedServiceRegs.Load(serviceID)
			serviceReg := sa.processCachedServiceReg(serviceID, item)
			if serviceReg != nil {
				serviceRegList = append(serviceRegList, *serviceReg)
			}
		}
	} else {
		sa.cachedServiceRegs.Range(func(key, item interface{}) bool {
			serviceReg := sa.processCachedServiceReg(key, item)
			if serviceReg != nil {
				serviceRegList = append(serviceRegList, *serviceReg)
			}
			return true
		})
	}

	return serviceRegList
}

func (sa *Adapter) processCachedServiceReg(key, item interface{}) *model.ServiceRegistration {
	errArgs := &logutils.FieldArgs{"registration.service_id": key}
	if item == nil {
		sa.logger.Warn(errors.ErrorData(logutils.StatusInvalid, model.TypeServiceReg, errArgs).Error())
		return nil
	}

	serviceReg, ok := item.(model.ServiceRegistration)
	if !ok {
		sa.logger.Warn(errors.ErrorAction(logutils.ActionCast, model.TypeServiceReg, errArgs).Error())
		return nil
	}

	return &serviceReg
}

// cacheOrganizations caches the organizations from the DB
func (sa *Adapter) cacheOrganizations() error {
	sa.logger.Info("cacheOrganizations..")

	organizations, err := sa.loadOrganizations()
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
	return nil, nil
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

// cacheApplications caches the applications
func (sa *Adapter) cacheApplications() error {
	sa.logger.Info("cacheApplications..")

	applications, err := sa.loadApplications()
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

	errArgs := &logutils.FieldArgs{"id": appID}

	item, _ := sa.cachedApplications.Load(appID)
	if item != nil {
		application, ok := item.(model.Application)
		if !ok {
			return nil, errors.ErrorAction(logutils.ActionCast, model.TypeApplication, errArgs)
		}
		return &application, nil
	}
	return nil, nil
}

func (sa *Adapter) getCachedApplications() ([]model.Application, error) {
	sa.applicationsLock.RLock()
	defer sa.applicationsLock.RUnlock()

	var err error
	applicationList := make([]model.Application, 0)
	sa.cachedApplications.Range(func(key, item interface{}) bool {
		errArgs := &logutils.FieldArgs{"app_id": key}
		if item == nil {
			err = errors.ErrorData(logutils.StatusInvalid, model.TypeApplication, errArgs)
			return false
		}

		application, ok := item.(model.Application)
		if !ok {
			err = errors.ErrorAction(logutils.ActionCast, model.TypeApplication, errArgs)
			return false
		}
		applicationList = append(applicationList, application)
		return true
	})

	return applicationList, err
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

// cacheAuthTypes caches the auth types
func (sa *Adapter) cacheAuthTypes() error {
	sa.logger.Info("cacheAuthTypes..")

	authTypes, err := sa.loadAuthTypes()
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
			sa.setCachedAuthType(authType)
		} else {
			sa.logger.Errorf("failed to validate and cache auth type with code %s: %s", authType.Code, err.Error())
		}
	}
}

func (sa *Adapter) setCachedAuthType(authType model.AuthType) {
	sa.cachedAuthTypes.Store(authType.ID, authType)
	sa.cachedAuthTypes.Store(authType.Code, authType)
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
	return nil, nil
}

func (sa *Adapter) getCachedAuthTypes() ([]model.AuthType, error) {
	sa.authTypesLock.RLock()
	defer sa.authTypesLock.RUnlock()

	var err error
	authTypeList := make([]model.AuthType, 0)
	idsFound := make([]string, 0)
	sa.cachedAuthTypes.Range(func(key, item interface{}) bool {
		errArgs := &logutils.FieldArgs{"code or id": key}
		if item == nil {
			err = errors.ErrorData(logutils.StatusInvalid, model.TypeAuthType, errArgs)
			return false
		}

		authType, ok := item.(model.AuthType)
		if !ok {
			err = errors.ErrorAction(logutils.ActionCast, model.TypeAuthType, errArgs)
			return false
		}

		if !utils.Contains(idsFound, authType.ID) {
			authTypeList = append(authTypeList, authType)
			idsFound = append(idsFound, authType.ID)
		}

		return true
	})

	return authTypeList, err
}

// cacheApplicationsOrganizations caches the applications organizations
func (sa *Adapter) cacheApplicationsOrganizations() error {
	sa.logger.Info("cacheApplicationsOrganizations..")

	applicationsOrganizations, err := sa.loadApplicationsOrganizations()
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
	return nil, nil
}

func (sa *Adapter) getCachedApplicationOrganizationByKeys(keys []string) ([]model.ApplicationOrganization, error) {
	sa.applicationsOrganizationsLock.RLock()
	defer sa.applicationsOrganizationsLock.RUnlock()

	var result []model.ApplicationOrganization
	for _, key := range keys {
		errArgs := &logutils.FieldArgs{"key": key}

		item, exists := sa.cachedApplicationsOrganizations.Load(key)
		if exists {
			appOrg, ok := item.(model.ApplicationOrganization)
			if !ok {
				return nil, errors.ErrorAction(logutils.ActionCast, model.TypeApplicationOrganization, errArgs)
			}
			result = append(result, appOrg)
		}
	}

	return result, nil
}

func (sa *Adapter) getCachedApplicationOrganizations() ([]model.ApplicationOrganization, error) {
	sa.applicationsOrganizationsLock.RLock()
	defer sa.applicationsOrganizationsLock.RUnlock()

	var err error
	appOrgList := make([]model.ApplicationOrganization, 0)
	idsFound := make([]string, 0)
	sa.cachedApplicationsOrganizations.Range(func(key, item interface{}) bool {
		errArgs := &logutils.FieldArgs{"key": key}
		if item == nil {
			err = errors.ErrorData(logutils.StatusInvalid, model.TypeApplicationOrganization, errArgs)
			return false
		}

		appOrg, ok := item.(model.ApplicationOrganization)
		if !ok {
			err = errors.ErrorAction(logutils.ActionCast, model.TypeApplicationOrganization, errArgs)
			return false
		}

		if !utils.Contains(idsFound, appOrg.ID) {
			appOrgList = append(appOrgList, appOrg)
			idsFound = append(idsFound, appOrg.ID)
		}

		return true
	})

	return appOrgList, err
}

func (sa *Adapter) cacheApplicationConfigs() error {
	sa.logger.Info("cacheApplicationConfigs..")

	applicationConfigs, err := sa.loadAppConfigs()
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionLoad, model.TypeApplicationConfig, nil, err)
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
			sa.logger.Errorf("failed to validate and cache application config with appOrgID_version %s_%s: %s", config.AppOrg.ID, config.Version.VersionNumbers.String(), err.Error())
		} else {
			// key 1 - ID
			sa.cachedApplicationConfigs.Store(config.ID, config)

			// key 2 - cache pair {appTypeID_appOrgID: []model.ApplicationConfigs}
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

	return appConfigs, nil
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

// cacheConfigs caches the configs from the DB
func (sa *Adapter) cacheConfigs() error {
	sa.db.logger.Info("cacheConfigs...")

	configs, err := sa.loadConfigs()
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionLoad, model.TypeConfig, nil, err)
	}

	sa.setCachedConfigs(configs)

	return nil
}

func (sa *Adapter) setCachedConfigs(configs []model.Config) {
	sa.configsLock.Lock()
	defer sa.configsLock.Unlock()

	sa.cachedConfigs = &syncmap.Map{}

	for _, config := range configs {
		var err error
		switch config.Type {
		case model.ConfigTypeEnv:
			err = parseConfigsData[model.EnvConfigData](&config)
		default:
			err = parseConfigsData[map[string]interface{}](&config)
		}
		if err != nil {
			sa.db.logger.Warn(err.Error())
		}
		sa.cachedConfigs.Store(config.ID, config)
		sa.cachedConfigs.Store(fmt.Sprintf("%s_%s_%s", config.Type, config.AppID, config.OrgID), config)
	}
}

func parseConfigsData[T model.ConfigData](config *model.Config) error {
	bsonBytes, err := bson.Marshal(config.Data)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUnmarshal, model.TypeConfig, nil, err)
	}

	var data T
	err = bson.Unmarshal(bsonBytes, &data)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUnmarshal, model.TypeConfigData, &logutils.FieldArgs{"type": config.Type}, err)
	}

	config.Data = data
	return nil
}

func (sa *Adapter) getCachedConfig(id string, configType string, appID string, orgID string) (*model.Config, error) {
	sa.configsLock.RLock()
	defer sa.configsLock.RUnlock()

	var item any
	var errArgs logutils.FieldArgs
	if id != "" {
		errArgs = logutils.FieldArgs{"id": id}
		item, _ = sa.cachedConfigs.Load(id)
	} else {
		errArgs = logutils.FieldArgs{"type": configType, "app_id": appID, "org_id": orgID}
		item, _ = sa.cachedConfigs.Load(fmt.Sprintf("%s_%s_%s", configType, appID, orgID))
	}

	if item != nil {
		config, ok := item.(model.Config)
		if !ok {
			return nil, errors.ErrorAction(logutils.ActionCast, model.TypeConfig, &errArgs)
		}
		return &config, nil
	}
	return nil, nil
}

func (sa *Adapter) getCachedConfigs(configType *string) ([]model.Config, error) {
	sa.configsLock.RLock()
	defer sa.configsLock.RUnlock()

	var err error
	configList := make([]model.Config, 0)
	sa.cachedConfigs.Range(func(key, item interface{}) bool {
		keyStr, ok := key.(string)
		if !ok || item == nil {
			return false
		}
		if !strings.Contains(keyStr, "_") {
			return true
		}

		config, ok := item.(model.Config)
		if !ok {
			err = errors.ErrorAction(logutils.ActionCast, model.TypeConfig, &logutils.FieldArgs{"key": key})
			return false
		}

		if configType == nil || strings.HasPrefix(keyStr, fmt.Sprintf("%s_", *configType)) {
			configList = append(configList, config)
		}

		return true
	})

	return configList, err
}

// loadAuthTypes loads all auth types
func (sa *Adapter) loadAuthTypes() ([]model.AuthType, error) {
	filter := bson.D{}
	var result []model.AuthType
	err := sa.db.authTypes.Find(filter, &result, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAuthType, nil, err)
	}

	return result, nil
}

// FindAuthType finds auth type by id or code
func (sa *Adapter) FindAuthType(codeOrID string) (*model.AuthType, error) {
	return sa.getCachedAuthType(codeOrID)
}

// FindAuthTypes finds all auth types
func (sa *Adapter) FindAuthTypes() ([]model.AuthType, error) {
	return sa.getCachedAuthTypes()
}

// InsertFollow inserts a follow to specified user
func (sa *Adapter) InsertFollow(context TransactionContext, follow model.Follow) error {
	_, err := sa.db.follows.InsertOneWithContext(context, follow)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionInsert, model.TypeFollow, nil, err)
	}

	return nil
}

// DeleteFollow deletes a specified follow relationship
func (sa *Adapter) DeleteFollow(context TransactionContext, appID string, orgID string, followingID string, followerID string) error {
	filter := bson.D{primitive.E{Key: "app_id", Value: appID},
		primitive.E{Key: "org_id", Value: orgID},
		primitive.E{Key: "following_id", Value: followingID},
		primitive.E{Key: "follower_id", Value: followerID}}

	res, err := sa.db.follows.DeleteOneWithContext(context, filter, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeFollow, nil, err)
	}
	if res.DeletedCount != 1 {
		return errors.ErrorAction(logutils.ActionDelete, model.TypeFollow, logutils.StringArgs("unexpected deleted count"))
	}

	return nil
}

// InsertLoginSession inserts login session
func (sa *Adapter) InsertLoginSession(context TransactionContext, session model.LoginSession) error {
	storageLoginSession := loginSessionToStorage(session)

	_, err := sa.db.loginsSessions.InsertOneWithContext(context, storageLoginSession)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionInsert, model.TypeLoginSession, nil, err)
	}

	return nil
}

// FindLoginSessions finds login sessions by identifier and sorts by date created
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
			return nil, errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeAuthType, &logutils.FieldArgs{"code": session.AuthTypeCode}, err)
		}
		if authType == nil {
			return nil, errors.ErrorData(logutils.StatusMissing, model.TypeAuthType, &logutils.FieldArgs{"code": session.AuthTypeCode})
		}

		//application organization - from cache
		appOrg, err := sa.getCachedApplicationOrganization(session.AppID, session.OrgID)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeApplicationOrganization, &logutils.FieldArgs{"app_id": session.AppID, "org_id": session.OrgID}, err)
		}
		if appOrg == nil {
			return nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationOrganization, &logutils.FieldArgs{"app_id": session.AppID, "org_id": session.OrgID})
		}

		sessions[i] = loginSessionFromStorage(session, *authType, account, *appOrg)
	}

	return sessions, nil
}

// FindLoginSessionsByParams finds login sessions by params
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
		loginSession, err := sa.buildLoginSession(nil, &ls)
		if err != nil {
			return nil, errors.WrapErrorAction("building", model.TypeLoginSession, nil, err)
		}
		loginSessions[i] = *loginSession
	}
	return loginSessions, nil
}

// FindLoginSession finds a login session
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

	return sa.buildLoginSession(nil, &loginSession)
}

// FindAndUpdateLoginSession finds and updates a login session
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

	return sa.buildLoginSession(context, &loginSession)
}

func (sa *Adapter) buildLoginSession(context TransactionContext, ls *loginSession) (*model.LoginSession, error) {
	//account - from storage
	var account *model.Account
	var err error
	if ls.AccountAuthTypeID != nil {
		account, err = sa.FindAccountByID(context, ls.Identifier)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, &logutils.FieldArgs{"_id": ls.Identifier}, err)
		}
	}

	//auth type - from cache
	authType, err := sa.getCachedAuthType(ls.AuthTypeCode)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeAuthType, &logutils.FieldArgs{"code": ls.AuthTypeCode}, err)
	}
	if authType == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeAuthType, &logutils.FieldArgs{"code": ls.AuthTypeCode})
	}

	//application organization - from cache
	appOrg, err := sa.getCachedApplicationOrganization(ls.AppID, ls.OrgID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeApplicationOrganization, &logutils.FieldArgs{"app_id": ls.AppID, "org_id": ls.OrgID}, err)
	}
	if appOrg == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationOrganization, &logutils.FieldArgs{"app_id": ls.AppID, "org_id": ls.OrgID})
	}

	modelLoginSession := loginSessionFromStorage(*ls, *authType, account, *appOrg)
	return &modelLoginSession, nil
}

// UpdateLoginSession updates login session
func (sa *Adapter) UpdateLoginSession(context TransactionContext, loginSession model.LoginSession) error {
	storageLoginSession := loginSessionToStorage(loginSession)

	filter := bson.D{primitive.E{Key: "_id", Value: storageLoginSession.ID}}
	err := sa.db.loginsSessions.ReplaceOneWithContext(context, filter, storageLoginSession, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeLoginSession, &logutils.FieldArgs{"_id": storageLoginSession.ID}, err)
	}

	return nil
}

// DeleteLoginSession deletes login session
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

// DeleteLoginSessionsByIDs deletes login sessions by ids
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
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeLoginSession, &logutils.FieldArgs{"identifier": ids}, err)
	}

	sa.logger.Infof("%d were deleted", res.DeletedCount)
	return nil
}

// DeleteLoginSessionsByIdentifier deletes all login sessions with the identifier
func (sa *Adapter) DeleteLoginSessionsByIdentifier(context TransactionContext, identifier string) error {
	return sa.deleteLoginSessions(context, "identifier", identifier, false)
}

// DeleteLoginSessionByID deletes a login session by id
func (sa *Adapter) DeleteLoginSessionByID(context TransactionContext, id string) error {
	return sa.deleteLoginSessions(context, "_id", id, true)
}

// DeleteLoginSessionsByAccountAuthTypeID deletes login sessions by account auth type ID
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
		return errors.ErrorAction(logutils.ActionDelete, model.TypeLoginSession, &logutils.FieldArgs{key: value, "deleted": res.DeletedCount})
	}
	return nil
}

// DeleteLoginSessionsByAccountAndSessionID deletes all login sessions with the identifier and sessionID
func (sa *Adapter) DeleteLoginSessionsByAccountAndSessionID(context TransactionContext, identifier string, sessionID string) error {
	filter := bson.M{"identifier": identifier, "_id": sessionID}
	result, err := sa.db.loginsSessions.DeleteOne(filter, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeLoginSession, &logutils.FieldArgs{"identifier": identifier, "_id": sessionID}, err)
	}
	if result == nil {
		return errors.WrapErrorData(logutils.StatusInvalid, "delete result", &logutils.FieldArgs{"identifier": identifier, "_id": sessionID}, err)
	}
	deletedCount := result.DeletedCount
	if deletedCount == 0 {
		return errors.WrapErrorData(logutils.StatusMissing, model.TypeLoginSession, &logutils.FieldArgs{"identifier": identifier, "_id": sessionID}, err)
	}

	return nil
}

// DeleteMFAExpiredSessions deletes MFA expired sessions
func (sa *Adapter) DeleteMFAExpiredSessions() error {
	now := time.Now().UTC()

	filter := bson.D{primitive.E{Key: "state_expires", Value: bson.M{"$lte": now}}}

	_, err := sa.db.loginsSessions.DeleteMany(filter, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeLoginSession, &logutils.FieldArgs{"expires": now}, err)
	}

	return nil
}

// FindSessionsLazy finds all sessions for app/org but lazy filled.
// - lazy means that we make only one request to the logins sessions collection and fill the objects with what we have there.
// - i.e. we do not apply any relations
// - this partly filled is enough for some cases(expiration policy checks for example) but in the same time it give very good performace
func (sa *Adapter) FindSessionsLazy(appID string, orgID string) ([]model.LoginSession, error) {
	filter := bson.D{primitive.E{Key: "app_id", Value: appID}, primitive.E{Key: "org_id", Value: orgID}}

	var loginSessions []loginSession
	timeout := time.Millisecond * time.Duration(5000) //5 seconds
	err := sa.db.loginsSessions.FindWithParams(context.Background(), filter, &loginSessions, nil, &timeout)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeLoginSession, &logutils.FieldArgs{"app_id": appID, "org_id": orgID}, err)
	}

	sessions := make([]model.LoginSession, len(loginSessions))
	for i, session := range loginSessions {
		//auth type - from cache
		authType, err := sa.getCachedAuthType(session.AuthTypeCode)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeAuthType, &logutils.FieldArgs{"code": session.AuthTypeCode}, err)
		}
		if authType == nil {
			return nil, errors.ErrorData(logutils.StatusMissing, model.TypeAuthType, &logutils.FieldArgs{"code": session.AuthTypeCode})
		}

		//application organization - from cache
		appOrg, err := sa.getCachedApplicationOrganization(session.AppID, session.OrgID)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeApplicationOrganization, &logutils.FieldArgs{"app_id": session.AppID, "org_id": session.OrgID}, err)
		}

		sessions[i] = loginSessionFromStorage(session, *authType, nil, *appOrg)
	}

	return sessions, nil
}

// FindAccountByOrgAndIdentifier finds an account for org and user identity
func (sa *Adapter) FindAccountByOrgAndIdentifier(context TransactionContext, orgID string, authTypeID string, accountAuthTypeIdentifier string, currentAppOrgID string) (*model.Account, error) {
	filter := bson.D{
		primitive.E{Key: "org_id", Value: orgID},
		primitive.E{Key: "auth_types.auth_type_id", Value: authTypeID},
		primitive.E{Key: "auth_types.identifier", Value: accountAuthTypeIdentifier}}
	var accounts []tenantAccount
	err := sa.db.tenantsAccounts.FindWithContext(context, filter, &accounts, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}
	if len(accounts) == 0 {
		//not found
		return nil, nil
	}
	account := accounts[0]

	//all memberships applications organizations - from cache
	membershipsAppsOrgsIDs := make([]string, len(account.OrgAppsMemberships))
	for i, aoID := range account.OrgAppsMemberships {
		membershipsAppsOrgsIDs[i] = aoID.AppOrgID
	}
	appsOrgs, err := sa.getCachedApplicationOrganizationByKeys(membershipsAppsOrgsIDs)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeApplicationOrganization, nil, err)
	}
	if len(appsOrgs) != len(account.OrgAppsMemberships) {
		return nil, errors.WrapErrorAction(logutils.ActionCount, "does not match memberships apps orgs ids count", nil, err)
	}

	modelAccount := accountFromStorage(account, &currentAppOrgID, appsOrgs)
	return &modelAccount, nil
}

// FindAccount finds an account for app, org, auth type and account auth type identifier
func (sa *Adapter) FindAccount(context TransactionContext, appOrgID string, authTypeID string, accountAuthTypeIdentifier string) (*model.Account, error) {
	filter := bson.D{
		primitive.E{Key: "org_apps_memberships.app_org_id", Value: appOrgID},
		primitive.E{Key: "auth_types.auth_type_id", Value: authTypeID},
		primitive.E{Key: "auth_types.identifier", Value: accountAuthTypeIdentifier}}
	var accounts []tenantAccount
	err := sa.db.tenantsAccounts.FindWithContext(context, filter, &accounts, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}
	if len(accounts) == 0 {
		//not found
		return nil, nil
	}
	account := accounts[0]

	//all memberships applications organizations - from cache
	membershipsAppsOrgsIDs := make([]string, len(account.OrgAppsMemberships))
	for i, aoID := range account.OrgAppsMemberships {
		membershipsAppsOrgsIDs[i] = aoID.AppOrgID
	}
	appsOrgs, err := sa.getCachedApplicationOrganizationByKeys(membershipsAppsOrgsIDs)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeApplicationOrganization, nil, err)
	}
	if len(appsOrgs) != len(account.OrgAppsMemberships) {
		return nil, errors.WrapErrorAction(logutils.ActionCount, "does not match memberships apps orgs ids count", nil, err)
	}

	modelAccount := accountFromStorage(account, &appOrgID, appsOrgs)
	return &modelAccount, nil
}

// FindAccounts finds accounts
func (sa *Adapter) FindAccounts(context TransactionContext, limit *int, offset *int, appID string, orgID string, accountID *string, firstName *string, lastName *string, authType *string,
	authTypeIdentifier *string, anonymous *bool, hasPermissions *bool, permissions []string, roleIDs []string, groupIDs []string) ([]model.Account, error) {
	//find app org id
	appOrg, err := sa.getCachedApplicationOrganization(appID, orgID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeApplicationOrganization, nil, err)
	}
	if appOrg == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationOrganization, nil)
	}

	//find the accounts
	filter := bson.D{}

	//ID, profile, and auth type filters
	if accountID != nil {
		filter = append(filter, primitive.E{Key: "_id", Value: *accountID})
	}
	filter = append(filter, primitive.E{Key: "app_org_id", Value: appOrg.ID})
	if firstName != nil {
		filter = append(filter, primitive.E{Key: "profile.first_name", Value: *firstName})
	}
	if lastName != nil {
		filter = append(filter, primitive.E{Key: "profile.last_name", Value: *lastName})
	}
	if authType != nil {
		cachedAuthType, err := sa.getCachedAuthType(*authType)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeAuthType, &logutils.FieldArgs{"code": *authType}, err)
		}
		if cachedAuthType == nil {
			return nil, errors.ErrorData(logutils.StatusMissing, model.TypeAuthType, &logutils.FieldArgs{"code": *authType})
		}
		filter = append(filter, primitive.E{Key: "auth_types.auth_type_id", Value: cachedAuthType.ID})
	}
	if authTypeIdentifier != nil {
		filter = append(filter, primitive.E{Key: "auth_types.identifier", Value: *authTypeIdentifier})
	}
	if anonymous != nil {
		filter = append(filter, primitive.E{Key: "anonymous", Value: *anonymous})
	}

	//authorization filters
	overrideHasPermissions := false
	if len(permissions) > 0 {
		filter = append(filter, primitive.E{Key: "permissions.name", Value: bson.M{"$in": permissions}})
		overrideHasPermissions = true
	}
	if len(roleIDs) > 0 {
		filter = append(filter, primitive.E{Key: "roles.role._id", Value: bson.M{"$in": roleIDs}})
		overrideHasPermissions = true
	}
	if len(groupIDs) > 0 {
		filter = append(filter, primitive.E{Key: "groups.group._id", Value: bson.M{"$in": groupIDs}})
		overrideHasPermissions = true
	}
	if !overrideHasPermissions && hasPermissions != nil {
		if *hasPermissions {
			filter = append(filter, primitive.E{Key: "$or", Value: bson.A{
				bson.M{"permissions.0": bson.M{"$exists": true}},
				bson.M{"roles.0": bson.M{"$exists": true}},
				bson.M{"groups.0": bson.M{"$exists": true}},
			}})
		} else {
			filter = append(filter, primitive.E{Key: "permissions.0", Value: bson.M{"$exists": false}})
			filter = append(filter, primitive.E{Key: "roles.0", Value: bson.M{"$exists": false}})
			filter = append(filter, primitive.E{Key: "groups.0", Value: bson.M{"$exists": false}})
		}
	}

	var list []account
	var findOptions *options.FindOptions
	if limit != nil {
		findOptions = options.Find()
		findOptions.SetLimit(int64(*limit))
	}
	if offset != nil {
		if findOptions == nil {
			findOptions = options.Find()
		}
		findOptions.SetSkip(int64(*offset))
	}

	err = sa.db.accounts.FindWithContext(context, filter, &list, findOptions)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}

	accounts := accountsFromStorageDeprecated(list, *appOrg)
	return accounts, nil
}

// FindPublicAccounts finds accounts and returns name and username
func (sa *Adapter) FindPublicAccounts(context TransactionContext, appID string, orgID string, limit *int, offset *int,
	search *string, firstName *string, lastName *string, username *string, followingID *string, followerID *string, userID string) ([]model.PublicAccount, error) {
	appOrg, err := sa.FindApplicationOrganization(appID, orgID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationOrganization, nil, err)
	}

	pipeline := []bson.M{}

	var searchStr, firstNameStr, lastNameStr, usernameStr, followingIDStr, followerIDStr string

	// search for matching using text search. No substring matches
	// if search != nil {
	// 	searchStr = *search
	// 	pipeline = append(pipeline,
	// 		bson.M{
	// 			"$match": bson.M{
	// 				"$text": bson.M{
	// 					"$search": search,
	// 					// "$caseSensitive": false,
	// 				}},
	// 		})
	// }

	if search != nil {
		searchStr = *search
		searchStrParts := strings.Split(searchStr, " ")
		searchStr = ""
		for _, part := range searchStrParts {
			if searchStr != "" {
				searchStr += "|"
			}
			searchStr += "(" + part + ")"
		}
		regexFilter := bson.M{
			"$or": []bson.M{
				{"username": primitive.Regex{Pattern: searchStr, Options: "i"}},
				{"profile.first_name": primitive.Regex{Pattern: searchStr, Options: "i"}},
				{"profile.last_name": primitive.Regex{Pattern: searchStr, Options: "i"}},
			},
		}
		pipeline = append(pipeline, bson.M{"$match": regexFilter})
	}

	pipeline = append(pipeline, bson.M{"$match": bson.M{"app_org_id": appOrg.ID, "privacy.public": true}})
	pipeline = append(pipeline, bson.M{"$lookup": bson.M{
		"from":         "follows",
		"localField":   "_id",
		"foreignField": "following_id",
		"as":           "followings",
	}})
	pipeline = append(pipeline, bson.M{"$lookup": bson.M{
		"from":         "follows",
		"localField":   "_id",
		"foreignField": "follower_id",
		"as":           "followers",
	}})

	if firstName != nil {
		firstNameStr = *firstName
		pipeline = append(pipeline, bson.M{"$match": bson.M{"profile.first_name": *firstName}})
	}
	if lastName != nil {
		lastNameStr = *lastName
		pipeline = append(pipeline, bson.M{"$match": bson.M{"profile.last_name": *lastName}})
	}
	if username != nil {
		usernameStr = *username
		pipeline = append(pipeline, bson.M{"$match": bson.M{"username": *username}})
	}

	if followingID != nil {
		followingIDStr = *followingID
		pipeline = append(pipeline, bson.M{"$match": bson.M{"followers.following_id": *followingID}})
	}

	if followerID != nil {
		followerIDStr = *followerID
		pipeline = append(pipeline, bson.M{"$match": bson.M{"followings.follower_id": *followerID}})
	}

	// adds boolean value whether API calling user is following account
	pipeline = append(pipeline, bson.M{"$addFields": bson.M{"is_following": bson.M{"$in": bson.A{userID, "$followings.follower_id"}}}})

	if offset != nil {
		pipeline = append(pipeline, bson.M{"$skip": *offset})
	}

	if limit != nil {
		pipeline = append(pipeline, bson.M{"$limit": *limit})
	}

	var accounts []account
	err = sa.db.accounts.Aggregate(pipeline, &accounts, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, &logutils.FieldArgs{"app_id": appID, "org_id": orgID, "search": searchStr, "first_name": firstNameStr, "last_name": lastNameStr, "username": usernameStr, "following_id": followingIDStr, "follower_id": followerIDStr}, err)
	}

	var publicAccounts []model.PublicAccount
	for _, account := range accounts {
		publicAccounts = append(publicAccounts, model.PublicAccount{
			ID:          account.ID,
			Username:    account.Username,
			FirstName:   account.Profile.FirstName,
			LastName:    account.Profile.LastName,
			Verified:    account.Verified,
			IsFollowing: account.IsFollowing,
		})
	}
	return publicAccounts, nil
}

// FindAccountsByParams finds accounts by an arbitrary set of search params
func (sa *Adapter) FindAccountsByParams(searchParams map[string]interface{}, appID string, orgID string, limit int, offset int, allAccess bool, approvedKeys []string) ([]map[string]interface{}, error) {
	//find app orgs accessed by service
	appOrgs, err := sa.FindApplicationOrganizations(utils.StringOrNil(appID, authutils.AllApps), utils.StringOrNil(orgID, authutils.AllOrgs))
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationOrganization, &logutils.FieldArgs{"app_id": appID, "org_id": orgID}, err)
	}
	if len(appOrgs) == 0 {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationOrganization, &logutils.FieldArgs{"app_id": appID, "org_id": orgID})
	}

	//find the accounts
	appOrgIDs := make([]string, len(appOrgs))
	for i, appOrg := range appOrgs {
		appOrgIDs[i] = appOrg.ID
	}
	searchParams["app_org_id"] = appOrgIDs
	filter := sa.getFilterForParams(searchParams)

	var accounts []map[string]interface{}
	options := options.Find()
	options.SetLimit(int64(limit))
	options.SetSkip(int64(offset))

	// set projection if scope limited
	if !allAccess {
		options.SetProjection(sa.getProjectionForKeys(approvedKeys))
	}

	err = sa.db.accounts.Find(filter, &accounts, options)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}

	sa.convertIDs(accounts)

	return accounts, nil
}

// CountAccountsByParams find accounts by an arbitrary set of search params
func (sa *Adapter) CountAccountsByParams(searchParams map[string]interface{}, appID string, orgID string) (int64, error) {
	//find app orgs accessed by service
	appOrgs, err := sa.FindApplicationOrganizations(utils.StringOrNil(appID, authutils.AllApps), utils.StringOrNil(orgID, authutils.AllOrgs))
	if err != nil {
		return -1, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationOrganization, &logutils.FieldArgs{"app_id": appID, "org_id": orgID}, err)
	}
	if len(appOrgs) == 0 {
		return -1, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationOrganization, &logutils.FieldArgs{"app_id": appID, "org_id": orgID})
	}

	//find the accounts
	appOrgIDs := make([]string, len(appOrgs))
	for i, appOrg := range appOrgs {
		appOrgIDs[i] = appOrg.ID
	}
	searchParams["app_org_id"] = appOrgIDs
	filter := sa.getFilterForParams(searchParams)

	count, err := sa.db.accounts.CountDocuments(filter)
	if err != nil {
		return -1, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}

	return count, nil
}

// FindAccountsByAccountID finds accounts
func (sa *Adapter) FindAccountsByAccountID(context TransactionContext, appID string, orgID string, accountIDs []string) ([]model.Account, error) {
	if len(accountIDs) == 0 {
		return make([]model.Account, 0), nil
	}

	//find app org id
	appOrg, err := sa.getCachedApplicationOrganization(appID, orgID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeApplicationOrganization, nil, err)
	}

	accountFilter := bson.D{primitive.E{Key: "_id", Value: bson.M{"$in": accountIDs}}, primitive.E{Key: "app_org_id", Value: appOrg.ID}}
	var accountResult []account
	err = sa.db.accounts.FindWithContext(context, accountFilter, &accountResult, nil)
	if err != nil {
		return nil, err
	}
	accounts := accountsFromStorageDeprecated(accountResult, *appOrg)
	return accounts, nil
}

// FindAccountsByUsername finds accounts with a username for a given appOrg
func (sa *Adapter) FindAccountsByUsername(context TransactionContext, appOrg *model.ApplicationOrganization, username string) ([]model.Account, error) {
	if appOrg == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationOrganization, nil)
	}

	filter := bson.D{primitive.E{Key: "app_org_id", Value: appOrg.ID}, primitive.E{Key: "username", Value: username}}

	var accountResult []account
	err := sa.db.accounts.Find(filter, &accountResult, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, &logutils.FieldArgs{"app_org_id": appOrg.ID, "username": username}, err)
	}
	if len(accountResult) > 1 {
		sa.logger.WarnWithFields("duplicate username", logutils.Fields{"number": len(accountResult), "app_org_id": appOrg.ID, "username": username})
	}

	accounts := accountsFromStorageDeprecated(accountResult, *appOrg)
	return accounts, nil
}

// FindAccountByID finds an account by id
func (sa *Adapter) FindAccountByID(context TransactionContext, id string) (*model.Account, error) {
	return sa.findAccount(context, "_id", id, nil)
}

// FindAccountByAuthTypeID finds an account by auth type id
func (sa *Adapter) FindAccountByAuthTypeID(context TransactionContext, id string, currentAppOrgID *string) (*model.Account, error) {
	return sa.findAccount(context, "auth_types.id", id, currentAppOrgID)
}

func (sa *Adapter) findAccount(context TransactionContext, key string, id string, currentAppOrgID *string) (*model.Account, error) {
	account, err := sa.findStorageAccount(context, key, id)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}

	if account == nil {
		return nil, nil
	}

	//all memberships applications organizations - from cache
	membershipsAppsOrgsIDs := make([]string, len(account.OrgAppsMemberships))
	for i, aoID := range account.OrgAppsMemberships {
		membershipsAppsOrgsIDs[i] = aoID.AppOrgID
	}
	appsOrgs, err := sa.getCachedApplicationOrganizationByKeys(membershipsAppsOrgsIDs)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeApplicationOrganization, nil, err)
	}
	if len(appsOrgs) != len(account.OrgAppsMemberships) {
		return nil, errors.WrapErrorAction(logutils.ActionCount, "does not match memberships apps orgs ids count", nil, err)
	}

	modelAccount := accountFromStorage(*account, currentAppOrgID, appsOrgs)
	return &modelAccount, nil

}

func (sa *Adapter) findStorageAccount(context TransactionContext, key string, id string) (*tenantAccount, error) {
	filter := bson.M{key: id}
	var accounts []tenantAccount
	err := sa.db.tenantsAccounts.FindWithContext(context, filter, &accounts, nil)
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

// InsertAccount inserts an account
func (sa *Adapter) InsertAccount(context TransactionContext, account model.Account) (*model.Account, error) {
	storageAccount := accountToStorage(&account)

	_, err := sa.db.tenantsAccounts.InsertOneWithContext(context, storageAccount)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionInsert, model.TypeAccount, nil, err)
	}

	return &account, nil
}

// SaveAccount saves an existing account
func (sa *Adapter) SaveAccount(context TransactionContext, account *model.Account) error {
	if account == nil {
		return errors.ErrorData(logutils.StatusInvalid, logutils.TypeArg, logutils.StringArgs("account"))
	}

	storageAccount := accountToStorage(account)

	filter := bson.M{"_id": account.ID}
	err := sa.db.tenantsAccounts.ReplaceOneWithContext(context, filter, storageAccount, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccount, nil, err)
	}

	return nil
}

// UpdateAccountUsageInfo updates the usage information in accounts
func (sa *Adapter) UpdateAccountUsageInfo(context TransactionContext, accountID string, updateLoginTime bool, updateAccessTokenTime bool, clientVersion *string) error {
	filter := bson.D{primitive.E{Key: "_id", Value: accountID}}
	now := time.Now().UTC()
	update := bson.M{}
	if updateLoginTime {
		update["last_login_date"] = now
	}
	if updateAccessTokenTime {
		update["last_access_token_date"] = now
	}
	if clientVersion != nil && *clientVersion != "" {
		update["most_recent_client_version"] = *clientVersion
	}
	usageInfoUpdate := bson.M{"$set": update}

	res, err := sa.db.tenantsAccounts.UpdateOneWithContext(context, filter, usageInfoUpdate, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccountUsageInfo, nil, err)
	}
	if res.ModifiedCount != 1 {
		return errors.ErrorAction(logutils.ActionUpdate, model.TypeAccountUsageInfo, &logutils.FieldArgs{"unexpected modified count": res.ModifiedCount})
	}

	return nil
}

// DeleteAccount deletes an account
func (sa *Adapter) DeleteAccount(context TransactionContext, id string) error {
	//TODO - we have to decide what we do on delete user operation - removing all user relations, (or) mark the user disabled etc

	filter := bson.M{"_id": id}
	res, err := sa.db.tenantsAccounts.DeleteOneWithContext(context, filter, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeAccount, nil, err)
	}
	if res.DeletedCount != 1 {
		return errors.ErrorAction(logutils.ActionDelete, model.TypeAccount, logutils.StringArgs("unexpected deleted count"))
	}

	return nil
}

// FindServiceAccount finds a service account by accountID, appID, and orgID
func (sa *Adapter) FindServiceAccount(context TransactionContext, accountID string, appID string, orgID string) (*model.ServiceAccount, error) {
	filter := bson.D{primitive.E{Key: "account_id", Value: accountID}, primitive.E{Key: "app_id", Value: appID}, primitive.E{Key: "org_id", Value: orgID}}

	var account serviceAccount
	errFields := logutils.FieldArgs{"account_id": accountID, "app_id": appID, "org_id": orgID}
	err := sa.db.serviceAccounts.FindOneWithContext(context, filter, &account, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeServiceAccount, &errFields, err)
	}

	modelAccount, err := serviceAccountFromStorage(account, sa)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCast, model.TypeServiceAccount, &errFields, err)
	}

	return modelAccount, nil
}

// FindServiceAccounts gets all service accounts matching a search
func (sa *Adapter) FindServiceAccounts(params map[string]interface{}) ([]model.ServiceAccount, error) {
	filter := bson.D{}
	for k, v := range params {
		if k == "permissions" {
			filter = append(filter, primitive.E{Key: k + ".name", Value: bson.M{"$in": v}})
		} else if k == "scopes" {
			filter = append(filter, primitive.E{Key: k, Value: bson.M{"$in": v}})
		} else {
			filter = append(filter, primitive.E{Key: k, Value: v})
		}
	}

	var accounts []serviceAccount
	err := sa.db.serviceAccounts.Find(filter, &accounts, nil)
	if err != nil {
		logParams := logutils.FieldArgs(params)
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeServiceAccount, &logParams, err)
	}

	modelAccounts := serviceAccountListFromStorage(accounts, sa)

	return modelAccounts, nil
}

// InsertServiceAccount inserts a service account
func (sa *Adapter) InsertServiceAccount(account *model.ServiceAccount) error {
	if account == nil {
		return errors.ErrorData(logutils.StatusInvalid, model.TypeServiceAccount, nil)
	}

	storageAccount := serviceAccountToStorage(*account)

	_, err := sa.db.serviceAccounts.InsertOne(storageAccount)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionInsert, model.TypeServiceAccount, nil, err)
	}

	return nil
}

// UpdateServiceAccount updates a service account
func (sa *Adapter) UpdateServiceAccount(context TransactionContext, account *model.ServiceAccount) (*model.ServiceAccount, error) {
	if account == nil {
		return nil, errors.ErrorData(logutils.StatusInvalid, model.TypeServiceAccount, nil)
	}

	storageAccount := serviceAccountToStorage(*account)

	filter := bson.D{primitive.E{Key: "account_id", Value: storageAccount.AccountID}, primitive.E{Key: "app_id", Value: storageAccount.AppID}, primitive.E{Key: "org_id", Value: storageAccount.OrgID}}
	update := bson.D{
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "name", Value: storageAccount.Name},
			primitive.E{Key: "permissions", Value: storageAccount.Permissions},
			primitive.E{Key: "scopes", Value: storageAccount.Scopes},
			primitive.E{Key: "date_updated", Value: time.Now().UTC()},
		}},
	}
	opts := options.FindOneAndUpdateOptions{}
	opts.SetReturnDocument(options.After)
	opts.SetProjection(bson.D{bson.E{Key: "secrets", Value: 0}})

	var updated serviceAccount
	errFields := logutils.FieldArgs{"account_id": storageAccount.AccountID, "app_id": storageAccount.AppID, "org_id": storageAccount.OrgID}
	err := sa.db.serviceAccounts.FindOneAndUpdateWithContext(context, filter, update, &updated, &opts)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUpdate, model.TypeServiceAccount, &errFields, err)
	}

	modelAccount, err := serviceAccountFromStorage(updated, sa)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCast, model.TypeServiceAccount, &errFields, err)
	}

	return modelAccount, nil
}

// DeleteServiceAccount deletes a service account
func (sa *Adapter) DeleteServiceAccount(accountID string, appID string, orgID string) error {
	filter := bson.D{primitive.E{Key: "account_id", Value: accountID}, primitive.E{Key: "app_id", Value: appID}, primitive.E{Key: "org_id", Value: orgID}}

	errFields := logutils.FieldArgs{"account_id": accountID, "app_id": appID, "org_id": orgID}
	res, err := sa.db.serviceAccounts.DeleteOne(filter, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeServiceAccount, &errFields, err)
	}
	if res.DeletedCount == 0 {
		return errors.ErrorAction(logutils.ActionDelete, model.TypeServiceAccount, &errFields)
	}
	if res.DeletedCount > 1 {
		return errors.ErrorAction(logutils.ActionDelete, model.TypeServiceAccount, logutils.StringArgs("unexpected deleted count"))
	}

	return nil
}

// DeleteServiceAccounts deletes service accounts by accountID
func (sa *Adapter) DeleteServiceAccounts(accountID string) error {
	filter := bson.D{primitive.E{Key: "account_id", Value: accountID}}

	res, err := sa.db.serviceAccounts.DeleteMany(filter, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeServiceAccount, &logutils.FieldArgs{"account_id": accountID}, err)
	}
	if res.DeletedCount == 0 {
		return errors.ErrorAction(logutils.ActionDelete, model.TypeServiceAccount, &logutils.FieldArgs{"account_id": accountID})
	}

	return nil
}

// InsertServiceAccountCredential inserts a service account credential
func (sa *Adapter) InsertServiceAccountCredential(accountID string, creds *model.ServiceAccountCredential) error {
	if creds == nil {
		return errors.ErrorData(logutils.StatusInvalid, logutils.TypeArg, logutils.StringArgs("credentials"))
	}

	filter := bson.D{primitive.E{Key: "account_id", Value: accountID}}
	update := bson.D{
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "date_updated", Value: time.Now().UTC()},
		}},
		primitive.E{Key: "$push", Value: bson.D{
			primitive.E{Key: "credentials", Value: creds},
		}},
	}

	res, err := sa.db.serviceAccounts.UpdateMany(filter, update, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionInsert, model.TypeServiceAccountCredential, &logutils.FieldArgs{"account_id": accountID}, err)
	}
	if res.MatchedCount == 0 {
		return errors.ErrorData(logutils.StatusMissing, model.TypeServiceAccount, &logutils.FieldArgs{"account_id": accountID})
	}
	if res.ModifiedCount == 0 {
		return errors.ErrorAction(logutils.ActionInsert, model.TypeServiceAccountCredential, logutils.StringArgs("unexpected modified count"))
	}

	return nil
}

// DeleteServiceAccountCredential deletes a service account credential
func (sa *Adapter) DeleteServiceAccountCredential(accountID string, credID string) error {
	filter := bson.D{primitive.E{Key: "account_id", Value: accountID}}
	update := bson.D{
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "date_updated", Value: time.Now().UTC()},
		}},
		primitive.E{Key: "$pull", Value: bson.D{
			primitive.E{Key: "credentials", Value: bson.M{"id": credID}},
		}},
	}

	res, err := sa.db.serviceAccounts.UpdateMany(filter, update, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeServiceAccountCredential, &logutils.FieldArgs{"account_id": accountID, "cred_id": credID}, err)
	}
	if res.MatchedCount == 0 {
		return errors.ErrorData(logutils.StatusMissing, model.TypeServiceAccount, &logutils.FieldArgs{"account_id": accountID, "cred_id": credID})
	}
	if res.ModifiedCount == 0 {
		return errors.ErrorAction(logutils.ActionDelete, model.TypeServiceAccountCredential, logutils.StringArgs("unexpected modified count"))
	}

	return nil
}

// UpdateAccountPreferences updates account preferences
func (sa *Adapter) UpdateAccountPreferences(context TransactionContext, accountID string, preferences map[string]interface{}) error {
	filter := bson.D{primitive.E{Key: "_id", Value: accountID}}
	update := bson.D{
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "preferences", Value: preferences},
			primitive.E{Key: "date_updated", Value: time.Now().UTC()},
		}},
	}

	res, err := sa.db.accounts.UpdateOneWithContext(context, filter, update, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccountPreferences, nil, err)
	}
	if res.ModifiedCount != 1 {
		return errors.ErrorAction(logutils.ActionUpdate, model.TypeAccountPreferences, &logutils.FieldArgs{"unexpected modified count": res.ModifiedCount})
	}

	return nil
}

// UpdateAccountSystemConfigs updates account system configs
func (sa *Adapter) UpdateAccountSystemConfigs(context TransactionContext, accountID string, configs map[string]interface{}) error {
	filter := bson.D{primitive.E{Key: "_id", Value: accountID}}
	update := bson.D{
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "system_configs", Value: configs},
			primitive.E{Key: "date_updated", Value: time.Now().UTC()},
		}},
	}

	res, err := sa.db.accounts.UpdateOne(filter, update, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccountSystemConfigs, nil, err)
	}
	if res.ModifiedCount != 1 {
		return errors.ErrorAction(logutils.ActionUpdate, model.TypeAccountSystemConfigs, &logutils.FieldArgs{"unexpected modified count": res.ModifiedCount})
	}

	return nil
}

// InsertAccountPermissions inserts account permissions
func (sa *Adapter) InsertAccountPermissions(context TransactionContext, accountID string, permissions []model.Permission) error {
	filter := bson.D{primitive.E{Key: "_id", Value: accountID}}
	update := bson.D{
		primitive.E{Key: "$push", Value: bson.D{
			primitive.E{Key: "permissions", Value: bson.M{"$each": permissions}},
		}},
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "date_updated", Value: time.Now().UTC()},
		}},
	}

	res, err := sa.db.accounts.UpdateOneWithContext(context, filter, update, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccount, &logutils.FieldArgs{"id": accountID}, err)
	}
	if res.ModifiedCount != 1 {
		return errors.ErrorAction(logutils.ActionUpdate, model.TypeAccount, &logutils.FieldArgs{"id": accountID, "modified": res.ModifiedCount, "expected": 1})
	}

	return nil
}

// UpdateAccountPermissions updates account permissions
func (sa *Adapter) UpdateAccountPermissions(context TransactionContext, accountID string, permissions []model.Permission) error {
	filter := bson.D{primitive.E{Key: "_id", Value: accountID}}
	update := bson.D{
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "permissions", Value: permissions},
			primitive.E{Key: "date_updated", Value: time.Now().UTC()},
		}},
	}

	res, err := sa.db.accounts.UpdateOneWithContext(context, filter, update, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccount, nil, err)
	}
	if res.ModifiedCount != 1 {
		return errors.ErrorAction(logutils.ActionUpdate, model.TypeAccount, &logutils.FieldArgs{"unexpected modified count": res.ModifiedCount})
	}

	return nil
}

// DeleteAccountPermissions deletes permissions from an account
func (sa *Adapter) DeleteAccountPermissions(context TransactionContext, accountID string, permissionNames []string) error {
	//filter
	filter := bson.D{primitive.E{Key: "_id", Value: accountID}}

	//update
	update := bson.D{
		primitive.E{Key: "$pull", Value: bson.D{
			primitive.E{Key: "permissions", Value: bson.M{"name": bson.M{"$in": permissionNames}}},
		}},
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "date_updated", Value: time.Now().UTC()},
		}},
	}

	res, err := sa.db.accounts.UpdateOneWithContext(context, filter, update, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccount, &logutils.FieldArgs{"id": accountID}, err)
	}
	if res.ModifiedCount != 1 {
		return errors.ErrorAction(logutils.ActionUpdate, model.TypeAccount, &logutils.FieldArgs{"id": accountID, "modified": res.ModifiedCount, "expected": 1})
	}
	return nil
}

// UpdateAccountUsername updates an account's username
func (sa *Adapter) UpdateAccountUsername(context TransactionContext, accountID string, username string) error {
	filter := bson.D{primitive.E{Key: "_id", Value: accountID}}
	update := bson.D{
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "username", Value: username},
			primitive.E{Key: "date_updated", Value: time.Now().UTC()},
		}},
	}

	res, err := sa.db.accounts.UpdateOneWithContext(context, filter, update, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccount, &logutils.FieldArgs{"id": accountID}, err)
	}
	if res.ModifiedCount != 1 {
		return errors.ErrorAction(logutils.ActionUpdate, model.TypeAccount, &logutils.FieldArgs{"id": accountID, "modified": res.ModifiedCount, "expected": 1})
	}

	return nil
}

// UpdateAccountVerified updates an account's username
func (sa *Adapter) UpdateAccountVerified(context TransactionContext, accountID string, appID string, orgID string, verified bool) error {
	appOrg, err := sa.FindApplicationOrganization(appID, orgID)
	if err != nil || appOrg == nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationOrganization, &logutils.FieldArgs{"app_id": appID, "org_id": orgID}, err)
	}

	filter := bson.M{"_id": accountID, "app_org_id": appOrg.ID}
	update := bson.D{
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "verified", Value: verified},
			primitive.E{Key: "date_updated", Value: time.Now().UTC()},
		}},
	}

	res, err := sa.db.accounts.UpdateOneWithContext(context, filter, update, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccount, &logutils.FieldArgs{"id": accountID, "app_id": appID, "org_id": orgID}, err)
	}
	if res.ModifiedCount != 1 {
		return errors.ErrorAction(logutils.ActionUpdate, model.TypeAccount, &logutils.FieldArgs{"id": accountID, "modified": res.ModifiedCount, "expected": 1})
	}

	return nil
}

// InsertAccountRoles inserts account roles
func (sa *Adapter) InsertAccountRoles(context TransactionContext, accountID string, appOrgID string, roles []model.AccountRole) error {
	stgRoles := accountRolesToStorage(roles)

	//appID included in search to prevent accidentally assigning permissions to account from different application
	filter := bson.D{primitive.E{Key: "_id", Value: accountID}, primitive.E{Key: "app_org_id", Value: appOrgID}}
	update := bson.D{
		primitive.E{Key: "$push", Value: bson.D{
			primitive.E{Key: "roles", Value: bson.M{"$each": stgRoles}},
		}},
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "date_updated", Value: time.Now().UTC()},
		}},
	}

	res, err := sa.db.accounts.UpdateOneWithContext(context, filter, update, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccount, &logutils.FieldArgs{"id": accountID}, err)
	}
	if res.ModifiedCount != 1 {
		return errors.ErrorAction(logutils.ActionUpdate, model.TypeAccount, &logutils.FieldArgs{"id": accountID, "modified": res.ModifiedCount, "expected": 1})
	}

	return nil
}

// InsertAccountGroups inserts account groups
func (sa *Adapter) InsertAccountGroups(context TransactionContext, accountID string, appOrgID string, groups []model.AccountGroup) error {
	stgGroups := accountGroupsToStorage(groups)

	//appID included in search to prevent accidentally assigning permissions to account from different application
	filter := bson.D{primitive.E{Key: "_id", Value: accountID}, primitive.E{Key: "app_org_id", Value: appOrgID}}
	update := bson.D{
		primitive.E{Key: "$push", Value: bson.D{
			primitive.E{Key: "groups", Value: bson.M{"$each": stgGroups}},
		}},
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "date_updated", Value: time.Now().UTC()},
		}},
	}

	res, err := sa.db.accounts.UpdateOneWithContext(context, filter, update, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccount, &logutils.FieldArgs{"_id": accountID, "app_org_id": appOrgID}, err)
	}
	if res.ModifiedCount != 1 {
		return errors.ErrorAction(logutils.ActionUpdate, model.TypeAccount, &logutils.FieldArgs{"unexpected modified count": res.ModifiedCount})
	}

	return nil
}

// InsertAccountsGroup inserts accounts into a group
func (sa *Adapter) InsertAccountsGroup(context TransactionContext, group model.AccountGroup, accountIDs []string) error {
	if len(accountIDs) == 0 {
		return nil
	}

	//prepare filter
	filter := bson.D{primitive.E{Key: "_id", Value: bson.M{"$in": accountIDs}}}

	//update
	storageGroup := accountGroupToStorage(group)
	update := bson.D{
		primitive.E{Key: "$push", Value: bson.D{
			primitive.E{Key: "groups", Value: storageGroup},
		}},
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "date_updated", Value: time.Now().UTC()},
		}},
	}

	res, err := sa.db.accounts.UpdateManyWithContext(context, filter, update, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccount, nil, err)
	}
	sa.logger.Infof("modified %d accounts with added group", res.ModifiedCount)
	return nil
}

// RemoveAccountsGroup removes accounts from a group
func (sa *Adapter) RemoveAccountsGroup(context TransactionContext, groupID string, accountIDs []string) error {
	if len(accountIDs) == 0 {
		return nil
	}

	filter := bson.D{primitive.E{Key: "_id", Value: bson.M{"$in": accountIDs}}}
	update := bson.D{
		primitive.E{Key: "$pull", Value: bson.D{
			primitive.E{Key: "groups", Value: bson.M{"group._id": groupID}},
		}},
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "date_updated", Value: time.Now().UTC()},
		}},
	}

	res, err := sa.db.accounts.UpdateManyWithContext(context, filter, update, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccount, &logutils.FieldArgs{"group_id": groupID}, err)
	}
	if res.ModifiedCount != res.MatchedCount {
		return errors.ErrorAction(logutils.ActionUpdate, model.TypeAccount, &logutils.FieldArgs{"group_id": groupID, "modified": res.ModifiedCount, "expected": res.MatchedCount})
	}

	sa.logger.Infof("modified %d accounts with removed group", res.ModifiedCount)
	return nil
}

// UpdateAccountRoles updates the account roles
func (sa *Adapter) UpdateAccountRoles(context TransactionContext, accountID string, roles []model.AccountRole) error {
	stgRoles := accountRolesToStorage(roles)

	filter := bson.D{primitive.E{Key: "_id", Value: accountID}}
	update := bson.D{
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "roles", Value: stgRoles},
			primitive.E{Key: "date_updated", Value: time.Now().UTC()},
		}},
	}

	res, err := sa.db.accounts.UpdateOneWithContext(context, filter, update, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccount, &logutils.FieldArgs{"id": accountID}, err)
	}
	if res.ModifiedCount != 1 {
		return errors.ErrorAction(logutils.ActionUpdate, model.TypeAccount, &logutils.FieldArgs{"id": accountID, "modified": res.ModifiedCount, "expected": 1})
	}

	return nil
}

// DeleteAccountRoles deletes account roles
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
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccount, &logutils.FieldArgs{"id": accountID}, err)
	}
	if res.ModifiedCount != 1 {
		return errors.ErrorAction(logutils.ActionUpdate, model.TypeAccount, &logutils.FieldArgs{"id": accountID, "modified": res.ModifiedCount, "expected": 1})
	}
	return nil
}

// UpdateAccountGroups updates the account groups
func (sa *Adapter) UpdateAccountGroups(context TransactionContext, accountID string, groups []model.AccountGroup) error {
	stgGroups := accountGroupsToStorage(groups)

	filter := bson.D{primitive.E{Key: "_id", Value: accountID}}
	update := bson.D{
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "groups", Value: stgGroups},
			primitive.E{Key: "date_updated", Value: time.Now().UTC()},
		}},
	}

	res, err := sa.db.accounts.UpdateOneWithContext(context, filter, update, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccount, &logutils.FieldArgs{"id": accountID}, err)
	}
	if res.ModifiedCount != 1 {
		return errors.ErrorAction(logutils.ActionUpdate, model.TypeAccount, &logutils.FieldArgs{"unexpected modified count": res.ModifiedCount})
	}

	return nil
}

// UpdateAccountScopes updates account scopes
func (sa *Adapter) UpdateAccountScopes(context TransactionContext, accountID string, scopes []string) error {
	filter := bson.D{primitive.E{Key: "_id", Value: accountID}}
	update := bson.D{
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "scopes", Value: scopes},
			primitive.E{Key: "date_updated", Value: time.Now().UTC()},
		}},
	}

	res, err := sa.db.accounts.UpdateOneWithContext(context, filter, update, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccount, nil, err)
	}
	if res.ModifiedCount != 1 {
		return errors.ErrorAction(logutils.ActionUpdate, model.TypeAccount, &logutils.FieldArgs{"unexpected modified count": res.ModifiedCount})
	}

	return nil
}

// InsertAccountAuthType inserts am account auth type
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

// UpdateAccountAuthType updates account auth type
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
		var accounts []tenantAccount
		err = sa.db.tenantsAccounts.FindWithContext(sessionContext, findFilter, &accounts, nil)
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
		err = sa.db.tenantsAccounts.ReplaceOneWithContext(sessionContext, replaceFilter, account, nil)
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

// DeleteAccountAuthType deletes an account auth type
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

// UpdateAccountExternalIDs updates account external IDs
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

// UpdateLoginSessionExternalIDs updates login session external IDs
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

// CountAccountsByRoleID counts how many accounts there are with the passed role id
func (sa *Adapter) CountAccountsByRoleID(roleID string) (*int64, error) {
	filter := bson.D{primitive.E{Key: "roles.role._id", Value: roleID}}

	count, err := sa.db.accounts.CountDocuments(filter)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCount, model.TypeAccount, &logutils.FieldArgs{"roles._id": roleID}, err)
	}
	return &count, nil
}

// CountAccountsByGroupID counts how many accounts there are with the passed group id
func (sa *Adapter) CountAccountsByGroupID(groupID string) (*int64, error) {
	filter := bson.D{primitive.E{Key: "groups.group._id", Value: groupID}}

	count, err := sa.db.accounts.CountDocuments(filter)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCount, model.TypeAccount, &logutils.FieldArgs{"groups._id": groupID}, err)
	}
	return &count, nil
}

// FindCredential finds a credential by ID
func (sa *Adapter) FindCredential(context TransactionContext, ID string) (*model.Credential, error) {
	filter := bson.D{primitive.E{Key: "_id", Value: ID}}

	var creds credential
	err := sa.db.credentials.FindOneWithContext(context, filter, &creds, nil)
	if err != nil {
		if err.Error() == mongo.ErrNoDocuments.Error() {
			return nil, nil
		}
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeCredential, &logutils.FieldArgs{"_id": ID}, err)
	}

	modelCreds := credentialFromStorage(creds)
	return &modelCreds, nil
}

// InsertCredential inserts a set of credential
func (sa *Adapter) InsertCredential(context TransactionContext, creds *model.Credential) error {
	storageCreds := credentialToStorage(creds)

	if storageCreds == nil {
		return errors.ErrorData(logutils.StatusInvalid, logutils.TypeArg, logutils.StringArgs(model.TypeCredential))
	}

	_, err := sa.db.credentials.InsertOneWithContext(context, storageCreds)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionInsert, model.TypeCredential, nil, err)
	}

	return nil
}

// UpdateCredential updates a set of credentials
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

// UpdateCredentialValue updates the value in credentials collection
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

// DeleteCredential deletes a credential
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

// FindMFAType finds one MFA type for an account
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

// FindMFATypes finds all MFA types for an account
func (sa *Adapter) FindMFATypes(accountID string) ([]model.MFAType, error) {
	filter := bson.D{primitive.E{Key: "_id", Value: accountID}}

	var account account
	err := sa.db.accounts.FindOne(filter, &account, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}

	return mfaTypesFromStorage(account.MFATypes), nil
}

// InsertMFAType inserts a MFA type
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

// UpdateMFAType updates one MFA type
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

// DeleteMFAType deletes a MFA type
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

// FindPermissions finds a set of permissions
func (sa *Adapter) FindPermissions(context TransactionContext, ids []string) ([]model.Permission, error) {
	if len(ids) == 0 {
		return []model.Permission{}, nil
	}

	permissionsFilter := bson.D{primitive.E{Key: "_id", Value: bson.M{"$in": ids}}}
	var permissionsResult []model.Permission
	err := sa.db.permissions.FindWithContext(context, permissionsFilter, &permissionsResult, nil)
	if err != nil {
		return nil, err
	}

	return permissionsResult, nil
}

// FindPermissionsByServiceIDs finds permissions
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

// FindPermissionsByName finds a set of permissions
func (sa *Adapter) FindPermissionsByName(context TransactionContext, names []string) ([]model.Permission, error) {
	if len(names) == 0 {
		return []model.Permission{}, nil
	}

	permissionsFilter := bson.D{primitive.E{Key: "name", Value: bson.M{"$in": names}}}
	var permissionsResult []model.Permission
	err := sa.db.permissions.FindWithContext(context, permissionsFilter, &permissionsResult, nil)
	if err != nil {
		return nil, err
	}

	return permissionsResult, nil
}

// InsertPermission inserts a new permission
func (sa *Adapter) InsertPermission(context TransactionContext, item model.Permission) error {
	_, err := sa.db.permissions.InsertOneWithContext(context, item)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionInsert, model.TypePermission, &logutils.FieldArgs{"name": item.Name, "duplicate": mongo.IsDuplicateKeyError(err)}, err)
	}

	return nil
}

// InsertPermissions inserts permissions
func (sa *Adapter) InsertPermissions(context TransactionContext, items []model.Permission) error {
	if len(items) == 0 {
		return nil
	}

	stgPermissions := make([]interface{}, len(items))
	for i, p := range items {
		stgPermissions[i] = p
	}

	res, err := sa.db.permissions.InsertManyWithContext(context, stgPermissions, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionInsert, model.TypePermission, nil, err)
	}

	if len(res.InsertedIDs) != len(items) {
		return errors.ErrorAction(logutils.ActionInsert, model.TypePermission, &logutils.FieldArgs{"inserted": len(res.InsertedIDs), "expected": len(items)})
	}

	return nil
}

// UpdatePermission updates permission
func (sa *Adapter) UpdatePermission(item model.Permission) error {
	//TODO
	//This will be slow operation as we keep a copy of the entity in the users collection without index.
	//Maybe we need to up the transaction timeout for this operation because of this.
	//TODO
	//Update the permission in all collection where there is a copy of it - accounts, application_roles, application_groups, service_accounts

	// Update serviceIDs
	filter := bson.D{primitive.E{Key: "name", Value: item.Name}}

	now := time.Now().UTC()
	permissionUpdate := bson.D{
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "description", Value: item.Description},
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
		return errors.ErrorAction(logutils.ActionUpdate, model.TypePermission, &logutils.FieldArgs{"name": item.Name, "modified": res.ModifiedCount, "expected": 1})
	}

	return nil
}

// DeletePermission deletes permission
func (sa *Adapter) DeletePermission(id string) error {
	//TODO
	//This will be slow operation as we keep a copy of the entity in the users collection without index.
	//Maybe we need to up the transaction timeout for this operation because of this.
	return errors.New(logutils.Unimplemented)
}

// FindAppOrgRoles finds all application organization roles fora given AppOrg ID
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
		return nil, errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeApplicationOrganization, &logutils.FieldArgs{"app_org_id": appOrg}, err)
	}
	if appOrg == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationOrganization, &logutils.FieldArgs{"app_org_id": appOrg})
	}

	result := appOrgRolesFromStorage(rolesResult, *appOrg)

	return result, nil
}

// FindAppOrgRolesByIDs finds a set of application organization roles for the provided IDs
func (sa *Adapter) FindAppOrgRolesByIDs(context TransactionContext, ids []string, appOrgID string) ([]model.AppOrgRole, error) {
	if len(ids) == 0 {
		return []model.AppOrgRole{}, nil
	}

	rolesFilter := bson.D{primitive.E{Key: "app_org_id", Value: appOrgID}, primitive.E{Key: "_id", Value: bson.M{"$in": ids}}}
	var rolesResult []appOrgRole
	err := sa.db.applicationsOrganizationsRoles.FindWithContext(context, rolesFilter, &rolesResult, nil)
	if err != nil {
		return nil, err
	}

	//get the application organization from the cached ones
	appOrg, err := sa.getCachedApplicationOrganizationByKey(appOrgID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeApplicationOrganization, &logutils.FieldArgs{"app_org_id": appOrg}, err)
	}
	if appOrg == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationOrganization, &logutils.FieldArgs{"app_org_id": appOrg})
	}

	result := appOrgRolesFromStorage(rolesResult, *appOrg)

	return result, nil
}

// FindAppOrgRole finds an application organization role
func (sa *Adapter) FindAppOrgRole(context TransactionContext, id string, appOrgID string) (*model.AppOrgRole, error) {
	filter := bson.D{primitive.E{Key: "_id", Value: id}, primitive.E{Key: "app_org_id", Value: appOrgID}}
	var rolesResult []appOrgRole
	err := sa.db.applicationsOrganizationsRoles.FindWithContext(context, filter, &rolesResult, nil)
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
		return nil, errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeApplicationOrganization, &logutils.FieldArgs{"app_org_id": appOrg}, err)
	}
	if appOrg == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationOrganization, &logutils.FieldArgs{"app_org_id": appOrg})
	}

	result := appOrgRoleFromStorage(&roles, *appOrg)
	return &result, nil
}

// InsertAppOrgRole inserts a new application organization role
func (sa *Adapter) InsertAppOrgRole(context TransactionContext, item model.AppOrgRole) error {
	role := appOrgRoleToStorage(item)
	_, err := sa.db.applicationsOrganizationsRoles.InsertOneWithContext(context, role)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionInsert, model.TypeAppOrgRole, nil, err)
	}
	return nil
}

// UpdateAppOrgRole updates application organization role
func (sa *Adapter) UpdateAppOrgRole(context TransactionContext, item model.AppOrgRole) error {
	if context == nil {
		transaction := func(newContext TransactionContext) error {
			return sa.updateAppOrgRole(newContext, item)
		}
		return sa.PerformTransaction(transaction)
	}

	return sa.updateAppOrgRole(context, item)
}

func (sa *Adapter) updateAppOrgRole(context TransactionContext, item model.AppOrgRole) error {
	// update role
	roleFilter := bson.D{primitive.E{Key: "_id", Value: item.ID}}
	roleUpdate := bson.D{
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "name", Value: item.Name},
			primitive.E{Key: "description", Value: item.Description},
			primitive.E{Key: "permissions", Value: item.Permissions},
			primitive.E{Key: "scopes", Value: item.Scopes},
			primitive.E{Key: "system", Value: item.System},
			primitive.E{Key: "date_updated", Value: item.DateUpdated},
		}},
	}

	res, err := sa.db.applicationsOrganizationsRoles.UpdateOneWithContext(context, roleFilter, roleUpdate, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAppOrgRole, &logutils.FieldArgs{"id": item.ID}, err)
	}
	if res.ModifiedCount != 1 {
		return errors.ErrorAction(logutils.ActionUpdate, model.TypeAppOrgRole, &logutils.FieldArgs{"id": item.ID, "modified": res.ModifiedCount, "expected": 1})
	}

	// update all groups that have the role in all collections
	key := "roles._id"
	groups, err := sa.findAppOrgGroups(context, &key, item.ID, item.AppOrg.ID)
	for _, g := range groups {
		for ridx, r := range g.Roles {
			if r.ID == item.ID {
				g.Roles[ridx] = item
				err = sa.UpdateAppOrgGroup(context, g)
				break
			}
		}
	}

	// update all accounts that have the role
	accountsFilter := bson.D{primitive.E{Key: "roles.role._id", Value: item.ID}}
	accountsUpdate := bson.D{
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "roles.$.role.name", Value: item.Name},
			primitive.E{Key: "roles.$.role.description", Value: item.Description},
			primitive.E{Key: "roles.$.role.permissions", Value: item.Permissions},
			primitive.E{Key: "roles.$.role.scopes", Value: item.Scopes},
			primitive.E{Key: "roles.$.role.system", Value: item.System},
			primitive.E{Key: "roles.$.role.date_updated", Value: item.DateUpdated},
		}},
	}

	res, err = sa.db.accounts.UpdateManyWithContext(context, accountsFilter, accountsUpdate, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccount, &logutils.FieldArgs{"roles.role._id": item.ID}, err)
	}
	if res.ModifiedCount != res.MatchedCount {
		return errors.ErrorAction(logutils.ActionUpdate, model.TypeAccount, &logutils.FieldArgs{"roles.role._id": item.ID, "modified": res.ModifiedCount, "expected": res.MatchedCount})
	}

	return nil
}

// DeleteAppOrgRole deletes application organization role
//   - make sure to call this function once you have verified that there is no any relations
//     in other collections for the role which is supposed to be deleted.
func (sa *Adapter) DeleteAppOrgRole(id string) error {
	filter := bson.M{"_id": id}
	result, err := sa.db.applicationsOrganizationsRoles.DeleteOne(filter, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeAppOrgRole, &logutils.FieldArgs{"_id": id}, err)
	}
	if result == nil {
		return errors.WrapErrorData(logutils.StatusInvalid, "delete result", &logutils.FieldArgs{"_id": id}, err)
	}
	deletedCount := result.DeletedCount
	if deletedCount == 0 {
		return errors.WrapErrorData(logutils.StatusMissing, model.TypeAppOrgRole, &logutils.FieldArgs{"_id": id}, err)
	}
	return nil
}

// InsertAppOrgRolePermissions inserts permissions to role
func (sa *Adapter) InsertAppOrgRolePermissions(context TransactionContext, roleID string, permissions []model.Permission) error {

	filter := bson.D{primitive.E{Key: "_id", Value: roleID}}
	update := bson.D{
		primitive.E{Key: "$push", Value: bson.D{
			primitive.E{Key: "permissions", Value: bson.M{"$each": permissions}},
		}},
	}

	res, err := sa.db.applicationsOrganizationsRoles.UpdateOne(filter, update, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAppOrgRole, &logutils.FieldArgs{"id": roleID}, err)
	}
	if res.ModifiedCount != 1 {
		return errors.ErrorAction(logutils.ActionUpdate, model.TypeAppOrgRole, &logutils.FieldArgs{"unexpected modified count": res.ModifiedCount})
	}

	return nil
}

// FindAppOrgGroups finds all application organization groups for the provided AppOrg ID
func (sa *Adapter) FindAppOrgGroups(appOrgID string) ([]model.AppOrgGroup, error) {
	return sa.findAppOrgGroups(nil, nil, "", appOrgID)
}

// FindAppOrgGroupsByIDs finds a set of application organization groups for the provided IDs
func (sa *Adapter) FindAppOrgGroupsByIDs(context TransactionContext, ids []string, appOrgID string) ([]model.AppOrgGroup, error) {
	if len(ids) == 0 {
		return []model.AppOrgGroup{}, nil
	}

	filter := bson.D{primitive.E{Key: "app_org_id", Value: appOrgID}, primitive.E{Key: "_id", Value: bson.M{"$in": ids}}}
	var groupsResult []appOrgGroup
	err := sa.db.applicationsOrganizationsGroups.FindWithContext(context, filter, &groupsResult, nil)
	if err != nil {
		return nil, err
	}

	appOrg, err := sa.getCachedApplicationOrganizationByKey(appOrgID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeApplicationOrganization, &logutils.FieldArgs{"app_org_id": appOrgID}, err)
	}
	if appOrg == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationOrganization, &logutils.FieldArgs{"app_org_id": appOrgID})
	}

	result := appOrgGroupsFromStorage(groupsResult, *appOrg)

	return result, nil
}

// FindAppOrgGroup finds a application organization group
func (sa *Adapter) FindAppOrgGroup(context TransactionContext, id string, appOrgID string) (*model.AppOrgGroup, error) {
	filter := bson.D{primitive.E{Key: "_id", Value: id}, primitive.E{Key: "app_org_id", Value: appOrgID}}
	var groupsResult []appOrgGroup
	err := sa.db.applicationsOrganizationsGroups.FindWithContext(context, filter, &groupsResult, nil)
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
		return nil, errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeApplicationOrganization, &logutils.FieldArgs{"app_org_id": appOrgID}, err)
	}
	if appOrg == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationOrganization, &logutils.FieldArgs{"app_org_id": appOrgID})
	}

	result := appOrgGroupFromStorage(&group, *appOrg)
	return &result, nil
}

func (sa *Adapter) findAppOrgGroups(context TransactionContext, key *string, id string, appOrgID string) ([]model.AppOrgGroup, error) {
	filter := bson.D{primitive.E{Key: "app_org_id", Value: appOrgID}}
	if key != nil {
		filter = append(filter, primitive.E{Key: *key, Value: id})
	}
	var groupsResult []appOrgGroup
	err := sa.db.applicationsOrganizationsGroups.FindWithContext(context, filter, &groupsResult, nil)
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

// InsertAppOrgGroup inserts a new application organization group
func (sa *Adapter) InsertAppOrgGroup(context TransactionContext, item model.AppOrgGroup) error {
	group := appOrgGroupToStorage(item)

	_, err := sa.db.applicationsOrganizationsGroups.InsertOneWithContext(context, group)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionInsert, model.TypeAppOrgGroup, nil, err)
	}
	return nil
}

// UpdateAppOrgGroup updates application organization group
func (sa *Adapter) UpdateAppOrgGroup(context TransactionContext, item model.AppOrgGroup) error {
	if context == nil {
		transaction := func(newContext TransactionContext) error {
			return sa.updateAppOrgGroup(newContext, item)
		}
		return sa.PerformTransaction(transaction)
	}

	return sa.updateAppOrgGroup(context, item)
}

func (sa *Adapter) updateAppOrgGroup(context TransactionContext, item model.AppOrgGroup) error {
	roles := appOrgRolesToStorage(item.Roles)

	// update group
	groupFilter := bson.D{primitive.E{Key: "_id", Value: item.ID}}
	groupUpdate := bson.D{
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "name", Value: item.Name},
			primitive.E{Key: "description", Value: item.Description},
			primitive.E{Key: "permissions", Value: item.Permissions},
			primitive.E{Key: "roles", Value: roles},
			primitive.E{Key: "system", Value: item.System},
			primitive.E{Key: "date_updated", Value: item.DateUpdated},
		}},
	}

	res, err := sa.db.applicationsOrganizationsGroups.UpdateOneWithContext(context, groupFilter, groupUpdate, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAppOrgGroup, &logutils.FieldArgs{"id": item.ID}, err)
	}
	if res.ModifiedCount != 1 {
		return errors.ErrorAction(logutils.ActionUpdate, model.TypeAppOrgGroup, &logutils.FieldArgs{"id": item.ID, "modified": res.ModifiedCount, "expected": 1})
	}

	// update all accounts that have the group
	accountsFilter := bson.D{primitive.E{Key: "groups.group._id", Value: item.ID}}
	accountsUpdate := bson.D{
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "groups.$.group.name", Value: item.Name},
			primitive.E{Key: "groups.$.group.description", Value: item.Description},
			primitive.E{Key: "groups.$.group.permissions", Value: item.Permissions},
			primitive.E{Key: "groups.$.group.roles", Value: roles},
			primitive.E{Key: "groups.$.group.system", Value: item.System},
			primitive.E{Key: "groups.$.group.date_updated", Value: item.DateUpdated},
		}},
	}

	res, err = sa.db.accounts.UpdateManyWithContext(context, accountsFilter, accountsUpdate, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccount, &logutils.FieldArgs{"groups.group.id": item.ID}, err)
	}
	if res.ModifiedCount != res.MatchedCount {
		return errors.ErrorAction(logutils.ActionUpdate, model.TypeAccount, &logutils.FieldArgs{"groups.group.id": item.ID, "modified": res.ModifiedCount, "expected": res.MatchedCount})
	}

	return nil
}

// DeleteAppOrgGroup deletes application organization group
//   - make sure to call this function once you have verified that there is no any relations
//     in other collections for the group which is supposed to be deleted.
func (sa *Adapter) DeleteAppOrgGroup(id string) error {
	filter := bson.M{"_id": id}
	result, err := sa.db.applicationsOrganizationsGroups.DeleteOne(filter, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeAppOrgGroup, &logutils.FieldArgs{"_id": id}, err)
	}
	if result == nil {
		return errors.WrapErrorData(logutils.StatusInvalid, "delete result", &logutils.FieldArgs{"_id": id}, err)
	}
	deletedCount := result.DeletedCount
	if deletedCount == 0 {
		return errors.WrapErrorData(logutils.StatusMissing, model.TypeAppOrgGroup, &logutils.FieldArgs{"_id": id}, err)
	}

	return nil
}

// CountGroupsByRoleID counts how many groups there are with the passed role id
func (sa *Adapter) CountGroupsByRoleID(roleID string) (*int64, error) {
	filter := bson.D{primitive.E{Key: "roles._id", Value: roleID}}

	count, err := sa.db.applicationsOrganizationsGroups.CountDocuments(filter)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCount, model.TypeAppOrgGroup, &logutils.FieldArgs{"roles._id": roleID}, err)
	}
	return &count, nil
}

// LoadAPIKeys finds all api key documents in the DB
func (sa *Adapter) LoadAPIKeys() ([]model.APIKey, error) {
	filter := bson.D{}
	var result []model.APIKey
	err := sa.db.apiKeys.Find(filter, &result, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionLoad, model.TypeAPIKey, nil, err)
	}

	return result, nil
}

// InsertAPIKey inserts an API key
func (sa *Adapter) InsertAPIKey(context TransactionContext, apiKey model.APIKey) (*model.APIKey, error) {
	_, err := sa.db.apiKeys.InsertOneWithContext(context, apiKey)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionInsert, model.TypeAPIKey, &logutils.FieldArgs{"_id": apiKey.ID}, err)
	}
	return &apiKey, nil
}

// UpdateAPIKey updates the API key in storage
func (sa *Adapter) UpdateAPIKey(apiKey model.APIKey) error {
	filter := bson.M{"_id": apiKey.ID}
	err := sa.db.apiKeys.ReplaceOne(filter, apiKey, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAPIKey, &logutils.FieldArgs{"_id": apiKey.ID}, err)
	}

	return nil
}

// DeleteAPIKey deletes the API key from storage
func (sa *Adapter) DeleteAPIKey(ID string) error {
	filter := bson.M{"_id": ID}
	result, err := sa.db.apiKeys.DeleteOne(filter, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeAPIKey, &logutils.FieldArgs{"_id": ID}, err)
	}
	if result == nil {
		return errors.WrapErrorData(logutils.StatusInvalid, "delete result", &logutils.FieldArgs{"_id": ID}, err)
	}
	deletedCount := result.DeletedCount
	if deletedCount == 0 {
		return errors.WrapErrorData(logutils.StatusMissing, model.TypeAPIKey, &logutils.FieldArgs{"_id": ID}, err)
	}

	return nil
}

// LoadIdentityProviders finds all identity providers documents in the DB
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

// UpdateAccountProfile updates a profile
func (sa *Adapter) UpdateAccountProfile(context TransactionContext, profile model.Profile) error {
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
			primitive.E{Key: "profile.unstructured_properties", Value: profile.UnstructuredProperties},
		}},
	}

	res, err := sa.db.accounts.UpdateManyWithContext(context, filter, profileUpdate, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeProfile, nil, err)
	}
	sa.logger.Infof("modified %d profile copies", res.ModifiedCount)

	return nil
}

// UpdateAccountPrivacy updates the privacy settings for an account
func (sa *Adapter) UpdateAccountPrivacy(context TransactionContext, accountID string, privacy model.Privacy) error {
	filter := bson.D{primitive.E{Key: "_id", Value: accountID}}

	privacyUpdate := bson.D{
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "privacy", Value: privacy},
		}},
	}

	res, err := sa.db.accounts.UpdateManyWithContext(context, filter, privacyUpdate, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypePrivacy, nil, err)
	}
	sa.logger.Infof("modified %d privacy copies", res.ModifiedCount)

	return nil
}

// FindAccountProfiles finds profiles by app id, authtype id and account auth type identifier
func (sa *Adapter) FindAccountProfiles(appID string, authTypeID string, accountAuthTypeIdentifier string) ([]model.Profile, error) {
	pipeline := []bson.M{
		{"$match": bson.M{"auth_types.auth_type_id": authTypeID, "auth_types.identifier": accountAuthTypeIdentifier}},
		{"$lookup": bson.M{
			"from":         "applications_organizations",
			"localField":   "app_org_id",
			"foreignField": "_id",
			"as":           "app_org",
		}},
		{"$match": bson.M{"app_org.app_id": appID}},
	}
	var accounts []account
	err := sa.db.accounts.Aggregate(pipeline, &accounts, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, &logutils.FieldArgs{"app_id": appID, "auth_types.id": authTypeID, "auth_types.identifier": accountAuthTypeIdentifier}, err)
	}
	if len(accounts) == 0 {
		//not found
		return nil, nil
	}

	result := profilesFromStorage(accounts, *sa)
	return result, nil
}

// loadConfigs loads configs
func (sa *Adapter) loadConfigs() ([]model.Config, error) {
	filter := bson.M{}

	var configs []model.Config
	err := sa.db.configs.Find(filter, &configs, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeConfig, nil, err)
	}

	return configs, nil
}

// FindConfig finds the config for the specified type, appID, and orgID
func (sa *Adapter) FindConfig(configType string, appID string, orgID string) (*model.Config, error) {
	return sa.getCachedConfig("", configType, appID, orgID)
}

// FindConfigByID finds the config for the specified ID
func (sa *Adapter) FindConfigByID(id string) (*model.Config, error) {
	return sa.getCachedConfig(id, "", "", "")
}

// FindConfigs finds all configs for the specified type
func (sa *Adapter) FindConfigs(configType *string) ([]model.Config, error) {
	return sa.getCachedConfigs(configType)
}

// InsertConfig inserts a new config
func (sa *Adapter) InsertConfig(config model.Config) error {
	_, err := sa.db.configs.InsertOne(config)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionInsert, model.TypeConfig, nil, err)
	}

	return nil
}

// UpdateConfig updates an existing config
func (sa *Adapter) UpdateConfig(config model.Config) error {
	filter := bson.M{"_id": config.ID}
	update := bson.D{
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "type", Value: config.Type},
			primitive.E{Key: "app_id", Value: config.AppID},
			primitive.E{Key: "org_id", Value: config.OrgID},
			primitive.E{Key: "system", Value: config.System},
			primitive.E{Key: "data", Value: config.Data},
			primitive.E{Key: "date_updated", Value: config.DateUpdated},
		}},
	}
	_, err := sa.db.configs.UpdateOne(filter, update, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeConfig, &logutils.FieldArgs{"id": config.ID}, err)
	}

	return nil
}

// DeleteConfig deletes a configuration from storage
func (sa *Adapter) DeleteConfig(id string) error {
	delFilter := bson.M{"_id": id}
	_, err := sa.db.configs.DeleteMany(delFilter, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeConfig, &logutils.FieldArgs{"id": id}, err)
	}

	return nil
}

// FindOrganization finds an organization
func (sa *Adapter) FindOrganization(id string) (*model.Organization, error) {
	return sa.getCachedOrganization(id)
}

// FindSystemOrganization finds the system organization (only one)
func (sa *Adapter) FindSystemOrganization() (*model.Organization, error) {
	organizations, err := sa.getCachedOrganizations()
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeOrganization, nil, err)
	}

	for _, org := range organizations {
		if org.System {
			return &org, nil
		}
	}

	return nil, nil
}

// FindOrganizations finds all organizations
func (sa *Adapter) FindOrganizations() ([]model.Organization, error) {
	return sa.getCachedOrganizations()
}

// InsertOrganization inserts an organization
func (sa *Adapter) InsertOrganization(context TransactionContext, organization model.Organization) (*model.Organization, error) {
	org := organizationToStorage(&organization)

	_, err := sa.db.organizations.InsertOneWithContext(context, org)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionInsert, model.TypeOrganization, nil, err)
	}

	return &organization, nil
}

// UpdateOrganization updates an organization
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

// loadOrganizations gets the organizations
func (sa *Adapter) loadOrganizations() ([]model.Organization, error) {
	//no transactions for get operations..

	//1. find the organizations
	orgsFilter := bson.D{}
	var orgsResult []organization
	err := sa.db.organizations.Find(orgsFilter, &orgsResult, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionLoad, model.TypeOrganization, nil, err)
	}
	if len(orgsResult) == 0 {
		//no data
		return make([]model.Organization, 0), nil
	}

	//2. prepare the response
	organizations := organizationsFromStorage(orgsResult)
	return organizations, nil
}

// loadApplications loads all applications
func (sa *Adapter) loadApplications() ([]model.Application, error) {
	filter := bson.D{}
	var result []application
	err := sa.db.applications.Find(filter, &result, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionLoad, model.TypeApplication, nil, err)
	}

	if len(result) == 0 {
		//no data
		return make([]model.Application, 0), nil
	}

	applications := applicationsFromStorage(result)
	return applications, nil
}

// InsertApplication inserts an application
func (sa *Adapter) InsertApplication(context TransactionContext, application model.Application) (*model.Application, error) {
	app := applicationToStorage(&application)

	_, err := sa.db.applications.InsertOneWithContext(context, app)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionInsert, model.TypeApplication, nil, err)
	}

	return &application, nil
}

// SaveApplication saves an application
func (sa *Adapter) SaveApplication(context TransactionContext, application model.Application) error {
	filter := bson.D{primitive.E{Key: "_id", Value: application.ID}}
	app := applicationToStorage(&application)

	err := sa.db.applications.ReplaceOneWithContext(context, filter, app, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionSave, model.TypeApplication, &logutils.FieldArgs{"id": app.ID}, err)
	}

	return nil
}

// FindApplication finds application
func (sa *Adapter) FindApplication(context TransactionContext, ID string) (*model.Application, error) {
	if context != nil {
		filter := bson.D{primitive.E{Key: "_id", Value: ID}}

		var app application
		err := sa.db.applications.FindOneWithContext(context, filter, &app, nil)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplication, &logutils.FieldArgs{"_id": ID}, err)
		}

		modelApp := applicationFromStorage(&app)
		return &modelApp, nil
	}
	return sa.getCachedApplication(ID)
}

// FindApplications finds applications
func (sa *Adapter) FindApplications() ([]model.Application, error) {
	return sa.getCachedApplications()
}

// loadAppConfigs loads all application configs
func (sa *Adapter) loadAppConfigs() ([]model.ApplicationConfig, error) {
	filter := bson.D{}
	options := options.Find()
	options.SetSort(bson.D{primitive.E{Key: "app_type_id", Value: 1}, primitive.E{Key: "app_org_id", Value: 1}, primitive.E{Key: "version.version_numbers.major", Value: -1}, primitive.E{Key: "version.version_numbers.minor", Value: -1}, primitive.E{Key: "version.version_numbers.patch", Value: -1}}) //sort by version numbers
	var list []applicationConfig

	err := sa.db.applicationConfigs.Find(filter, &list, options)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationConfig, nil, err)
	}

	result := make([]model.ApplicationConfig, len(list))
	for i, item := range list {
		var appOrg *model.ApplicationOrganization
		if item.AppOrgID != nil {
			appOrg, err = sa.getCachedApplicationOrganizationByKey(*item.AppOrgID)
			if err != nil {
				return nil, errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeApplicationOrganization, nil, err)
			}
		}

		_, appType, err := sa.getCachedApplicationType(item.AppTypeID)
		if err != nil || appType == nil {
			return nil, errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeApplicationType, nil, err)
		}
		result[i] = appConfigFromStorage(&item, appOrg, *appType)
	}

	return result, nil
}

// FindAppConfigs finds appconfigs
func (sa *Adapter) FindAppConfigs(appTypeID string, appOrgID *string, versionNumbers *model.VersionNumbers) ([]model.ApplicationConfig, error) {
	return sa.getCachedApplicationConfigByAppTypeIDAndVersion(appTypeID, appOrgID, versionNumbers)
}

// FindAppConfigByVersion finds the most recent app config for the specified version
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

// FindAppConfigByID finds appconfig by ID
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
	updateItem := bson.D{primitive.E{Key: "date_updated", Value: now}, primitive.E{Key: "app_type_id", Value: appType.ID}, primitive.E{Key: "version", Value: versionToStorage(version)}}
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
		return errors.WrapErrorData(logutils.StatusInvalid, "delete result", &logutils.FieldArgs{"_id": ID}, err)
	}
	deletedCount := result.DeletedCount
	if deletedCount == 0 {
		return errors.WrapErrorData(logutils.StatusMissing, model.TypeApplicationConfig, &logutils.FieldArgs{"_id": ID}, err)
	}

	return nil
}

// FindApplicationType finds an application type by ID or identifier
func (sa *Adapter) FindApplicationType(id string) (*model.ApplicationType, error) {
	app, appType, err := sa.getCachedApplicationType(id)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationType, nil, err)
	}

	appType.Application = *app

	return appType, nil
}

// loadApplicationsOrganizations loads all applications organizations
func (sa *Adapter) loadApplicationsOrganizations() ([]model.ApplicationOrganization, error) {
	filter := bson.D{}
	var list []applicationOrganization
	err := sa.db.applicationsOrganizations.Find(filter, &list, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionLoad, model.TypeApplicationOrganization, nil, err)
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
			return nil, errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeApplication, nil, err)
		}
		if application == nil {
			return nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplication, &logutils.FieldArgs{"app_id": item.AppID})
		}
		organization, err := sa.getCachedOrganization(item.OrgID)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeOrganization, nil, err)
		}
		if organization == nil {
			return nil, errors.ErrorData(logutils.StatusMissing, model.TypeOrganization, &logutils.FieldArgs{"org_id": item.OrgID})
		}

		result[i] = applicationOrganizationFromStorage(item, *application, *organization)
	}
	return result, nil

}

// FindApplicationOrganization finds application organization
func (sa *Adapter) FindApplicationOrganization(appID string, orgID string) (*model.ApplicationOrganization, error) {
	return sa.getCachedApplicationOrganization(appID, orgID)
}

// FindApplicationsOrganizations finds application organizations
func (sa *Adapter) FindApplicationsOrganizations() ([]model.ApplicationOrganization, error) {
	return sa.getCachedApplicationOrganizations()
}

// FindApplicationsOrganizationsByOrgID finds applications organizations by orgID
func (sa *Adapter) FindApplicationsOrganizationsByOrgID(orgID string) ([]model.ApplicationOrganization, error) {

	cachedAppOrgs, err := sa.getCachedApplicationOrganizations()
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeApplicationOrganization, nil, err)
	}

	result := make([]model.ApplicationOrganization, 0)
	for _, appOrg := range cachedAppOrgs {
		if appOrg.Organization.ID == orgID {
			result = append(result, appOrg)
		}
	}

	return result, nil
}

// FindApplicationOrganizations finds applications organizations by appID or orgID
func (sa *Adapter) FindApplicationOrganizations(appID *string, orgID *string) ([]model.ApplicationOrganization, error) {
	cachedAppOrgs, err := sa.getCachedApplicationOrganizations()
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeApplicationOrganization, nil, err)
	}

	result := make([]model.ApplicationOrganization, 0)
	for _, appOrg := range cachedAppOrgs {
		if orgID == nil || appOrg.Organization.ID == *orgID {
			if appID == nil || appOrg.Application.ID == *appID {
				result = append(result, appOrg)
			}
		}
	}

	return result, nil
}

// FindApplicationOrganizationByID finds applications organizations by ID
func (sa *Adapter) FindApplicationOrganizationByID(ID string) (*model.ApplicationOrganization, error) {
	cachedAppOrgs, err := sa.getCachedApplicationOrganizations()
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeApplicationOrganization, nil, err)
	}

	for _, appOrg := range cachedAppOrgs {
		if appOrg.ID == ID {
			return &appOrg, nil
		}
	}

	return nil, nil
}

// InsertApplicationOrganization inserts an application organization
func (sa *Adapter) InsertApplicationOrganization(context TransactionContext, applicationOrganization model.ApplicationOrganization) (*model.ApplicationOrganization, error) {
	appOrg := applicationOrganizationToStorage(applicationOrganization)

	_, err := sa.db.applicationsOrganizations.InsertOneWithContext(context, appOrg)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionInsert, model.TypeApplicationOrganization, nil, err)
	}

	return &applicationOrganization, nil
}

// UpdateApplicationOrganization updates an application organization
func (sa *Adapter) UpdateApplicationOrganization(context TransactionContext, applicationOrganization model.ApplicationOrganization) error {
	appOrg := applicationOrganizationToStorage(applicationOrganization)
	now := time.Now()

	filter := bson.M{"_id": applicationOrganization.ID}
	update := bson.D{primitive.E{Key: "date_updated", Value: now},
		primitive.E{Key: "identity_providers_settings", Value: appOrg.IdentityProvidersSettings},
		primitive.E{Key: "supported_auth_types", Value: appOrg.SupportedAuthTypes},
		primitive.E{Key: "logins_sessions_settings", Value: appOrg.LoginsSessionsSetting},
		primitive.E{Key: "services_ids", Value: appOrg.ServicesIDs}}

	updateAppOrg := bson.D{
		primitive.E{Key: "$set", Value: update},
	}

	res, err := sa.db.applicationsOrganizations.UpdateOneWithContext(context, filter, updateAppOrg, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeApplicationOrganization, nil, err)
	}
	if res.ModifiedCount != 1 {
		return errors.ErrorAction(logutils.ActionUpdate, model.TypeApplicationOrganization, &logutils.FieldArgs{"unexpected modified count": res.ModifiedCount})
	}
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeApplicationOrganization, nil, err)
	}

	return nil
}

// FindDevice finds a device by device id and account id
func (sa *Adapter) FindDevice(context TransactionContext, deviceID *string, accountID string) (*model.Device, error) {
	filter := bson.D{primitive.E{Key: "account_id", Value: accountID}}

	if deviceID != nil {
		filter = append(filter, primitive.E{Key: "device_id", Value: *deviceID})
	}

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

// InsertDevice inserts a device
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
	res, err := sa.db.tenantsAccounts.UpdateOneWithContext(context, filter, update, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccount, logutils.StringArgs("inserting device"), err)
	}
	if res.ModifiedCount != 1 {
		return nil, errors.ErrorAction(logutils.ActionUpdate, model.TypeAccount, &logutils.FieldArgs{"unexpected modified count": res.ModifiedCount})
	}

	return &device, nil
}

// InsertAuthType inserts an auth type
func (sa *Adapter) InsertAuthType(context TransactionContext, authType model.AuthType) (*model.AuthType, error) {
	sa.setCachedAuthType(authType)
	_, err := sa.db.authTypes.InsertOneWithContext(context, authType)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionInsert, model.TypeAuthType, nil, err)
	}

	return &authType, nil
}

// UpdateAuthTypes updates an auth type
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

// MigrateServiceRegs migrates all service registrations from the service_regs collection to the service_registrations collection
// TODO: Remove this once all necessary migrations are complete
func (sa *Adapter) MigrateServiceRegs() error {
	transaction := func(context TransactionContext) error {
		filter := bson.M{"core_host": sa.host}
		count, err := sa.db.serviceRegistrations.CountDocumentsWithContext(context, filter)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionFind, model.TypeServiceReg, &logutils.FieldArgs{"core_host": sa.host, "service_id": "all"}, err)
		}

		if count > 0 {
			return nil
		}

		filter = bson.M{}
		var results []model.ServiceRegistration
		err = sa.db.serviceRegs.FindWithContext(context, filter, &results, nil)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionFind, model.TypeServiceReg, &logutils.FieldArgs{"service_id": "all"}, err)
		}

		if results != nil {
			var registrations []interface{}
			for _, res := range results {
				res.CoreHost = sa.host
				registrations = append(registrations, res)
			}

			_, err := sa.db.serviceRegistrations.InsertManyWithContext(context, registrations, nil)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionInsert, model.TypeServiceReg, nil, err)
			}
		}
		return nil
	}
	return sa.PerformTransaction(transaction)
}

// loadServiceRegs fetches all service registration records
func (sa *Adapter) loadServiceRegs() ([]model.ServiceRegistration, error) {
	filter := bson.M{"core_host": sa.host}
	var result []model.ServiceRegistration
	err := sa.db.serviceRegistrations.Find(filter, &result, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeServiceReg, &logutils.FieldArgs{"core_host": sa.host, "service_id": "all"}, err)
	}

	if result == nil {
		result = []model.ServiceRegistration{}
	}

	return result, nil
}

// FindServiceRegs fetches the requested service registration records
func (sa *Adapter) FindServiceRegs(serviceIDs []string) []model.ServiceRegistration {
	return sa.getCachedServiceRegs(serviceIDs)
}

// FindServiceReg finds the service registration in storage
func (sa *Adapter) FindServiceReg(serviceID string) (*model.ServiceRegistration, error) {
	return sa.getCachedServiceReg(serviceID)
}

// InsertServiceReg inserts the service registration to storage
func (sa *Adapter) InsertServiceReg(reg *model.ServiceRegistration) error {
	reg.CoreHost = sa.host
	_, err := sa.db.serviceRegistrations.InsertOne(reg)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionInsert, model.TypeServiceReg, &logutils.FieldArgs{"core_host": sa.host, "service_id": reg.Registration.ServiceID}, err)
	}

	return nil
}

// UpdateServiceReg updates the service registration in storage
func (sa *Adapter) UpdateServiceReg(reg *model.ServiceRegistration) error {
	reg.CoreHost = sa.host
	filter := bson.M{"core_host": reg.CoreHost, "registration.service_id": reg.Registration.ServiceID}
	err := sa.db.serviceRegistrations.ReplaceOne(filter, reg, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeServiceReg, &logutils.FieldArgs{"core_host": reg.CoreHost, "service_id": reg.Registration.ServiceID}, err)
	}

	return nil
}

// SaveServiceReg saves the service registration to the storage
func (sa *Adapter) SaveServiceReg(reg *model.ServiceRegistration, immediateCache bool) error {
	if reg == nil {
		return nil
	}

	reg.CoreHost = sa.host
	filter := bson.M{"core_host": reg.CoreHost, "registration.service_id": reg.Registration.ServiceID}
	opts := options.Replace().SetUpsert(true)
	err := sa.db.serviceRegistrations.ReplaceOne(filter, reg, opts)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionSave, model.TypeServiceReg, &logutils.FieldArgs{"core_host": reg.CoreHost, "service_id": reg.Registration.ServiceID}, err)
	}

	if immediateCache {
		sa.cacheServiceReg(*reg)
	}

	return nil
}

// DeleteServiceReg deletes the service registration from storage
func (sa *Adapter) DeleteServiceReg(serviceID string) error {
	filter := bson.M{"core_host": sa.host, "registration.service_id": serviceID}
	result, err := sa.db.serviceRegistrations.DeleteOne(filter, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeServiceReg, &logutils.FieldArgs{"core_host": sa.host, "service_id": serviceID}, err)
	}
	if result == nil {
		return errors.WrapErrorData(logutils.StatusInvalid, "delete result", &logutils.FieldArgs{"core_host": sa.host, "service_id": serviceID}, err)
	}
	deletedCount := result.DeletedCount
	if deletedCount == 0 {
		return errors.WrapErrorData(logutils.StatusMissing, model.TypeServiceReg, &logutils.FieldArgs{"core_host": sa.host, "service_id": serviceID}, err)
	}

	return nil
}

// FindServiceAuthorization finds the service authorization in storage
func (sa *Adapter) FindServiceAuthorization(userID string, serviceID string) (*model.ServiceAuthorization, error) {
	filter := bson.M{"user_id": userID, "service_id": serviceID}
	var reg *model.ServiceAuthorization
	err := sa.db.serviceAuthorizations.FindOne(filter, &reg, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeServiceAuthorization, &logutils.FieldArgs{"user_id": userID, "service_id": serviceID}, err)
	}

	return reg, nil
}

// SaveServiceAuthorization saves the service authorization to storage
func (sa *Adapter) SaveServiceAuthorization(authorization *model.ServiceAuthorization) error {
	filter := bson.M{"user_id": authorization.UserID, "service_id": authorization.ServiceID}
	opts := options.Replace().SetUpsert(true)
	err := sa.db.serviceAuthorizations.ReplaceOne(filter, authorization, opts)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionSave, model.TypeServiceAuthorization, &logutils.FieldArgs{"user_id": authorization.UserID, "service_id": authorization.ServiceID}, err)
	}

	return nil
}

// DeleteServiceAuthorization deletes the service authorization from storage
func (sa *Adapter) DeleteServiceAuthorization(userID string, serviceID string) error {
	filter := bson.M{"user_id": userID, "service_id": serviceID}
	result, err := sa.db.serviceAuthorizations.DeleteOne(filter, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeServiceAuthorization, &logutils.FieldArgs{"user_id": userID, "service_id": serviceID}, err)
	}
	if result == nil {
		return errors.WrapErrorData(logutils.StatusInvalid, "delete result", &logutils.FieldArgs{"user_id": userID, "service_id": serviceID}, err)
	}
	deletedCount := result.DeletedCount
	if deletedCount == 0 {
		return errors.WrapErrorData(logutils.StatusMissing, model.TypeServiceAuthorization, &logutils.FieldArgs{"user_id": userID, "service_id": serviceID}, err)
	}

	return nil
}

// SaveDevice saves device
func (sa *Adapter) SaveDevice(context TransactionContext, device *model.Device) error {
	if device == nil {
		return errors.ErrorData(logutils.StatusInvalid, logutils.TypeArg, logutils.StringArgs("device"))
	}

	storageDevice := deviceToStorage(device)

	filter := bson.M{"_id": device.ID}
	opts := options.Replace().SetUpsert(true)
	err := sa.db.devices.ReplaceOneWithContext(context, filter, storageDevice, opts)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionSave, model.TypeDevice, &logutils.FieldArgs{"device_id": device.ID}, nil)
	}

	return nil
}

// DeleteDevice deletes a device
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

func (sa *Adapter) getFilterForParams(params map[string]interface{}) bson.M {
	filter := bson.M{}
	for k, v := range params {
		if k == "id" {
			k = "_id"
		}
		if v != nil && reflect.TypeOf(v).Kind() == reflect.Slice {
			filter[k] = bson.M{"$in": v}
		} else if v != nil && reflect.TypeOf(v).Kind() == reflect.Map {
			vMap, ok := v.(map[string]interface{})
			if ok {
				op, okOp := vMap["operation"].(string)
				val, okVal := vMap["value"]
				if okOp && okVal {
					if op == "any" {
						if val != nil && reflect.TypeOf(val).Kind() == reflect.Slice {
							filter[k] = bson.M{"$elemMatch": bson.M{"$in": val}}
						} else {
							filter[k] = bson.M{"$elemMatch": val}
						}
					}
					continue
				}
			}
			filter[k] = v
		} else if v == "$exists" {
			filter[k] = bson.M{"$exists": true}
		} else {
			filter[k] = v
		}
	}
	return filter
}

func (sa *Adapter) getProjectionForKeys(keys []string) bson.D {
	projection := bson.D{}
	usesID := false
	for _, k := range keys {
		if k == "id" {
			k = "_id"
			usesID = true
		}
		projection = append(projection, bson.E{Key: k, Value: 1})
	}
	if !usesID {
		projection = append(projection, bson.E{Key: "_id", Value: 0})
	}
	return projection
}

func (sa *Adapter) convertIDs(results []map[string]interface{}) {
	for _, result := range results {
		sa.convertID(result)
	}
}

func (sa *Adapter) convertID(result map[string]interface{}) {
	for k, v := range result {
		if k == "_id" {
			result["id"] = v
			delete(result, "_id")
		}
		//TODO: recursively search for embedded _id if necessary
		// if v != nil && reflect.TypeOf(v).Kind() == reflect.Map {
		// 	mapVal := v.(map[string]interface{})
		// 	sa.convertID(mapVal)
		// 	result[k] = mapVal
		// }
	}
}

func (sa *Adapter) abortTransaction(sessionContext mongo.SessionContext) {
	err := sessionContext.AbortTransaction(sessionContext)
	if err != nil {
		sa.logger.Errorf("error aborting a transaction - %s", err)
	}
}

// NewStorageAdapter creates a new storage adapter instance
func NewStorageAdapter(host string, mongoDBAuth string, mongoDBName string, mongoTimeout string, uiucAuthTypeCodeMigrationSource string, logger *logs.Logger) *Adapter {
	timeoutInt, err := strconv.Atoi(mongoTimeout)
	if err != nil {
		logger.Warn("Setting default Mongo timeout - 500")
		timeoutInt = 500
	}
	timeout := time.Millisecond * time.Duration(timeoutInt)

	cachedServiceRegs := &syncmap.Map{}
	serviceRegsLock := &sync.RWMutex{}

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

	cachedConfigs := &syncmap.Map{}
	configsLock := &sync.RWMutex{}

	db := &database{mongoDBAuth: mongoDBAuth, mongoDBName: mongoDBName, mongoTimeout: timeout, logger: logger, uiucAuthTypeCodeMigrationSource: uiucAuthTypeCodeMigrationSource}
	return &Adapter{db: db, logger: logger, host: host, cachedServiceRegs: cachedServiceRegs, serviceRegsLock: serviceRegsLock,
		cachedOrganizations: cachedOrganizations, organizationsLock: organizationsLock,
		cachedApplications: cachedApplications, applicationsLock: applicationsLock,
		cachedAuthTypes: cachedAuthTypes, authTypesLock: authTypesLock,
		cachedApplicationsOrganizations: cachedApplicationsOrganizations, applicationsOrganizationsLock: applicationsOrganizationsLock,
		cachedApplicationConfigs: cachedApplicationConfigs, applicationConfigsLock: applicationConfigsLock,
		cachedConfigs: cachedConfigs, configsLock: configsLock}
}

type storageListener struct {
	adapter *Adapter
	DefaultListenerImpl
}

func (sl *storageListener) OnAuthTypesUpdated() {
	sl.adapter.cacheAuthTypes()
}

func (sl *storageListener) OnServiceRegistrationsUpdated() {
	sl.adapter.cacheServiceRegs()
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

func (sl *storageListener) OnApplicationConfigsUpdated() {
	sl.adapter.cacheApplicationConfigs()
}

func (sl *storageListener) OnConfigsUpdated() {
	sl.adapter.cacheConfigs()
}

// Listener represents storage listener
type Listener interface {
	OnAPIKeysUpdated()
	OnAuthTypesUpdated()
	OnIdentityProvidersUpdated()
	OnServiceRegistrationsUpdated()
	OnOrganizationsUpdated()
	OnApplicationsUpdated()
	OnApplicationsOrganizationsUpdated()
	OnApplicationConfigsUpdated()
	OnConfigsUpdated()
}

// DefaultListenerImpl default listener implementation
type DefaultListenerImpl struct{}

// OnAPIKeysUpdated notifies api keys have been updated
func (d *DefaultListenerImpl) OnAPIKeysUpdated() {}

// OnAuthTypesUpdated notifies auth types have been updated
func (d *DefaultListenerImpl) OnAuthTypesUpdated() {}

// OnIdentityProvidersUpdated notifies identity providers have been updated
func (d *DefaultListenerImpl) OnIdentityProvidersUpdated() {}

// OnServiceRegistrationsUpdated notifies services registrations have been updated
func (d *DefaultListenerImpl) OnServiceRegistrationsUpdated() {}

// OnOrganizationsUpdated notifies organizations have been updated
func (d *DefaultListenerImpl) OnOrganizationsUpdated() {}

// OnApplicationsUpdated notifies applications have been updated
func (d *DefaultListenerImpl) OnApplicationsUpdated() {}

// OnApplicationsOrganizationsUpdated notifies applications organizations have been updated
func (d *DefaultListenerImpl) OnApplicationsOrganizationsUpdated() {}

// OnApplicationConfigsUpdated notifies application configs have been updated
func (d *DefaultListenerImpl) OnApplicationConfigsUpdated() {}

// OnConfigsUpdated notifies configs have been updated
func (d *DefaultListenerImpl) OnConfigsUpdated() {}

// TransactionContext wraps mongo.SessionContext for use by external packages
type TransactionContext interface {
	mongo.SessionContext
}
