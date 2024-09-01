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
	"core-building-block/core/model"
	"core-building-block/utils"
	"fmt"
	"strings"

	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logutils"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/sync/syncmap"
	"gopkg.in/go-playground/validator.v9"
)

// KEYS

// loadKeys loads all keys
func (sa *Adapter) loadKeys() ([]model.Key, error) {
	filter := bson.D{}
	var result []model.Key
	err := sa.db.keys.Find(filter, &result, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeKey, nil, err)
	}

	return result, nil
}

// cacheKeys caches the keys
func (sa *Adapter) cacheKeys() error {
	sa.logger.Info("cacheKeys..")

	keys, err := sa.loadKeys()
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeKey, nil, err)
	}
	sa.setCachedKeys(keys)

	return nil
}

func (sa *Adapter) setCachedKeys(keys []model.Key) {
	sa.keysLock.Lock()
	defer sa.keysLock.Unlock()

	sa.cachedKeys = &syncmap.Map{}

	for _, key := range keys {
		sa.cachedKeys.Store(key.Name, key)
	}
}

func (sa *Adapter) getCachedKey(name string) (*model.Key, error) {
	sa.keysLock.RLock()
	defer sa.keysLock.RUnlock()

	errArgs := &logutils.FieldArgs{"name": name}

	item, _ := sa.cachedKeys.Load(name)
	if item != nil {
		key, ok := item.(model.Key)
		if !ok {
			return nil, errors.ErrorAction(logutils.ActionCast, model.TypeKey, errArgs)
		}
		return &key, nil
	}
	return nil, nil
}

// SERVICE REGS

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

// AUTH TYPES

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
			sa.setCachedAuthType(authType)
		} else {
			sa.logger.Errorf("failed to validate and cache auth type with code %s: %s", authType.Code, err.Error())
		}
	}
}

func (sa *Adapter) setCachedAuthType(authType model.AuthType) {
	//we will get it by id and code as well
	sa.cachedAuthTypes.Store(authType.ID, authType)
	sa.cachedAuthTypes.Store(authType.Code, authType)
	for _, alias := range authType.Aliases {
		sa.cachedAuthTypes.Store(alias, authType)
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

// ORGANIZATIONS

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

// APPLICATIONS

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

// APPLICATION ORGANIZATIONS

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

// APP CONFIGS

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

// ASSETS

// loadAppAsssets gets the app assets
func (sa *Adapter) loadAppAssets() ([]model.AppAsset, error) {
	//no transactions for get operations..

	//1. find the assets
	filter := bson.D{}
	var results []model.AppAsset
	err := sa.db.applicationAssets.Find(filter, &results, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionLoad, model.TypeAppAsset, nil, err)
	}
	return results, nil
}

// cacheApplicationAssets caches the app assets from the DB
func (sa *Adapter) cacheApplicationAssets() error {
	sa.logger.Info("cacheApplicationAssets...")

	assets, err := sa.loadAppAssets()
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeAppAsset, nil, err)
	}

	sa.setCachedApplicationAssets(&assets)

	return nil
}

func (sa *Adapter) setCachedApplicationAssets(assets *[]model.AppAsset) {
	sa.applicationAssetsLock.Lock()
	defer sa.applicationAssetsLock.Unlock()

	sa.cachedApplicationAssets = &syncmap.Map{}
	validate := validator.New()

	for _, asset := range *assets {
		key := fmt.Sprintf("%s_%s_%s", asset.OrgID, asset.AppID, asset.Name)
		err := validate.Struct(asset)
		if err == nil {
			sa.cachedApplicationAssets.Store(key, asset)
		} else {
			sa.logger.Errorf("failed to validate and cache application asset %s: %s", key, err.Error())
		}
	}
}

func (sa *Adapter) getCachedApplicationAsset(orgID string, appID string, name string) (*model.AppAsset, error) {
	sa.applicationAssetsLock.RLock()
	defer sa.applicationAssetsLock.RUnlock()

	errArgs := &logutils.FieldArgs{"org_id": orgID, "app_id": appID, "name": name}

	key := fmt.Sprintf("%s_%s_%s", orgID, appID, name)
	item, _ := sa.cachedApplicationAssets.Load(key)
	if item != nil {
		asset, ok := item.(model.AppAsset)
		if !ok {
			return nil, errors.ErrorAction(logutils.ActionCast, model.TypeAppAsset, errArgs)
		}
		return &asset, nil
	}
	return nil, nil
}

func (sa *Adapter) getCachedApplicationAssets(orgID string, appID string) ([]model.AppAsset, error) {
	sa.applicationAssetsLock.RLock()
	defer sa.applicationAssetsLock.RUnlock()

	var err error
	assets := make([]model.AppAsset, 0)
	sa.cachedApplicationAssets.Range(func(key, item interface{}) bool {
		errArgs := &logutils.FieldArgs{"org_id": orgID, "app_id": appID}
		if item == nil {
			err = errors.ErrorData(logutils.StatusInvalid, model.TypeAppAsset, errArgs)
			return false
		}

		asset, ok := item.(model.AppAsset)
		if !ok {
			err = errors.ErrorAction(logutils.ActionCast, model.TypeAppAsset, errArgs)
			return false
		}
		if asset.AppID == appID && asset.OrgID == orgID {
			assets = append(assets, asset)
		}
		return true
	})

	return assets, err
}

// CONFIGS

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
