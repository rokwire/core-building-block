package storage

import (
	"context"
	"core-building-block/core/model"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/rokmetro/logging-library/errors"
	"github.com/rokmetro/logging-library/logs"
	"github.com/rokmetro/logging-library/logutils"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type application struct {
	ID       string   `bson:"_id"`
	Name     string   `bson:"name"`
	Versions []string `bson:"versions"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
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
		return errors.WrapErrorAction(logutils.ActionInitialize, "storage adapter", nil, err)
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
			abortTransaction(sessionContext)
			return errors.WrapErrorAction(logutils.ActionDelete, model.TypeGlobalConfig, nil, err)
		}

		//add the new one
		_, err = sa.db.globalConfig.InsertOneWithContext(sessionContext, gc)
		if err != nil {
			abortTransaction(sessionContext)
			return errors.WrapErrorAction(logutils.ActionInsert, model.TypeGlobalConfig, nil, err)
		}

		err = sessionContext.CommitTransaction(sessionContext)
		if err != nil {
			abortTransaction(sessionContext)
			return errors.WrapErrorAction(logutils.ActionCommit, logutils.TypeTransaction, nil, err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
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
		return nil, errors.WrapErrorAction(logutils.ActionInsert, model.TypeOrganization, nil, err)
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
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeOrganization, nil, err)
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
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeOrganization, &logutils.FieldArgs{"id": ID}, err)
	}
	if result.MatchedCount == 0 {
		return errors.WrapErrorData(logutils.StatusMissing, model.TypeOrganization, &logutils.FieldArgs{"id": ID}, err)
	}

	return nil
}

//GetOrganizations gets the organizations
func (sa *Adapter) GetOrganizations() ([]model.Organization, error) {

	filter := bson.D{}
	var result []model.Organization
	err := sa.db.organizations.Find(filter, &result, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeOrganization, nil, err)
	}

	var resultList []model.Organization
	for _, current := range result {
		item := &model.Organization{ID: current.ID, Name: current.Name, Type: current.Type, RequiresOwnLogin: current.RequiresOwnLogin,
			LoginTypes: current.LoginTypes, Config: current.Config}
		resultList = append(resultList, *item)
	}
	return resultList, nil
}

//GetApplication gets application
func (sa *Adapter) GetApplication(ID string) (*model.Application, error) {
	filter := bson.D{primitive.E{Key: "_id", Value: ID}}
	var result []application
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

//NewStorageAdapter creates a new storage adapter instance
func NewStorageAdapter(mongoDBAuth string, mongoDBName string, mongoTimeout string, logger *logs.Logger) *Adapter {
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
