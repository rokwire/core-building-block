package storage

import (
	"context"
	"core-building-block/core/model"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rokmetro/auth-library/authservice"
	log "github.com/rokmetro/logging-library/loglib"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/sync/syncmap"
	"gopkg.in/go-playground/validator.v9"
)

type user struct {
	ID string `bson:"_id"`

	Account model.UserAccount `bson:"account"`
	Profile model.UserProfile `bson:"profile"`

	Permissions              []model.GlobalPermission `bson:"permissions"`
	Roles                    []model.GlobalRole       `bson:"roles"`
	Groups                   []model.GlobalGroup      `bson:"groups"`
	OrganizationsMemberships []userMembership         `bson:"organizations_memberships"`

	Devices []model.Device `bson:"devices"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

type rawMembership struct {
	ID     string `bson:"_id"`
	UserID string `bson:"user_id"`

	OrgID       string                 `bson:"organization_id"`
	OrgUserData map[string]interface{} `bson:"org_user_data"`

	Permissions []string `bson:"permissions"`
	Roles       []string `bson:"roles"`
	Groups      []string `bson:"groups"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

type userMembership struct {
	ID string `bson:"_id"`

	OrgID       string                 `bson:"organization_id"`
	OrgUserData map[string]interface{} `bson:"org_user_data"`

	Permissions []model.OrganizationPermission `bson:"permissions"`
	Roles       []model.OrganizationRole       `bson:"roles"`
	Groups      []model.OrganizationGroup      `bson:"groups"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

type group struct {
	ID   string `bson:"_id"`
	Name string `bson:"name"`

	OrgID string `bson:"organization_id"`

	Permissions []string `bson:"permissions"`
	Roles       []string `bson:"roles"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

type role struct {
	ID          string `bson:"_id"`
	Name        string `bson:"name"`
	Description string `bson:"desciption"`

	OrgID string `bson:"organization_id"`

	Permissions []string `bson:"permissions"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

type permission struct {
	ID   string `bson:"_id"`
	Name string `bson:"name"`

	OrgID string `bson:"organization_id"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

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

	organizations     *syncmap.Map
	organizationsLock *sync.RWMutex
}

//Start starts the storage
func (sa *Adapter) Start() error {
	err := sa.db.start()
	if err != nil {
		return log.WrapActionError(log.ActionInitialize, "storage adapter", nil, err)
	}

	sl := storageListener{adapter: sa}
	sa.RegisterStorageListener(&sl)

	return err
}

//RegisterStorageListener registers a data change listener with the storage adapter
func (sa *Adapter) RegisterStorageListener(storageListener Listener) {
	sa.db.listeners = append(sa.db.listeners, storageListener)
}

//cacheOrganizations caches the organizations from the DB
func (sa *Adapter) cacheOrganizations() error {
	organizations, err := sa.GetOrganizations()
	if err != nil {
		return log.WrapActionError(log.ActionFind, model.TypeOrganization, nil, err)
	}

	sa.setOrganizations(&organizations)

	return nil
}

func (sa *Adapter) getOrganization(orgID string) (*model.Organization, error) {
	sa.organizationsLock.RLock()
	defer sa.organizationsLock.RUnlock()

	errArgs := &log.FieldArgs{"org_id": orgID}

	item, _ := sa.organizations.Load(orgID)
	if item != nil {
		organization, ok := item.(model.Organization)
		if !ok {
			return nil, log.ActionError(log.ActionCast, model.TypeOrganization, errArgs)
		}
		return &organization, nil
	}
	return nil, log.DataError(log.StatusMissing, model.TypeAuthConfig, errArgs)
}

func (sa *Adapter) setOrganizations(organizations *[]model.Organization) {
	sa.organizations = &syncmap.Map{}
	validate := validator.New()

	sa.organizationsLock.Lock()
	defer sa.organizationsLock.Unlock()
	for _, org := range *organizations {
		err := validate.Struct(org)
		if err == nil {
			sa.organizations.Store(org.ID, org)
		}
	}
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
	filter := bson.M{key: id}
	var user user
	err := sa.db.users.FindOne(filter, &user, nil)
	if err != nil {
		return nil, log.WrapActionError(log.ActionFind, model.TypeUser, nil, err)
	}

	fullUser := model.User{ID: user.ID, Account: user.Account, Profile: user.Profile,
		Permissions: user.Permissions, Roles: user.Roles, Groups: user.Groups,
		OrganizationsMemberships: []model.OrganizationMembership{}, Devices: user.Devices,
		DateCreated: user.DateCreated, DateUpdated: user.DateUpdated}
	for _, m := range user.OrganizationsMemberships {
		membership := model.OrganizationMembership{ID: m.ID, OrgUserData: m.OrgUserData,
			Permissions: m.Permissions, Roles: m.Roles, Groups: m.Groups, DateCreated: m.DateCreated, DateUpdated: m.DateUpdated}

		org, err := sa.getOrganization(m.OrgID)
		if err != nil {
			fmt.Printf("failed to find cached organization for org_id %s\n", m.OrgID)
		} else {
			membership.Organization = *org
		}

		fullUser.OrganizationsMemberships = append(fullUser.OrganizationsMemberships, membership)
	}

	return &fullUser, nil
}

//InsertUser inserts a user
func (sa *Adapter) InsertUser(userAuth *model.UserAuth, authCred *model.AuthCred) (*model.User, error) {
	if userAuth == nil {
		return nil, log.DataError(log.StatusInvalid, log.TypeArg, log.StringArgs(model.TypeUserAuth))
	}

	now := time.Now().UTC()
	newID, err := uuid.NewUUID()
	if err != nil {
		return nil, log.DataError(log.StatusInvalid, log.TypeString, log.StringArgs("user_id"))
	}
	newUser := user{ID: newID.String(), DateCreated: now}

	accountID, err := uuid.NewUUID()
	if err != nil {
		return nil, log.DataError(log.StatusInvalid, log.TypeString, log.StringArgs("account_id"))
	}
	newAccount := model.UserAccount{ID: accountID.String(), Email: userAuth.Email, Phone: userAuth.Phone, DateCreated: now}
	newUser.Account = newAccount

	profileID, err := uuid.NewUUID()
	if err != nil {
		return nil, log.DataError(log.StatusInvalid, log.TypeString, log.StringArgs("profile_id"))
	}
	newProfile := model.UserProfile{ID: profileID.String(), FirstName: userAuth.FirstName, LastName: userAuth.LastName, DateCreated: now}
	newUser.Profile = newProfile

	//TODO: populate new device with device information (search for existing device first)
	deviceID, err := uuid.NewUUID()
	if err != nil {
		return nil, log.DataError(log.StatusInvalid, log.TypeString, log.StringArgs("device_id"))
	}
	newDevice := model.Device{ID: deviceID.String(), DateCreated: now}
	newUser.Devices = []model.Device{newDevice}

	membershipID, err := uuid.NewUUID()
	if err != nil {
		return nil, log.DataError(log.StatusInvalid, log.TypeString, log.StringArgs("membership_id"))
	}
	orgID, ok := userAuth.OrgData["orgID"].(string)
	if !ok {
		return nil, log.DataError(log.StatusInvalid, log.TypeString, log.StringArgs("org_id"))
	}
	newOrgMembership := userMembership{ID: membershipID.String(), OrgID: orgID, OrgUserData: userAuth.OrgData, DateCreated: now}

	rawMembership := rawMembership{ID: membershipID.String(), UserID: newID.String(), OrgID: orgID,
		OrgUserData: userAuth.OrgData, DateCreated: now}

	// TODO:
	// maybe set groups based on organization populations

	newUser.OrganizationsMemberships = []userMembership{newOrgMembership}

	// transaction
	err = sa.db.dbClient.UseSession(context.Background(), func(sessionContext mongo.SessionContext) error {
		err := sessionContext.StartTransaction()
		if err != nil {
			abortTransaction(sessionContext)
			return log.WrapActionError(log.ActionStart, log.TypeTransaction, nil, err)
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

		err = sa.InsertMembership(&rawMembership, sessionContext)
		if err != nil {
			abortTransaction(sessionContext)
			return log.WrapActionError(log.ActionInsert, model.TypeOrganizationMembership, nil, err)
		}

		//TODO: only save if device info has changed or it is new device
		// err = sa.SaveDevice(&newDevice, sessionContext)
		// if err == nil {
		// 	abortTransaction(sessionContext)
		// 	return log.WrapActionError(log.ActionSave, "device", nil, err)
		// }

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

	membership := model.OrganizationMembership{ID: newOrgMembership.ID, OrgUserData: newOrgMembership.OrgUserData,
		DateCreated: newOrgMembership.DateCreated, DateUpdated: newOrgMembership.DateUpdated}
	org, err := sa.getOrganization(orgID)
	if err != nil {
		fmt.Printf("failed to find cached organization for org_id %s\n", orgID)
	} else {
		membership.Organization = *org
	}

	returnUser := model.User{ID: newUser.ID, Account: newUser.Account, Profile: newUser.Profile,
		Permissions: newUser.Permissions, Roles: newUser.Roles, Groups: newUser.Groups,
		OrganizationsMemberships: []model.OrganizationMembership{membership}, Devices: newUser.Devices,
		DateCreated: newUser.DateCreated, DateUpdated: newUser.DateUpdated}
	return &returnUser, nil
}

//UpdateUser updates an existing user
func (sa *Adapter) UpdateUser(updatedUser *model.User, newOrgData *map[string]interface{}) (*model.User, error) {
	if updatedUser == nil {
		return nil, log.DataError(log.StatusInvalid, log.TypeArg, log.StringArgs(model.TypeUser))
	}

	now := time.Now().UTC()
	newUser := user{ID: updatedUser.ID, Account: updatedUser.Account, Profile: updatedUser.Profile,
		Permissions: updatedUser.Permissions, Roles: updatedUser.Roles, Groups: updatedUser.Groups,
		OrganizationsMemberships: []userMembership{}, Devices: updatedUser.Devices,
		DateCreated: updatedUser.DateCreated, DateUpdated: &now}

	for _, m := range updatedUser.OrganizationsMemberships {
		membership := userMembership{ID: m.ID, OrgID: m.Organization.ID, OrgUserData: m.OrgUserData,
			Permissions: m.Permissions, Roles: m.Roles, Groups: m.Groups, DateCreated: m.DateCreated, DateUpdated: m.DateUpdated}
		newUser.OrganizationsMemberships = append(newUser.OrganizationsMemberships, membership)
	}

	// TODO:
	// check for device updates and add possible new device

	var newMembership *rawMembership
	if newOrgData != nil {
		membershipID, err := uuid.NewUUID()
		if err != nil {
			return nil, log.WrapDataError(log.StatusInvalid, log.TypeString, log.StringArgs("membership_id"), err)
		}
		orgID, ok := (*newOrgData)["orgID"].(string)
		if !ok {
			return nil, log.WrapDataError(log.StatusInvalid, log.TypeString, log.StringArgs("org_id"), err)
		}
		newOrgMembership := rawMembership{ID: membershipID.String(), UserID: updatedUser.ID, OrgID: orgID,
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
			abortTransaction(sessionContext)
			return log.WrapActionError(log.ActionStart, log.TypeTransaction, nil, err)
		}

		filter := bson.M{"_id": updatedUser.ID}
		err = sa.db.users.ReplaceOneWithContext(sessionContext, filter, newUser, nil)
		if err != nil {
			abortTransaction(sessionContext)
			return log.WrapActionError(log.ActionReplace, model.TypeUser, nil, err)
		}

		if newMembership != nil {
			err = sa.InsertMembership(newMembership, sessionContext)
			if err != nil {
				abortTransaction(sessionContext)
				return log.WrapActionError(log.ActionInsert, model.TypeOrganizationMembership, nil, err)
			}
		}

		//TODO: save device if some device info has changed or added new device
		// err = sa.SaveDevice(&newDevice, sessionContext)
		// if err == nil {
		// 	abortTransaction(sessionContext)
		// 	return log.WrapActionError(log.ActionSave, "device", nil, err)
		// }

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

	return updatedUser, nil
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

//FindGlobalPermissions finds a set of global user permissions
func (sa *Adapter) FindGlobalPermissions(ids *[]string, context mongo.SessionContext) (*[]model.GlobalPermission, error) {
	permissionsFilter := bson.D{primitive.E{Key: "_id", Value: bson.M{"$in": *ids}}}
	var permissionsResult []permission
	var err error
	if context == nil {
		err = sa.db.permissions.Find(permissionsFilter, &permissionsResult, nil)
	} else {
		err = sa.db.permissions.FindWithContext(context, permissionsFilter, &permissionsResult, nil)
	}
	if err != nil {
		return nil, err
	}

	globalPermissions := []model.GlobalPermission{}
	for _, permission := range permissionsResult {
		globalPermission := model.GlobalPermission{ID: permission.ID, Name: permission.Name}
		globalPermissions = append(globalPermissions, globalPermission)
	}

	return &globalPermissions, nil
}

//FindOrganizationPermissions finds a set of organization user permissions
func (sa *Adapter) FindOrganizationPermissions(ids *[]string, orgID string, context mongo.SessionContext) (*[]model.OrganizationPermission, error) {
	permissionsFilter := bson.D{primitive.E{Key: "organization_id", Value: orgID}, primitive.E{Key: "_id", Value: bson.M{"$in": *ids}}}
	var permissionsResult []permission
	var err error
	if context == nil {
		err = sa.db.permissions.Find(permissionsFilter, &permissionsResult, nil)
	} else {
		err = sa.db.permissions.FindWithContext(context, permissionsFilter, &permissionsResult, nil)
	}
	if err != nil {
		return nil, err
	}

	orgPermissions := []model.OrganizationPermission{}
	for _, permission := range permissionsResult {
		orgPermission := model.OrganizationPermission{ID: permission.ID, Name: permission.Name}
		orgPermissions = append(orgPermissions, orgPermission)
	}

	return &orgPermissions, nil
}

//FindGlobalRoles finds a set of global user roles
func (sa *Adapter) FindGlobalRoles(ids *[]string, context mongo.SessionContext) (*[]model.GlobalRole, error) {
	rolesFilter := bson.D{primitive.E{Key: "_id", Value: bson.M{"$in": *ids}}}
	var rolesResult []role
	var err error
	if context == nil {
		err = sa.db.roles.Find(rolesFilter, &rolesResult, nil)
	} else {
		err = sa.db.roles.FindWithContext(context, rolesFilter, &rolesResult, nil)
	}
	if err != nil {
		return nil, err
	}

	globalRoles := []model.GlobalRole{}
	for _, role := range rolesResult {
		globalRole := model.GlobalRole{ID: role.ID, Name: role.Name, Description: role.Description}

		permissions, err := sa.FindGlobalPermissions(&role.Permissions, context)
		if err != nil {
			fmt.Printf("failed to find global permissions for role ID %s\n", role.ID)
		} else {
			globalRole.Permissions = *permissions
		}
		globalRoles = append(globalRoles, globalRole)
	}

	return &globalRoles, nil
}

//FindOrganizationRoles finds a set of organization user roles
func (sa *Adapter) FindOrganizationRoles(ids *[]string, orgID string, context mongo.SessionContext) (*[]model.OrganizationRole, error) {
	rolesFilter := bson.D{primitive.E{Key: "organization_id", Value: orgID}, primitive.E{Key: "_id", Value: bson.M{"$in": *ids}}}
	var rolesResult []role
	var err error
	if context == nil {
		err = sa.db.roles.Find(rolesFilter, &rolesResult, nil)
	} else {
		err = sa.db.roles.FindWithContext(context, rolesFilter, &rolesResult, nil)
	}
	if err != nil {
		return nil, err
	}

	orgRoles := []model.OrganizationRole{}
	for _, role := range rolesResult {
		orgRole := model.OrganizationRole{ID: role.ID, Name: role.Name, Description: role.Description}

		permissions, err := sa.FindOrganizationPermissions(&role.Permissions, orgID, context)
		if err != nil {
			fmt.Printf("failed to find organization permissions for role ID %s, org_id %s\n", role.ID, orgID)
		} else {
			orgRole.Permissions = *permissions
		}
		org, err := sa.getOrganization(orgID)
		if err != nil {
			fmt.Printf("failed to find cached organization for org_id %s\n", orgID)
		} else {
			orgRole.Organization = *org
		}

		orgRoles = append(orgRoles, orgRole)
	}

	return &orgRoles, nil
}

//FindGlobalGroups finds a set of global user groups
func (sa *Adapter) FindGlobalGroups(ids *[]string, context mongo.SessionContext) (*[]model.GlobalGroup, error) {
	filter := bson.D{primitive.E{Key: "_id", Value: bson.M{"$in": *ids}}}
	var groupsResult []group
	var err error
	if context == nil {
		err = sa.db.groups.Find(filter, &groupsResult, nil)
	} else {
		err = sa.db.groups.FindWithContext(context, filter, &groupsResult, nil)
	}
	if err != nil {
		return nil, err
	}

	globalGroups := []model.GlobalGroup{}
	for _, group := range groupsResult {
		globalGroup := model.GlobalGroup{ID: group.ID, Name: group.Name}

		permissions, err := sa.FindGlobalPermissions(&group.Permissions, context)
		if err != nil {
			fmt.Printf("failed to find global permissions for group ID %s\n", group.ID)
		} else {
			globalGroup.Permissions = *permissions
		}
		roles, err := sa.FindGlobalRoles(&group.Roles, context)
		if err != nil {
			fmt.Printf("failed to find global roles for group ID %s\n", group.ID)
		} else {
			globalGroup.Roles = *roles
		}

		globalGroups = append(globalGroups, globalGroup)
	}

	return &globalGroups, nil
}

//FindOrganizationGroups finds a set of organization user groups
func (sa *Adapter) FindOrganizationGroups(ids *[]string, orgID string, context mongo.SessionContext) (*[]model.OrganizationGroup, error) {
	filter := bson.D{primitive.E{Key: "organization_id", Value: orgID}, primitive.E{Key: "_id", Value: bson.M{"$in": *ids}}}
	var groupsResult []group
	var err error
	if context == nil {
		err = sa.db.groups.Find(filter, &groupsResult, nil)
	} else {
		err = sa.db.groups.FindWithContext(context, filter, &groupsResult, nil)
	}
	if err != nil {
		return nil, err
	}

	orgGroups := []model.OrganizationGroup{}
	for _, group := range groupsResult {
		orgGroup := model.OrganizationGroup{ID: group.ID, Name: group.Name}

		permissions, err := sa.FindOrganizationPermissions(&group.Permissions, orgID, context)
		if err != nil {
			fmt.Printf("failed to find organization permissions for group ID %s, org_id %s\n", group.ID, orgID)
		} else {
			orgGroup.Permissions = *permissions
		}
		roles, err := sa.FindOrganizationRoles(&group.Roles, orgID, context)
		if err != nil {
			fmt.Printf("failed to find organization roles for group ID %s, org_id %s\n", group.ID, orgID)
		} else {
			orgGroup.Roles = *roles
		}
		org, err := sa.getOrganization(orgID)
		if err != nil {
			fmt.Printf("failed to find cached organization for org_id %s\n", orgID)
		} else {
			orgGroup.Organization = *org
		}

		orgGroups = append(orgGroups, orgGroup)
	}

	return &orgGroups, nil
}

//InsertMembership inserts an organization membership
func (sa *Adapter) InsertMembership(orgMembership *rawMembership, context mongo.SessionContext) error {
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

//GetApplication gets application
func (sa *Adapter) GetApplication(ID string) (*model.Application, error) {
	filter := bson.D{primitive.E{Key: "_id", Value: ID}}
	var result []application
	err := sa.db.applications.Find(filter, &result, nil)
	if err != nil {
		return nil, log.WrapActionError(log.ActionFind, model.TypeApplication, nil, err)
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

type storageListener struct {
	adapter *Adapter
	DefaultListenerImpl
}

func (sl *storageListener) OnOrganizationsUpdated() {
	sl.adapter.cacheOrganizations()
}

//Listener represents storage listener
type Listener interface {
	OnAuthConfigUpdated()
	OnServiceRegsUpdated()
	OnOrganizationsUpdated()
}

//DefaultListenerImpl default listener implementation
type DefaultListenerImpl struct{}

//OnAuthConfigUpdated notifies auth configs have been updated
func (d *DefaultListenerImpl) OnAuthConfigUpdated() {}

//OnServiceRegsUpdated notifies services regs have been updated
func (d *DefaultListenerImpl) OnServiceRegsUpdated() {}

//OnOrganizationsUpdated notifies organizations have been updated
func (d *DefaultListenerImpl) OnOrganizationsUpdated() {}
