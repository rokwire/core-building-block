package storage

import (
	"context"
	"log"
	"time"

	"github.com/rokmetro/logging-library/logs"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type database struct {
	mongoDBAuth  string
	mongoDBName  string
	mongoTimeout time.Duration

	logger *logs.Logger

	db       *mongo.Database
	dbClient *mongo.Client

	users                    *collectionWrapper
	devices                  *collectionWrapper
	credentials              *collectionWrapper
	globalConfig             *collectionWrapper
	globalGroups             *collectionWrapper
	globalRoles              *collectionWrapper
	globalPermissions        *collectionWrapper
	organizations            *collectionWrapper
	organizationsGroups      *collectionWrapper
	organizationsRoles       *collectionWrapper
	organizationsPermissions *collectionWrapper
	organizationsMemberships *collectionWrapper
	authConfigs              *collectionWrapper
	serviceRegs              *collectionWrapper
	serviceAuthorizations    *collectionWrapper
	applications             *collectionWrapper

	listeners []Listener
}

func (m *database) start() error {
	m.logger.Info("database -> start")

	//connect to the database
	clientOptions := options.Client().ApplyURI(m.mongoDBAuth)
	connectContext, cancel := context.WithTimeout(context.Background(), m.mongoTimeout)
	client, err := mongo.Connect(connectContext, clientOptions)
	cancel()
	if err != nil {
		return err
	}

	//ping the database
	pingContext, cancel := context.WithTimeout(context.Background(), m.mongoTimeout)
	err = client.Ping(pingContext, nil)
	cancel()
	if err != nil {
		return err
	}

	//apply checks
	db := client.Database(m.mongoDBName)

	users := &collectionWrapper{database: m, coll: db.Collection("users")}
	err = m.applyUsersChecks(users)
	if err != nil {
		return err
	}

	devices := &collectionWrapper{database: m, coll: db.Collection("devices")}
	err = m.applyDevicesChecks(devices)
	if err != nil {
		return err
	}

	credentials := &collectionWrapper{database: m, coll: db.Collection("credentials")}
	err = m.applyCredentialChecks(credentials)
	if err != nil {
		return err
	}

	globalConfig := &collectionWrapper{database: m, coll: db.Collection("global_config")}
	err = m.applyGlobalConfigChecks(globalConfig)
	if err != nil {
		return err
	}

	globalGroups := &collectionWrapper{database: m, coll: db.Collection("global_groups")}
	err = m.applyGlobalGroupsChecks(globalGroups)
	if err != nil {
		return err
	}

	globalRoles := &collectionWrapper{database: m, coll: db.Collection("global_roles")}
	err = m.applyGlobalRolesChecks(globalRoles)
	if err != nil {
		return err
	}

	globalPermissions := &collectionWrapper{database: m, coll: db.Collection("global_permissions")}
	err = m.applyGlobalPermissionsChecks(globalPermissions)
	if err != nil {
		return err
	}

	organizations := &collectionWrapper{database: m, coll: db.Collection("organizations")}
	err = m.applyOrganizationsChecks(organizations)
	if err != nil {
		return err
	}

	organizationsGroups := &collectionWrapper{database: m, coll: db.Collection("organizations_groups")}
	err = m.applyOrganizationsGroupsChecks(organizationsGroups)
	if err != nil {
		return err
	}

	organizationsRoles := &collectionWrapper{database: m, coll: db.Collection("organizations_roles")}
	err = m.applyOrganizationsRolesChecks(organizationsRoles)
	if err != nil {
		return err
	}
	organizationsPermissions := &collectionWrapper{database: m, coll: db.Collection("organizations_permissions")}
	err = m.applyOrganizationsPermissionsChecks(organizationsPermissions)
	if err != nil {
		return err
	}

	organizationsMemberships := &collectionWrapper{database: m, coll: db.Collection("organizations_memberships")}
	err = m.applyOrganizationsMembershipsChecks(organizationsMemberships)
	if err != nil {
		return err
	}

	authConfigs := &collectionWrapper{database: m, coll: db.Collection("auth_configs")}
	err = m.applyAuthConfigChecks(authConfigs)
	if err != nil {
		return err
	}

	serviceRegs := &collectionWrapper{database: m, coll: db.Collection("service_regs")}
	err = m.applyServiceRegsChecks(serviceRegs)
	if err != nil {
		return err
	}

	serviceAuthorizations := &collectionWrapper{database: m, coll: db.Collection("service_authorizations")}
	err = m.applyServiceAuthorizationsChecks(serviceAuthorizations)
	if err != nil {
		return err
	}

	applications := &collectionWrapper{database: m, coll: db.Collection("applications")}
	err = m.applyApplicationsChecks(applications)
	if err != nil {
		return err
	}

	//asign the db, db client and the collections
	m.db = db
	m.dbClient = client

	m.users = users
	m.devices = devices
	m.credentials = credentials
	m.globalConfig = globalConfig
	m.globalGroups = globalGroups
	m.globalRoles = globalRoles
	m.globalPermissions = globalPermissions
	m.organizations = organizations
	m.organizationsGroups = organizationsGroups
	m.organizationsRoles = organizationsRoles
	m.organizationsPermissions = organizationsPermissions
	m.organizationsMemberships = organizationsMemberships
	m.authConfigs = authConfigs
	m.serviceRegs = serviceRegs
	m.serviceAuthorizations = serviceAuthorizations
	m.applications = applications

	go m.authConfigs.Watch(nil)
	go m.serviceRegs.Watch(nil)
	go m.organizations.Watch(nil)
	go m.applications.Watch(nil)

	m.listeners = []Listener{}

	return nil
}

func (m *database) applyUsersChecks(users *collectionWrapper) error {
	m.logger.Info("apply users checks.....")

	//add account index
	err := users.AddIndex(bson.D{primitive.E{Key: "account.id", Value: 1}}, false)
	if err != nil {
		return err
	}

	//add profile index
	err = users.AddIndex(bson.D{primitive.E{Key: "profile.id", Value: 1}}, false)
	if err != nil {
		return err
	}

	//add permissions index
	err = users.AddIndex(bson.D{primitive.E{Key: "permissions._id", Value: 1}}, false)
	if err != nil {
		return err
	}

	//add roles index
	err = users.AddIndex(bson.D{primitive.E{Key: "roles._id", Value: 1}}, false)
	if err != nil {
		return err
	}

	//add roles permissions index
	err = users.AddIndex(bson.D{primitive.E{Key: "roles.permissions._id", Value: 1}}, false)
	if err != nil {
		return err
	}

	//add groups index
	err = users.AddIndex(bson.D{primitive.E{Key: "groups._id", Value: 1}}, false)
	if err != nil {
		return err
	}

	//add groups permissions index
	err = users.AddIndex(bson.D{primitive.E{Key: "groups.permissions._id", Value: 1}}, false)
	if err != nil {
		return err
	}

	//add groups roles index
	err = users.AddIndex(bson.D{primitive.E{Key: "groups.roles._id", Value: 1}}, false)
	if err != nil {
		return err
	}

	//add groups roles permissions index
	err = users.AddIndex(bson.D{primitive.E{Key: "groups.roles.permissions._id", Value: 1}}, false)
	if err != nil {
		return err
	}

	//add organizations memberships index
	err = users.AddIndex(bson.D{primitive.E{Key: "organizations_memberships._id", Value: 1}}, false)
	if err != nil {
		return err
	}

	//add organizations memberships permissions index
	err = users.AddIndex(bson.D{primitive.E{Key: "organizations_memberships.permissions._id", Value: 1}}, false)
	if err != nil {
		return err
	}

	//add organizations memberships roles index
	err = users.AddIndex(bson.D{primitive.E{Key: "organizations_memberships.roles._id", Value: 1}}, false)
	if err != nil {
		return err
	}

	//add organizations memberships roles permissions index
	err = users.AddIndex(bson.D{primitive.E{Key: "organizations_memberships.roles.permissions_id", Value: 1}}, false)
	if err != nil {
		return err
	}

	//add organizations memberships groups index
	err = users.AddIndex(bson.D{primitive.E{Key: "organizations_memberships.groups._id", Value: 1}}, false)
	if err != nil {
		return err
	}

	//add organizations memberships groups permissions index
	err = users.AddIndex(bson.D{primitive.E{Key: "organizations_memberships.groups.permissions._id", Value: 1}}, false)
	if err != nil {
		return err
	}

	//add organizations memberships groups roles index
	err = users.AddIndex(bson.D{primitive.E{Key: "organizations_memberships.groups.roles._id", Value: 1}}, false)
	if err != nil {
		return err
	}

	//add organizations memberships groups roles permissions index
	err = users.AddIndex(bson.D{primitive.E{Key: "organizations_memberships.groups.roles.permissions._id", Value: 1}}, false)
	if err != nil {
		return err
	}

	//add devices index
	err = users.AddIndex(bson.D{primitive.E{Key: "devices._id", Value: 1}}, false)
	if err != nil {
		return err
	}

	m.logger.Info("users check passed")
	return nil
}

func (m *database) applyGlobalGroupsChecks(groups *collectionWrapper) error {
	m.logger.Info("apply global groups checks.....")

	//add permissions index
	err := groups.AddIndex(bson.D{primitive.E{Key: "permissions._id", Value: 1}}, false)
	if err != nil {
		return err
	}

	//add roles index
	err = groups.AddIndex(bson.D{primitive.E{Key: "roles._id", Value: 1}}, false)
	if err != nil {
		return err
	}

	//add roles permissions index
	err = groups.AddIndex(bson.D{primitive.E{Key: "roles.permissions._id", Value: 1}}, false)
	if err != nil {
		return err
	}

	m.logger.Info("global groups check passed")
	return nil
}

func (m *database) applyGlobalRolesChecks(roles *collectionWrapper) error {
	m.logger.Info("apply global roles checks.....")

	//add permissions index
	err := roles.AddIndex(bson.D{primitive.E{Key: "permissions._id", Value: 1}}, false)
	if err != nil {
		return err
	}

	m.logger.Info("global roles check passed")
	return nil
}

func (m *database) applyGlobalPermissionsChecks(permissions *collectionWrapper) error {
	m.logger.Info("apply global permissions checks.....")

	m.logger.Info("global permissions check passed")
	return nil
}

func (m *database) applyOrganizationsMembershipsChecks(organizationsMemberships *collectionWrapper) error {
	m.logger.Info("apply organizations memberships checks.....")

	//add user id index
	err := organizationsMemberships.AddIndex(bson.D{primitive.E{Key: "user_id", Value: 1}}, false)
	if err != nil {
		return err
	}

	//add organization id index
	err = organizationsMemberships.AddIndex(bson.D{primitive.E{Key: "organization_id", Value: 1}}, false)
	if err != nil {
		return err
	}

	m.logger.Info("organizations memberships check passed")
	return nil
}

func (m *database) applyDevicesChecks(devices *collectionWrapper) error {
	m.logger.Info("apply devices checks.....")

	//add users index
	err := devices.AddIndex(bson.D{primitive.E{Key: "users", Value: 1}}, false)
	if err != nil {
		return err
	}

	m.logger.Info("devices check passed")
	return nil
}

func (m *database) applyCredentialChecks(credentials *collectionWrapper) error {
	m.logger.Info("apply credentials checks.....")

	// Add org_id, app_id compound index
	err := credentials.AddIndex(bson.D{primitive.E{Key: "org_id", Value: 1}, primitive.E{Key: "app_id", Value: 1}}, false)
	if err != nil {
		return err
	}

	err = credentials.AddIndex(bson.D{primitive.E{Key: "type", Value: 1}, primitive.E{Key: "user_id", Value: 1}}, false)
	if err != nil {
		return err
	}
	m.logger.Info("credentials check passed")
	return nil
}

func (m *database) applyAuthConfigChecks(authInfo *collectionWrapper) error {
	m.logger.Info("apply auth info checks.....")

	// Add org_id, app_id compound index
	err := authInfo.AddIndex(bson.D{primitive.E{Key: "org_id", Value: 1}, primitive.E{Key: "app_id", Value: 1}}, false)
	if err != nil {
		return err
	}
	m.logger.Info("auth info check passed")
	return nil
}

func (m *database) applyGlobalConfigChecks(configs *collectionWrapper) error {
	m.logger.Info("apply global config checks.....")

	m.logger.Info("global config checks passed")
	return nil
}

func (m *database) applyOrganizationsChecks(organizations *collectionWrapper) error {
	m.logger.Info("apply organizations checks.....")

	//add name index - unique
	err := organizations.AddIndex(bson.D{primitive.E{Key: "name", Value: 1}}, true)
	if err != nil {
		return err
	}

	//add applications index
	err = organizations.AddIndex(bson.D{primitive.E{Key: "applications", Value: 1}}, false)
	if err != nil {
		return err
	}

	m.logger.Info("organizations checks passed")
	return nil
}

func (m *database) applyOrganizationsGroupsChecks(organizationsGroups *collectionWrapper) error {
	m.logger.Info("apply organizations groups checks.....")

	//add organization index
	err := organizationsGroups.AddIndex(bson.D{primitive.E{Key: "organization_id", Value: 1}}, false)
	if err != nil {
		return err
	}

	//add permissions index
	err = organizationsGroups.AddIndex(bson.D{primitive.E{Key: "permissions._id", Value: 1}}, false)
	if err != nil {
		return err
	}

	//add roles index
	err = organizationsGroups.AddIndex(bson.D{primitive.E{Key: "roles._id", Value: 1}}, false)
	if err != nil {
		return err
	}

	//add roles permissions index
	err = organizationsGroups.AddIndex(bson.D{primitive.E{Key: "roles.permissions._id", Value: 1}}, false)
	if err != nil {
		return err
	}

	m.logger.Info("organizations groups checks passed")
	return nil
}

func (m *database) applyOrganizationsRolesChecks(organizationsRoles *collectionWrapper) error {
	m.logger.Info("apply organizations roles checks.....")

	//add organization index
	err := organizationsRoles.AddIndex(bson.D{primitive.E{Key: "organization_id", Value: 1}}, false)
	if err != nil {
		return err
	}

	//add permissions index
	err = organizationsRoles.AddIndex(bson.D{primitive.E{Key: "permissions._id", Value: 1}}, false)
	if err != nil {
		return err
	}

	m.logger.Info("organizations roles checks passed")
	return nil
}

func (m *database) applyOrganizationsPermissionsChecks(organizationsPermissions *collectionWrapper) error {
	m.logger.Info("apply organizations permissions checks.....")

	//add organization index
	err := organizationsPermissions.AddIndex(bson.D{primitive.E{Key: "organization_id", Value: 1}}, false)
	if err != nil {
		return err
	}

	m.logger.Info("organizations permissions checks passed")
	return nil
}

func (m *database) applyServiceRegsChecks(serviceRegs *collectionWrapper) error {
	m.logger.Info("apply service regs checks.....")

	//add service_id index - unique
	err := serviceRegs.AddIndex(bson.D{primitive.E{Key: "registration.service_id", Value: 1}}, true)
	if err != nil {
		return err
	}

	m.logger.Info("service regs checks passed")
	return nil
}
func (m *database) applyApplicationsChecks(applications *collectionWrapper) error {
	log.Println("apply applications checks.....")

	//add name index - unique
	err := applications.AddIndex(bson.D{primitive.E{Key: "_id", Value: 1}}, true)
	if err != nil {
		return err
	}

	log.Println("applications checks passed")
	return nil
}

func (m *database) applyServiceAuthorizationsChecks(serviceAuthorizations *collectionWrapper) error {
	m.logger.Info("apply service authorizations checks.....")

	//add user_id, service_id index - unique
	err := serviceAuthorizations.AddIndex(bson.D{primitive.E{Key: "user_id", Value: 1}, primitive.E{Key: "service_id", Value: 1}}, true)
	if err != nil {
		return err
	}

	m.logger.Info("service authorizations checks passed")
	return nil
}

func (m *database) onDataChanged(changeDoc map[string]interface{}) {
	if changeDoc == nil {
		return
	}
	m.logger.Debugf("onDataChanged: %+v\n", changeDoc)
	ns := changeDoc["ns"]
	if ns == nil {
		return
	}
	nsMap := ns.(map[string]interface{})
	coll := nsMap["coll"]

	switch coll {
	case "auth_configs":
		m.logger.Info("auth_configs collection changed")

		for _, listener := range m.listeners {
			go listener.OnAuthConfigUpdated()
		}
	case "service_regs":
		m.logger.Info("service_regs collection changed")

		for _, listener := range m.listeners {
			go listener.OnServiceRegsUpdated()
		}
	case "organizations":
		m.logger.Info("organizations collection changed")

		for _, listener := range m.listeners {
			go listener.OnOrganizationsUpdated()
		}
	case "applications":
		m.logger.Info("applications collection changed")

		for _, listener := range m.listeners {
			go listener.OnApplicationsUpdated()
		}
	}

}
