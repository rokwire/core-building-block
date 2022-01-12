package main

import (
	"core-building-block/core"
	"core-building-block/core/auth"
	"core-building-block/driven/emailer"
	"core-building-block/driven/profilebb"
	"core-building-block/driven/storage"
	"core-building-block/driver/web"
	"core-building-block/utils"
	"io/ioutil"
	"strconv"
	"strings"

	"github.com/golang-jwt/jwt"

	"github.com/rokwire/core-auth-library-go/envloader"
	"github.com/rokwire/logging-library-go/logs"
)

var (
	// Version : version of this executable
	Version string
	// Build : build date of this executable
	Build string
)

func main() {
	if len(Version) == 0 {
		Version = "dev"
	}
	loggerOpts := logs.LoggerOpts{SuppressRequests: []logs.HttpRequestProperties{logs.NewAwsHealthCheckHttpRequestProperties("/core/version")}}
	logger := logs.NewLogger("core", &loggerOpts)
	envLoader := envloader.NewEnvLoader(Version, logger)

	level := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_LOG_LEVEL", false, false)
	logLevel := logs.LogLevelFromString(level)
	if logLevel != nil {
		logger.SetLevel(*logLevel)
	}

	err := utils.SetRandomSeed()
	if err != nil {
		logger.Error(err.Error())
	}

	env := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_ENVIRONMENT", true, false) //local, dev, staging, prod
	port := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_PORT", false, false)
	//Default port of 80
	if port == "" {
		port = "80"
	}

	serviceID := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_SERVICE_ID", true, false)
	host := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_HOST", true, false)

	// mongoDB adapter
	mongoDBAuth := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_MONGO_AUTH", true, false)
	mongoDBName := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_MONGO_DATABASE", true, false)
	mongoTimeout := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_MONGO_TIMEOUT", false, false)
	storageAdapter := storage.NewStorageAdapter(mongoDBAuth, mongoDBName, mongoTimeout, logger)
	err = storageAdapter.Start()
	if err != nil {
		logger.Fatalf("Cannot start the mongoDB adapter: %v", err)
	}

	//auth
	twilioAccountSID := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_AUTH_TWILIO_ACCOUNT_SID", false, true)
	twilioToken := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_AUTH_TWILIO_TOKEN", false, true)
	twilioServiceSID := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_AUTH_TWILIO_SERVICE_SID", false, true)

	smtpHost := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_SMTP_HOST", false, false)
	smtpPort := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_SMTP_PORT", false, false)
	smtpUser := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_SMTP_USER", false, true)
	smtpPassword := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_SMTP_PASSWORD", false, true)
	smtpFrom := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_SMTP_EMAIL_FROM", false, false)
	smtpPortNum, _ := strconv.Atoi(smtpPort)

	emailer := emailer.NewEmailerAdapter(smtpHost, smtpPortNum, smtpUser, smtpPassword, smtpFrom)

	var authPrivKeyPem []byte
	authPrivKeyPemString := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_AUTH_PRIV_KEY", false, true)
	if authPrivKeyPemString != "" {

		//make it to be a single line - AWS environemnt variable issue
		authPrivKeyPemString = strings.Replace(authPrivKeyPemString, `\n`, "\n", -1)

		authPrivKeyPem = []byte(authPrivKeyPemString)
	} else {
		authPrivateKeyPath := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_AUTH_PRIV_KEY_PATH", true, false)
		authPrivKeyPem, err = ioutil.ReadFile(authPrivateKeyPath)
		if err != nil {
			logger.Fatalf("Could not find auth priv key file: %v", err)
		}
	}
	authPrivKey, err := jwt.ParseRSAPrivateKeyFromPEM(authPrivKeyPem)
	if err != nil {
		logger.Fatalf("Failed to parse auth priv key: %v", err)
	}

	minTokenExpStr := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_MIN_TOKEN_EXP", false, false)
	var minTokenExp *int64
	minTokenExpVal, err := strconv.ParseInt(minTokenExpStr, 10, 64)
	if err == nil {
		minTokenExp = &minTokenExpVal
	} else {
		logger.Infof("Error parsing min token exp, applying defaults: %v", err)
	}

	maxTokenExpStr := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_MAX_TOKEN_EXP", false, false)
	var maxTokenExp *int64
	maxTokenExpVal, err := strconv.ParseInt(maxTokenExpStr, 10, 64)
	if err == nil {
		maxTokenExp = &maxTokenExpVal
	} else {
		logger.Infof("Error parsing max token exp, applying defaults: %v", err)
	}

	//profile bb adapter
	migrateProfiles := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_MIGRATE_PROFILES", false, false)
	migrate, err := strconv.ParseBool(migrateProfiles)
	if err != nil {
		logger.Infof("Error parsing migrate profiles flag, applying defaults: %v", err)
		migrate = true
	}
	profileBBHost := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_PROFILE_BB_HOST", false, false)
	profileBBApiKey := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_PROFILE_BB_API_KEY", false, true)
	profileBBAdapter := profilebb.NewProfileBBAdapter(migrate, profileBBHost, profileBBApiKey)

	auth, err := auth.NewAuth(serviceID, host, authPrivKey, storageAdapter, emailer, minTokenExp, maxTokenExp, twilioAccountSID, twilioToken, twilioServiceSID, profileBBAdapter, smtpHost, smtpPortNum, smtpUser, smtpPassword, smtpFrom, logger)
	if err != nil {
		logger.Fatalf("Error initializing auth: %v", err)
	}

	systemAdminAppID := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_SYSTEM_ADMIN_APP_ID", true, true)
	systemOrgID := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_SYSTEM_ORG_ID", true, true)

	//core
	coreAPIs := core.NewCoreAPIs(env, Version, Build, storageAdapter, auth, systemAdminAppID, systemOrgID)
	coreAPIs.Start()

	//web adapter
	webAdapter := web.NewWebAdapter(env, serviceID, auth.AuthService, port, coreAPIs, host, logger)
	webAdapter.Start()
}
