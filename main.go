package main

import (
	"core-building-block/core"
	"core-building-block/core/auth"
	"core-building-block/driven/storage"
	"core-building-block/driver/web"
	"strconv"

	"github.com/golang-jwt/jwt"
	"github.com/rokmetro/auth-library/envloader"
	log "github.com/rokmetro/logging-library/loglib"
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
	logger := log.NewLogger("core")
	envLoader := envloader.NewEnvLoader(Version, logger)

	env := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_ENVIRONMENT", true, false) //local, dev, staging, prod
	serviceID := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_SERVICE_ID", true, false)
	host := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_HOST", true, false)

	// mongoDB adapter
	mongoDBAuth := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_MONGO_AUTH", true, false)
	mongoDBName := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_MONGO_DATABASE", true, false)
	mongoTimeout := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_MONGO_TIMEOUT", false, false)
	storageAdapter := storage.NewStorageAdapter(mongoDBAuth, mongoDBName, mongoTimeout, logger)
	err := storageAdapter.Start()
	if err != nil {
		logger.Fatal("Cannot start the mongoDB adapter - " + err.Error())
	}

	//auth
	authPrivKeyPem := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_AUTH_PRIV_KEY", true, true)
	authPrivKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(authPrivKeyPem))
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

	auth, err := auth.NewAuth(serviceID, host, authPrivKey, storageAdapter, minTokenExp, maxTokenExp)
	if err != nil {
		logger.Fatalf("Error initializing auth: %v", err)
	}

	//core
	coreAPIs := core.NewCoreAPIs(env, Version, Build, storageAdapter, auth)
	coreAPIs.Start()

	//web adapter
	webAdapter := web.NewWebAdapter(env, coreAPIs, host, logger)
	webAdapter.Start()
}
