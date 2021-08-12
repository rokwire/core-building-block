package main

import (
	"core-building-block/core"
	"core-building-block/core/auth"
	"core-building-block/driven/storage"
	"core-building-block/driver/web"
	"io/ioutil"
	"strconv"

	"github.com/golang-jwt/jwt"

	"github.com/rokmetro/auth-library/envloader"
	"github.com/rokmetro/logging-library/logs"
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
	loggerOpts := logs.LoggerOpts{SuppressRequests: []logs.HttpRequestProperties{logs.NewAwsHealthCheckHttpRequestProperties("")}}
	logger := logs.NewLogger("core", &loggerOpts)
	envLoader := envloader.NewEnvLoader(Version, logger)

	level := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_LOG_LEVEL", false, false)
	logLevel := logs.LogLevelFromString(level)
	if logLevel != nil {
		logger.SetLevel(*logLevel)
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
	err := storageAdapter.Start()
	if err != nil {
		logger.Fatalf("Cannot start the mongoDB adapter: %v", err)
	}

	//auth
	var authPrivKeyPem []byte
	authPrivKeyPemString := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_AUTH_PRIV_KEY", false, true)
	if authPrivKeyPemString != "" {
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

	auth, err := auth.NewAuth(serviceID, host, authPrivKey, storageAdapter, minTokenExp, maxTokenExp, logger)
	if err != nil {
		logger.Fatalf("Error initializing auth: %v", err)
	}
	//core
	coreAPIs := core.NewCoreAPIs(env, Version, Build, storageAdapter, auth)
	coreAPIs.Start()

	//web adapter
	webAdapter := web.NewWebAdapter(env, serviceID, auth.AuthService, port, coreAPIs, host, logger)
	webAdapter.Start()
}
