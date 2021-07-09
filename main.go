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

	serviceID := envLoader.GetEnvVar("SERVICE_ID", true)
	host := envLoader.GetEnvVar("ROKWIRE_CORE_HOST", true)

	// mongoDB adapter
	mongoDBAuth := envLoader.GetEnvVar("ROKWIRE_CORE_MONGO_AUTH", true)
	mongoDBName := envLoader.GetEnvVar("ROKWIRE_CORE_MONGO_DATABASE", true)
	mongoTimeout := envLoader.GetEnvVar("ROKWIRE_CORE_MONGO_TIMEOUT", false)
	storageAdapter := storage.NewStorageAdapter(mongoDBAuth, mongoDBName, mongoTimeout, logger)
	err := storageAdapter.Start()
	if err != nil {
		logger.Fatal("Cannot start the mongoDB adapter - " + err.Error())
	}

	//auth
	authPrivKeyPem := envLoader.GetEnvVar("AUTH_PRIV_KEY", true)
	authPrivKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(authPrivKeyPem))
	if err != nil {
		logger.Fatalf("Failed to parse auth priv key: %v", err)
	}

	minTokenExpStr := envLoader.GetEnvVar("MIN_TOKEN_EXP", false)
	minTokenExp, err := strconv.ParseInt(minTokenExpStr, 10, 64)
	if err != nil {
		logger.Fatalf("Error parsing min token exp: %v", err)
	}

	maxTokenExpStr := envLoader.GetEnvVar("MAX_TOKEN_EXP", false)
	maxTokenExp, err := strconv.ParseInt(maxTokenExpStr, 10, 64)
	if err != nil {
		logger.Fatalf("Error parsing max token exp: %v", err)
	}

	auth, err := auth.NewAuth(serviceID, host, authPrivKey, storageAdapter, minTokenExp, maxTokenExp)
	if err != nil {
		logger.Fatalf("Error initializing auth: %v", err)
	}

	//application
	application := core.NewApplication(Version, Build, storageAdapter, auth)
	application.Start()

	//web adapter
	webAdapter := web.NewWebAdapter(application, host, logger)

	webAdapter.Start()
}
