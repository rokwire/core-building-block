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
	logger := log.NewLogger("core", nil)
	envLoader := envloader.NewEnvLoader(Version, logger)

	level := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_LOG_LEVEL", false, false)
	logLevel := log.LogLevelFromString(level)
	if logLevel != nil {
		logger.SetLevel(*logLevel)
	}

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
		logger.Fatalf("Cannot start the mongoDB adapter: %v", err)
	}

	//auth
	//authPrivKeyPem := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_AUTH_PRIV_KEY", true, true)
	authPrivKeyPem := "-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKBgQCjcGqTkOq0CR3rTx0ZSQSIdTrDrFAYl29611xN8aVgMQIWtDB/\nlD0W5TpKPuU9iaiG/sSn/VYt6EzN7Sr332jj7cyl2WrrHI6ujRswNy4HojMuqtfa\nb5FFDpRmCuvl35fge18OvoQTJELhhJ1EvJ5KUeZiuJ3u3YyMnxxXzLuKbQIDAQAB\nAoGAPrNDz7TKtaLBvaIuMaMXgBopHyQd3jFKbT/tg2Fu5kYm3PrnmCoQfZYXFKCo\nZUFIS/G1FBVWWGpD/MQ9tbYZkKpwuH+t2rGndMnLXiTC296/s9uix7gsjnT4Naci\n5N6EN9pVUBwQmGrYUTHFc58ThtelSiPARX7LSU2ibtJSv8ECQQDWBRrrAYmbCUN7\nra0DFT6SppaDtvvuKtb+mUeKbg0B8U4y4wCIK5GH8EyQSwUWcXnNBO05rlUPbifs\nDLv/u82lAkEAw39sTJ0KmJJyaChqvqAJ8guulKlgucQJ0Et9ppZyet9iVwNKX/aW\n9UlwGBMQdafQ36nd1QMEA8AbAw4D+hw/KQJBANJbHDUGQtk2hrSmZNoV5HXB9Uiq\n7v4N71k5ER8XwgM5yVGs2tX8dMM3RhnBEtQXXs9LW1uJZSOQcv7JGXNnhN0CQBZe\nnzrJAWxh3XtznHtBfsHWelyCYRIAj4rpCHCmaGUM6IjCVKFUawOYKp5mmAyObkUZ\nf8ue87emJLEdynC1CLkCQHduNjP1hemAGWrd6v8BHhE3kKtcK6KHsPvJR5dOfzbd\nHAqVePERhISfN6cwZt5p8B3/JUwSR8el66DF7Jm57BM=\n-----END RSA PRIVATE KEY-----"
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

	auth, err := auth.NewAuth(serviceID, host, authPrivKey, storageAdapter, minTokenExp, maxTokenExp, logger)
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
