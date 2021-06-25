package main

import (
	"core-building-block/core"
	"core-building-block/driven/storage"
	"core-building-block/driver/web"

	"os"

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
	var logger = log.NewLogger("core-building-block")

	// mongoDB adapter
	mongoDBAuth := getEnvKey(logger, "ROKWIRE_CORE_MONGO_AUTH", true)
	mongoDBName := getEnvKey(logger, "ROKWIRE_CORE_MONGO_DATABASE", true)
	mongoTimeout := getEnvKey(logger, "ROKWIRE_CORE_MONGO_TIMEOUT", false)
	storageAdapter := storage.NewStorageAdapter(mongoDBAuth, mongoDBName, mongoTimeout, logger)
	err := storageAdapter.Start()
	if err != nil {
		logger.Fatal("Cannot start the mongoDB adapter - " + err.Error())
	}

	//TODO - crash
	//auth
	//auth := auth.NewAuth(storageAdapter)

	//application
	application := core.NewApplication(Version, Build, storageAdapter, nil)
	application.Start()

	//web adapter
	host := getEnvKey(logger, "ROKWIRE_CORE_HOST", true)
	webAdapter := web.NewWebAdapter(application, host, logger)

	webAdapter.Start()
}

func getEnvKey(logger *log.StandardLogger, key string, required bool) string {
	//get from the environment
	value, exist := os.LookupEnv(key)
	if !exist {
		if required {
			logger.Fatal("No provided environment variable for " + key)
		} else {
			logger.Error("No provided environment variable for " + key)
		}
	}
	printEnvVar(logger, key, value)
	return value
}

func printEnvVar(logger *log.StandardLogger, name string, value string) {
	if Version == "dev" {
		logger.InfoWithFields("ENV_VAR", map[string]interface{}{"name": name, "value": value})
	}
}
