package main

import (
	"core-building-block/core"
	"core-building-block/core/auth"
	"core-building-block/driven/storage"
	"core-building-block/driver/web"
	"log"
	"os"
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

	//mongoDB adapter
	mongoDBAuth := getEnvKey("ROKWIRE_CORE_MONGO_AUTH", true)
	mongoDBName := getEnvKey("ROKWIRE_CORE_MONGO_DATABASE", true)
	mongoTimeout := getEnvKey("ROKWIRE_CORE_MONGO_TIMEOUT", false)
	storageAdapter := storage.NewStorageAdapter(mongoDBAuth, mongoDBName, mongoTimeout)
	err := storageAdapter.Start()
	if err != nil {
		log.Fatal("Cannot start the mongoDB adapter - " + err.Error())
	}

	//auth
	auth := auth.NewAuth(storageAdapter)

	//application
	application := core.NewApplication(Version, Build, storageAdapter, auth)
	application.Start()

	//web adapter
	host := getEnvKey("ROKWIRE_CORE_HOST", true)
	webAdapter := web.NewWebAdapter(application, host)

	webAdapter.Start()
}

func getEnvKey(key string, required bool) string {
	//get from the environment
	value, exist := os.LookupEnv(key)
	if !exist {
		if required {
			log.Fatal("No provided environment variable for " + key)
		} else {
			log.Printf("No provided environment variable for " + key)
		}
	}
	printEnvVar(key, value)
	return value
}

func printEnvVar(name string, value string) {
	if Version == "dev" {
		log.Printf("%s=%s", name, value)
	}
}
