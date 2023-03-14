// Copyright 2022 Board of Trustees of the University of Illinois.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"core-building-block/core"
	"core-building-block/core/auth"
	"core-building-block/driven/emailer"
	"core-building-block/driven/profilebb"
	"core-building-block/driven/storage"
	"core-building-block/driver/web"
	"core-building-block/utils"
	"os"
	"strconv"
	"strings"

	"github.com/rokwire/core-auth-library-go/v3/envloader"
	"github.com/rokwire/core-auth-library-go/v3/keys"
	"github.com/rokwire/logging-library-go/v2/logs"
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

	serviceID := "core"

	loggerOpts := logs.LoggerOpts{SuppressRequests: logs.NewStandardHealthCheckHTTPRequestProperties(serviceID + "/version")}
	logger := logs.NewLogger(serviceID, &loggerOpts)
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

	host := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_HOST", true, false)

	baseServerURL := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_BASE_SERVER_URL", false, false)
	prodServerURL := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_PRODUCTION_SERVER_URL", false, false)
	testServerURL := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_TEST_SERVER_URL", false, false)
	devServerURL := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_DEVELOPMENT_SERVER_URL", false, false)

	// mongoDB adapter
	mongoDBAuth := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_MONGO_AUTH", true, true)
	mongoDBName := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_MONGO_DATABASE", true, false)
	mongoTimeout := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_MONGO_TIMEOUT", false, false)
	storageAdapter := storage.NewStorageAdapter(host, mongoDBAuth, mongoDBName, mongoTimeout, logger)
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

	var authPrivKeyPem string
	authPrivKeyPemString := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_AUTH_PRIV_KEY", false, true)
	if authPrivKeyPemString != "" {
		//make it to be a single line - AWS environemnt variable issue
		authPrivKeyPem = strings.ReplaceAll(authPrivKeyPemString, `\n`, "\n")
	} else {
		authPrivateKeyPath := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_AUTH_PRIV_KEY_PATH", true, false)
		authPrivKeyPemBytes, err := os.ReadFile(authPrivateKeyPath)
		if err != nil {
			logger.Fatalf("Could not find auth priv key file: %v", err)
		}

		authPrivKeyPem = string(authPrivKeyPemBytes)
	}
	authPrivKey, err := keys.NewPrivKey(keys.PS256, authPrivKeyPem)
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

	supportLegacySigsStr := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_SUPPORT_LEGACY_SIGNATURES", false, false)
	supportLegacySigs, err := strconv.ParseBool(supportLegacySigsStr)
	if err != nil {
		logger.Infof("Error parsing legacy signature support, applying defaults: %v", err)
		supportLegacySigs = true
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

	auth, err := auth.NewAuth(serviceID, host, authPrivKey, storageAdapter, emailer, minTokenExp, maxTokenExp, supportLegacySigs, twilioAccountSID, twilioToken, twilioServiceSID, profileBBAdapter, smtpHost, smtpPortNum, smtpUser, smtpPassword, smtpFrom, logger)
	if err != nil {
		logger.Fatalf("Error initializing auth: %v", err)
	}

	//system account init
	systemInitSettings := map[string]string{
		"app_type_id":   envLoader.GetAndLogEnvVar("ROKWIRE_CORE_SYSTEM_APP_TYPE_IDENTIFIER", false, false),
		"app_type_name": envLoader.GetAndLogEnvVar("ROKWIRE_CORE_SYSTEM_APP_TYPE_NAME", false, false),
		"api_key":       envLoader.GetAndLogEnvVar("ROKWIRE_CORE_SYSTEM_API_KEY", false, true),
		"email":         envLoader.GetAndLogEnvVar("ROKWIRE_CORE_SYSTEM_ACCOUNT_EMAIL", false, false),
		"password":      envLoader.GetAndLogEnvVar("ROKWIRE_CORE_SYSTEM_ACCOUNT_PASSWORD", false, true),
	}

	//core
	coreAPIs := core.NewCoreAPIs(env, Version, Build, storageAdapter, auth, systemInitSettings, logger)
	coreAPIs.Start()

	//web adapter
	webAdapter := web.NewWebAdapter(env, serviceID, auth.ServiceRegManager, port, coreAPIs, host, baseServerURL, prodServerURL, testServerURL, devServerURL, logger)
	webAdapter.Start()
}
