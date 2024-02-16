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
	"core-building-block/core/model"
	"core-building-block/driven/emailer"
	"core-building-block/driven/identitybb"
	"core-building-block/driven/phoneverifier"
	"core-building-block/driven/profilebb"
	"core-building-block/driven/storage"
	"core-building-block/driver/web"
	"os"
	"strconv"
	"strings"

	"github.com/rokwire/core-auth-library-go/v3/authservice"
	"github.com/rokwire/core-auth-library-go/v3/authutils"

	"github.com/rokwire/core-auth-library-go/v3/envloader"
	"github.com/rokwire/core-auth-library-go/v3/keys"
	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logs"
	"github.com/rokwire/logging-library-go/v2/logutils"
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

	logger.Infof("Version: %s", Version)

	env := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_ENVIRONMENT", true, false) //local, dev, staging, prod
	port := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_PORT", false, false)
	//Default port of 80
	if port == "" {
		port = "5000"
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
	uiucAuthTypeCodeMigrationSource := envLoader.GetAndLogEnvVar("ROKWIRE_TAM_AUTH_TYPE_CODE_SOURCE", true, false) //TAM - TENANT_ACCOUNTS_MIGRATION
	storageAdapter := storage.NewStorageAdapter(host, mongoDBAuth, mongoDBName, mongoTimeout, uiucAuthTypeCodeMigrationSource, logger)
	err := storageAdapter.Start()
	if err != nil {
		logger.Fatalf("Cannot start the mongoDB adapter: %v", err)
	}

	//auth
	twilioAccountSID := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_AUTH_TWILIO_ACCOUNT_SID", false, true)
	twilioToken := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_AUTH_TWILIO_TOKEN", false, true)
	twilioServiceSID := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_AUTH_TWILIO_SERVICE_SID", false, true)

	twilioPhoneVerifier, err := phoneverifier.NewTwilioAdapter(twilioAccountSID, twilioToken, twilioServiceSID)
	if err != nil {
		logger.Warnf("Cannot start the twilio phone verifier: %v", err)
	}

	smtpHost := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_SMTP_HOST", false, false)
	smtpPort := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_SMTP_PORT", false, false)
	smtpUser := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_SMTP_USER", false, true)
	smtpPassword := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_SMTP_PASSWORD", false, true)
	smtpFrom := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_SMTP_EMAIL_FROM", false, false)
	smtpPortNum, _ := strconv.Atoi(smtpPort)

	verifyEmailRaw := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_VERIFY_EMAIL", false, false)
	verifyEmail, err := strconv.ParseBool(verifyEmailRaw)
	if err != nil {
		logger.Infof("Error parsing ROKWIRE_CORE_VERIFY_EMAIL, applying defaults: %v", err)
		verifyEmail = true
	}
	verifyWaitTimeRaw := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_VERIFY_WAIT_TIME", false, false)
	verifyWaitTime, err := strconv.Atoi(verifyWaitTimeRaw)
	if err != nil {
		logger.Infof("Error parsing ROKWIRE_CORE_VERIFY_WAIT_TIME, applying defaults: %v", err)
		verifyWaitTime = 30 // minutes
	}
	verifyExpiryRaw := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_VERIFY_EXPIRY", false, false)
	verifyExpiry, err := strconv.Atoi(verifyExpiryRaw)
	if err != nil {
		logger.Infof("Error parsing ROKWIRE_CORE_VERIFY_EXPIRY, applying defaults: %v", err)
		verifyExpiry = 24 // hours
	}

	emailer := emailer.NewEmailerAdapter(smtpHost, smtpPortNum, smtpUser, smtpPassword, smtpFrom)

	supportLegacySigsStr := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_SUPPORT_LEGACY_SIGNATURES", false, false)
	supportLegacySigs, err := strconv.ParseBool(supportLegacySigsStr)
	if err != nil {
		logger.Infof("Error parsing legacy signature support, applying defaults: %v", err)
		supportLegacySigs = true
	}
	currentAuthPrivKey := parsePrivKeyFromEnvVar("ROKWIRE_CORE_AUTH_PRIV_KEY", envLoader, supportLegacySigs, logger)
	if currentAuthPrivKey == nil {
		logger.Fatalf("Cannot parse the current private key: %v", err)
	}

	oldSupportLegacySigsStr := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_OLD_SUPPORT_LEGACY_SIGNATURES", false, false)
	oldSupportLegacySigs, err := strconv.ParseBool(oldSupportLegacySigsStr)
	if err != nil {
		logger.Infof("Error parsing old legacy signature support, applying defaults: %v", err)
		oldSupportLegacySigs = true
	}
	oldAuthPrivKey := parsePrivKeyFromEnvVar("ROKWIRE_CORE_OLD_AUTH_PRIV_KEY", envLoader, oldSupportLegacySigs, logger)

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

	authService := &authservice.AuthService{
		ServiceID:   serviceID,
		ServiceHost: host,
		FirstParty:  true,
	}

	authImpl, err := auth.NewAuth(serviceID, host, currentAuthPrivKey, oldAuthPrivKey, authService, storageAdapter, emailer, twilioPhoneVerifier, profileBBAdapter,
		minTokenExp, maxTokenExp, supportLegacySigs, Version, logger)
	if err != nil {
		logger.Fatalf("Error initializing auth: %v", err)
	}

	serviceAccountLoader := auth.NewLocalServiceAccountLoader(*authImpl)
	serviceAccountManager, err := authservice.NewServiceAccountManager(authService, serviceAccountLoader)
	if err != nil {
		logger.Fatalf("Error initializing service account manager: %v", err)
	}
	identityBBAdapter := identitybb.NewIdentityBBAdapter(serviceAccountManager)
	authImpl.SetIdentityBB(identityBBAdapter)

	//system account init
	systemInitSettings := map[string]string{
		"app_type_id":   envLoader.GetAndLogEnvVar("ROKWIRE_CORE_SYSTEM_APP_TYPE_IDENTIFIER", false, false),
		"app_type_name": envLoader.GetAndLogEnvVar("ROKWIRE_CORE_SYSTEM_APP_TYPE_NAME", false, false),
		"api_key":       envLoader.GetAndLogEnvVar("ROKWIRE_CORE_SYSTEM_API_KEY", false, true),
		"email":         envLoader.GetAndLogEnvVar("ROKWIRE_CORE_SYSTEM_ACCOUNT_EMAIL", false, false),
		"password":      envLoader.GetAndLogEnvVar("ROKWIRE_CORE_SYSTEM_ACCOUNT_PASSWORD", false, true),
	}

	//core
	coreAPIs := core.NewCoreAPIs(env, Version, Build, serviceID, storageAdapter, authImpl, systemInitSettings, verifyEmail, verifyWaitTime, verifyExpiry, logger)
	coreAPIs.Start()

	// read CORS parameters from stored env config
	var envData *model.EnvConfigData
	var corsAllowedHeaders []string
	var corsAllowedOrigins []string
	config, err := storageAdapter.FindConfig(model.ConfigTypeEnv, authutils.AllApps, authutils.AllOrgs)
	if err != nil {
		logger.Fatal(errors.WrapErrorAction(logutils.ActionFind, model.TypeConfig, nil, err).Error())
	}
	if config != nil {
		envData, err = model.GetConfigData[model.EnvConfigData](*config)
		if err != nil {
			logger.Fatal(errors.WrapErrorAction(logutils.ActionCast, model.TypeEnvConfigData, nil, err).Error())
		}

		corsAllowedHeaders = envData.CORSAllowedHeaders
		corsAllowedOrigins = envData.CORSAllowedOrigins
	}

	exposeDocs := false
	exposeDocsVar := envLoader.GetAndLogEnvVar("ROKWIRE_CORE_EXPOSE_DOCS", false, false)
	if strings.ToLower(exposeDocsVar) == "true" {
		exposeDocs = true
	}

	//web adapter
	webAdapter := web.NewWebAdapter(env, authImpl.ServiceRegManager, port, coreAPIs, host, exposeDocs,
		corsAllowedOrigins, corsAllowedHeaders, baseServerURL, prodServerURL, testServerURL, devServerURL, logger)
	webAdapter.Start()
}

func parsePrivKeyFromEnvVar(envVarName string, envLoader envloader.EnvLoader, supportLegacySigs bool, logger *logs.Logger) *keys.PrivKey {
	var authPrivKeyPem string
	authPrivKeyPemString := envLoader.GetAndLogEnvVar(envVarName, false, true)
	if authPrivKeyPemString != "" {
		//make it to be a single line - AWS environemnt variable issue
		authPrivKeyPem = strings.ReplaceAll(authPrivKeyPemString, `\n`, "\n")
	} else {
		authPrivateKeyPath := envLoader.GetAndLogEnvVar(envVarName+"_PATH", false, false)
		if authPrivateKeyPath == "" {
			return nil
		}

		authPrivKeyPemBytes, err := os.ReadFile(authPrivateKeyPath)
		if err != nil {
			logger.Fatalf("Could not find auth priv key file: %v", err)
		}
		authPrivKeyPem = string(authPrivKeyPemBytes)
	}

	alg := keys.PS256
	if supportLegacySigs {
		alg = keys.RS256
	}
	authPrivKey, err := keys.NewPrivKey(alg, authPrivKeyPem)
	if err != nil {
		logger.Fatalf("Failed to parse auth priv key: %v", err)
	}
	return authPrivKey
}
