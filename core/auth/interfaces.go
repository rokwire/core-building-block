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

package auth

import (
	"core-building-block/core/interfaces"
	"core-building-block/core/model"
	// "core-building-block/driven/storage"
	"time"

	"github.com/rokwire/core-auth-library-go/v2/sigauth"
	"github.com/rokwire/logging-library-go/logs"
)

// authType is the interface for authentication for auth types which are not external for the system(the users do not come from external system)
type authType interface {
	//signUp applies sign up operation
	// Returns:
	//	message (string): Success message if verification is required. If verification is not required, return ""
	//	credentialValue (map): Credential value
	signUp(authType model.AuthType, appOrg model.ApplicationOrganization, creds string, params string, newCredentialID string, l *logs.Log) (string, map[string]interface{}, error)

	//signUpAdmin signs up a new admin user
	// Returns:
	//	password (string): newly generated password
	//	credentialValue (map): Credential value
	signUpAdmin(authType model.AuthType, appOrg model.ApplicationOrganization, identifier string, password string, newCredentialID string) (map[string]interface{}, map[string]interface{}, error)

	//verifies credential (checks the verification code generated on email signup for email auth type)
	// Returns:
	//	authTypeCreds (map[string]interface{}): Updated Credential.Value
	verifyCredential(credential *model.Credential, verification string, l *logs.Log) (map[string]interface{}, error)

	//sends the verification code to the identifier
	sendVerifyCredential(credential *model.Credential, appName string, l *logs.Log) error

	//restarts the credential verification
	restartCredentialVerification(credential *model.Credential, appName string, l *logs.Log) error

	//updates the value of the credential object with new value
	// Returns:
	//	authTypeCreds (map[string]interface{}): Updated Credential.Value
	resetCredential(credential *model.Credential, resetCode *string, params string, l *logs.Log) (map[string]interface{}, error)

	//apply forgot credential for the auth type (generates a reset password link with code and expiry and sends it to given identifier for email auth type)
	forgotCredential(credential *model.Credential, identifier string, appName string, l *logs.Log) (map[string]interface{}, error)

	//getUserIdentifier parses the credentials and returns the user identifier
	// Returns:
	//	userIdentifier (string): User identifier
	getUserIdentifier(creds string) (string, error)

	//isCredentialVerified says if the credential is verified
	// Returns:
	//	verified (bool): is credential verified
	//	expired (bool): is credential verification expired
	isCredentialVerified(credential *model.Credential, l *logs.Log) (*bool, *bool, error)

	//checkCredentials checks if the account credentials are valid for the account auth type
	checkCredentials(accountAuthType model.AccountAuthType, creds string, l *logs.Log) (string, error)
}

// externalAuthType is the interface for authentication for auth types which are external for the system(the users comes from external system).
// these are the different identity providers - illinois_oidc etc
type externalAuthType interface {
	//getLoginUrl retrieves and pre-formats a login url and params for the SSO provider
	getLoginURL(authType model.AuthType, appType model.ApplicationType, redirectURI string, l *logs.Log) (string, map[string]interface{}, error)
	//externalLogin logins in the external system and provides the authenticated user
	externalLogin(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, creds string, params string, l *logs.Log) (*model.ExternalSystemUser, map[string]interface{}, error)
	//refresh refreshes tokens
	refresh(params map[string]interface{}, authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, l *logs.Log) (*model.ExternalSystemUser, map[string]interface{}, error)
}

// anonymousAuthType is the interface for authentication for auth types which are anonymous
type anonymousAuthType interface {
	//checkCredentials checks the credentials for the provided app and organization
	//	Returns anonymous profile identifier
	checkCredentials(creds string) (string, map[string]interface{}, error)
}

// serviceAuthType is the interface for authentication for non-human clients
type serviceAuthType interface {
	checkCredentials(r *sigauth.Request, creds interface{}, params map[string]interface{}) ([]model.ServiceAccount, error)
	addCredentials(creds *model.ServiceAccountCredential) (map[string]interface{}, error)
}

// mfaType is the interface for multi-factor authentication
type mfaType interface {
	//verify verifies the code based on stored mfa params
	verify(storage interfaces.Storage, mfa *model.MFAType, accountID string, code string) (*string, error)
	//enroll creates a mfa type to be added to an account
	enroll(identifier string) (*model.MFAType, error)
	//sendCode generates a mfa code and expiration time and sends the code to the user
	sendCode(identifier string) (string, *time.Time, error)
}
