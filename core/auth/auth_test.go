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

package auth_test

import (
	"core-building-block/core/auth"
	"crypto/rsa"
	"testing"

	"github.com/rokwire/logging-library-go/logs"
)

//Email

//1. signUp applies sign up operation
// Returns:
//	message (string): Success message if verification is required. If verification is not required, return ""
//	credentialValue (map): Credential value
// signUp(authType model.AuthType, appOrg model.ApplicationOrganization, creds string, params string, newCredentialID string, l *logs.Log) (string, map[string]interface{}, error)

//2. signUpAdmin signs up a new admin user
// Returns:
//	password (string): newly generated password
//	credentialValue (map): Credential value
// signUpAdmin(authType model.AuthType, appOrg model.ApplicationOrganization, identifier string, password string, newCredentialID string) (map[string]interface{}, map[string]interface{}, error)

//3. verifies credential (checks the verification code generated on email signup for email auth type)
// Returns:
//	authTypeCreds (map[string]interface{}): Updated Credential.Value
// verifyCredential(credential *model.Credential, verification string, l *logs.Log) (map[string]interface{}, error)

//4. sends the verification code to the identifier
// sendVerifyCredential(credential *model.Credential, appName string, l *logs.Log) error

//5. restarts the credential verification
// restartCredentialVerification(credential *model.Credential, appName string, l *logs.Log) error

//6. updates the value of the credential object with new value
// Returns:
//	authTypeCreds (map[string]interface{}): Updated Credential.Value
// resetCredential(credential *model.Credential, resetCode *string, params string, l *logs.Log) (map[string]interface{}, error)

//7. apply forgot credential for the auth type (generates a reset password link with code and expiry and sends it to given identifier for email auth type)
// forgotCredential(credential *model.Credential, identifier string, appName string, l *logs.Log) (map[string]interface{}, error)

//8. getUserIdentifier parses the credentials and returns the user identifier
// Returns:
//	userIdentifier (string): User identifier
// getUserIdentifier(creds string) (string, error)

//9. isCredentialVerified says if the credential is verified
// Returns:
//	verified (bool): is credential verified
//	expired (bool): is credential verification expired
// isCredentialVerified(credential *model.Credential, l *logs.Log) (*bool, *bool, error)

//10. checkCredentials checks if the account credentials are valid for the account auth type
// checkCredentials(accountAuthType model.AccountAuthType, creds string, l *logs.Log) (string, error)

func NewAuth(authPrivKey *rsa.PrivateKey, minTokenExp *int64, maxTokenExp *int64, logger *logs.Logger) (*auth.Auth, error) {
	if minTokenExp == nil {
		var minTokenExpVal int64 = 5
		minTokenExp = &minTokenExpVal
	}

	if maxTokenExp == nil {
		var maxTokenExpVal int64 = 60
		maxTokenExp = &maxTokenExpVal
	}

	authTypes := map[string]authType{}

	auth := &auth.Auth{logger: logger, authTypes: authTypes, authPrivKey: authPrivKey, minTokenExp: *minTokenExp, maxTokenExp: *maxTokenExp}

	//Initialize auth types
	initEmailAuth(auth)

	return auth, nil
}

func TestEmail_SignUp(t *testing.T) {
	// storage := genmocks.Storage{}
	// auth, err := auth.NewAuth(serviceID, host, authPrivKey, storage, emailer, minTokenExp, maxTokenExp, twilioAccountSID, twilioToken, twilioServiceSID, profileBBAdapter, smtpHost, smtpPortNum, smtpUser, smtpPassword, smtpFrom, logger)

	//TODO: auth.applySignUp (3) vs. emailAuthImpl.signUp (2), sent verification email only in sendVerifyCredential, not signUp
	type args struct {
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "success", args: args{}, wantErr: false},
		{name: "mismatched passwords", args: args{}, wantErr: true},
		{name: "existing account", args: args{}, wantErr: false},
		{name: "sent verification email", args: args{}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

		})
	}
}
