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
	"core-building-block/core/auth/mocks"
	"core-building-block/core/model"
	"core-building-block/utils"
	"testing"
	"time"

	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
)

// newEmailTestAuth creates a new email test auth instance
func newEmailTestAuth(t *testing.T) (authType, *logs.Log) {
	anyString := mock.AnythingOfType("string")

	emailer := mocks.NewEmailer(t)
	emailer.On("Send", "bad_email", anyString, anyString, mock.AnythingOfType("*string")).Return(errors.New("failed to send")).Maybe()
	emailer.On("Send", anyString, anyString, anyString, mock.AnythingOfType("*string")).Return(nil).Maybe()

	storage := mocks.NewStorage(t)
	storage.On("UpdateCredential", nil, mock.AnythingOfType("*model.Credential")).Return(nil).Maybe()
	storage.On("UpdateCredentialValue", anyString, mock.AnythingOfType("map[string]interface {}")).Return(nil).Maybe()

	logger := logs.NewLogger("auth_type_email", nil)

	authTypes := map[string]authType{}
	auth := &Auth{storage: storage, emailer: emailer, authTypes: authTypes, logger: logger}
	initEmailAuth(auth)

	return authTypes["email"], logger.NewRequestLog(nil)
}

//Email

func TestEmail_SignUp(t *testing.T) {
	emailAuth, log := newEmailTestAuth(t)
	emailAuthType := model.AuthType{Code: "email", Params: map[string]interface{}{"verify_email": true, "verify_expiry": 1}}

	type args struct {
		creds  string
		params string

		newCreds map[string]interface{}
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "success", args: args{creds: `{"email": "test@email.com", "password": "sample_password"}`, params: `{"confirm_password": "sample_password"}`, newCreds: map[string]interface{}{"email": "test@email.com", "password": "sample_password"}}, wantErr: false},
		{name: "mismatched passwords", args: args{creds: `{"email": "test@email.com", "password": "sample_password"}`, params: `{"confirm_password": "different_password"}`}, wantErr: true},
		{name: "missing email", args: args{creds: `{"password": "sample_password"}`, params: `{"confirm_password": "sample_password"}`}, wantErr: true},
		{name: "missing password", args: args{creds: `{"email": "test@email.com"}`, params: `{"confirm_password": "sample_password"}`}, wantErr: true},
		{name: "missing confirm password", args: args{creds: `{"email": "test@email.com", "password": "sample_password"}`, params: `{}`}, wantErr: true},
		{name: "email send fail", args: args{creds: `{"email": "bad_email", "password": "sample_password"}`, params: `{"confirm_password": "sample_password"}`}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, credential, err := emailAuth.signUp(emailAuthType, "Email Test", tt.args.creds, tt.args.params, "email_cred", log)
			if err != nil && !tt.wantErr {
				t.Errorf("emailAuthImpl.signUp error = %v", err)
				return
			}
			if (credential == nil) != (tt.args.newCreds == nil) {
				t.Errorf("emailAuthImpl.signUp credential = %v, expected %v", credential, tt.args.newCreds)
				return
			}
			if tt.args.newCreds != nil {
				if tt.args.newCreds["email"] != credential["email"] {
					t.Errorf("emailAuthImpl.signUp credential.email = %v, expected %v", credential["email"], tt.args.newCreds["email"])
					return
				}

				storedPassword, _ := credential["password"].(string)
				expectedPlaintext, _ := tt.args.newCreds["password"].(string)
				if bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(expectedPlaintext)) != nil {
					t.Errorf("emailAuthImpl.signUp password check error: credential.password = %s, plaintext %s", storedPassword, expectedPlaintext)
					return
				}
			}
		})
	}
}

func TestEmail_SignUpAdmin(t *testing.T) {
	emailAuth, _ := newEmailTestAuth(t)
	emailAuthType := model.AuthType{Code: "email", Params: map[string]interface{}{"verify_email": true, "verify_expiry": 1}}

	type args struct {
		identifier string
		password   string

		newCreds map[string]interface{}
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "success explicit password", args: args{identifier: "test@email.com", password: "sample_password", newCreds: map[string]interface{}{"email": "test@email.com", "password": "sample_password"}}, wantErr: false},
		{name: "success random password", args: args{identifier: "test@email.com", password: "", newCreds: map[string]interface{}{"email": "test@email.com"}}, wantErr: false},
		{name: "email send fail", args: args{identifier: "bad_email", password: "sample_password"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, credential, err := emailAuth.signUpAdmin(emailAuthType, "Email Test", tt.args.identifier, tt.args.password, "email_cred")
			if err != nil && !tt.wantErr {
				t.Errorf("emailAuthImpl.signUpAdmin error = %v", err)
				return
			}
			if params == nil && !tt.wantErr {
				t.Errorf("emailAuthImpl.signUpAdmin params = %v", params)
				return
			}
			if (credential == nil) != (tt.args.newCreds == nil) {
				t.Errorf("emailAuthImpl.signUpAdmin credential = %v, expected %v", credential, tt.args.newCreds)
				return
			}
			if tt.args.newCreds != nil {
				if tt.args.newCreds["email"] != credential["email"] {
					t.Errorf("emailAuthImpl.signUpAdmin credential.email = %v, expected %v", credential["email"], tt.args.newCreds["email"])
					return
				}

				storedPassword, _ := credential["password"].(string)
				expectedPlaintext, _ := params["password"].(string)
				if bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(expectedPlaintext)) != nil {
					t.Errorf("emailAuthImpl.signUpAdmin password check error: credential.password = %s, plaintext %s", storedPassword, expectedPlaintext)
					return
				}
			}
		})
	}
}

// Verifies credential (checks the verification code generated on email signup for email auth type)
// Returns:
//
//	authTypeCreds (map[string]interface{}): Updated Credential.Value
func TestEmail_VerifyCredential(t *testing.T) {
	emailAuth, log := newEmailTestAuth(t)
	credential := model.Credential{Value: map[string]interface{}{
		"verification_code": "sample_verification_code",
	}}

	type args struct {
		code       string
		expiration time.Time

		newCreds map[string]interface{}
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "success", args: args{code: "sample_verification_code", expiration: time.Now().UTC().Add(time.Minute), newCreds: map[string]interface{}{"verification_code": "", "verification_expiry": utils.FormatTime(&time.Time{})}}, wantErr: false},
		{name: "incorrect verification code", args: args{code: "incorrect_verification_code", expiration: time.Now().UTC().Add(time.Minute)}, wantErr: true},
		{name: "expired code", args: args{code: "sample_verification_code", expiration: time.Now().UTC().Add(-time.Minute)}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			credential.Value["verification_expiry"] = utils.FormatTime(&tt.args.expiration)
			updatedCredentialValue, err := emailAuth.verifyCredential(&credential, tt.args.code, log)
			if err != nil && !tt.wantErr {
				t.Errorf("emailAuthImpl.verifyCredential error = %v", err)
				return
			}
			if (updatedCredentialValue == nil) != (tt.args.newCreds == nil) {
				t.Errorf("emailAuthImpl.signUp credential value = %v, expected %v", credential, tt.args.newCreds)
			}
		})
	}
}

// Sends the verification code to the identifier
func TestEmail_SendVerifyCredential(t *testing.T) {
	emailAuth, log := newEmailTestAuth(t)
	emailAuthType := model.AuthType{Code: "email", Params: map[string]interface{}{"verify_email": true, "verify_expiry": 1, "verify_wait_time": 60}}
	credential := model.Credential{ID: "email_cred", AuthType: emailAuthType, Value: map[string]interface{}{}}

	type args struct {
		email      string
		expiration time.Time
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "success", args: args{email: "test@email.com", expiration: time.Now().UTC().Add(58 * time.Minute)}, wantErr: false},
		{name: "resend too soon", args: args{email: "test@email.com", expiration: time.Now().UTC().Add(59*time.Minute + 30*time.Second)}, wantErr: true},
		{name: "email send fail", args: args{email: "bad_email", expiration: time.Now().UTC().Add(58 * time.Minute)}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			credential.Value["email"] = tt.args.email
			credential.Value["verification_expiry"] = utils.FormatTime(&tt.args.expiration)
			err := emailAuth.sendVerifyCredential(&credential, "Email Test", log)
			if (err != nil) != tt.wantErr {
				t.Errorf("emailAuthImpl.sendVerifyCredential error = %v", err)
				return
			}
		})
	}
}

func TestEmail_RestartCredentialVerification(t *testing.T) {
	emailAuth, log := newEmailTestAuth(t)
	credential := model.Credential{ID: "email_cred", Value: map[string]interface{}{}}

	type args struct {
		email      string
		expiration time.Time
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "success future", args: args{email: "test@email.com", expiration: time.Now().UTC().Add(time.Minute)}, wantErr: false},
		{name: "success past", args: args{email: "test@email.com", expiration: time.Now().UTC().Add(-time.Minute)}, wantErr: false},
		{name: "email send fail", args: args{email: "bad_email", expiration: time.Now().UTC().Add(58 * time.Minute)}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			credential.Value["email"] = tt.args.email
			credential.Value["verification_expiry"] = utils.FormatTime(&tt.args.expiration)
			err := emailAuth.restartCredentialVerification(&credential, "Email Test", log)
			if (err != nil) != tt.wantErr {
				t.Errorf("emailAuthImpl.restartCredentialVerification error = %v", err)
				return
			}
		})
	}
}

/*
// Updates the value of the credential object with new value
// Returns:
//
//	authTypeCreds (map[string]interface{}): Updated Credential.Value
func TestEmail_ResetCredential(t *testing.T) {
	emailAuth, log := newEmailTestAuth(t)
	emailAuthType := model.AuthType{Code: "email", Params: map[string]interface{}{"verify_email": true, "verify_expiry": 1}}

	type args struct {
		identifier string
		password   string

		newCreds map[string]interface{}
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "success explicit password", args: args{identifier: "test@email.com", password: "sample_password", newCreds: map[string]interface{}{"email": "test@email.com", "password": "sample_password"}}, wantErr: false},
		{name: "success random password", args: args{identifier: "test@email.com", password: "", newCreds: map[string]interface{}{"email": "test@email.com"}}, wantErr: false},
		{name: "email send fail", args: args{identifier: "bad_email", password: "sample_password"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			credential, err := emailAuth.resetCredential(emailAuthType, "Email Test", log)
			if err != nil && !tt.wantErr {
				t.Errorf("emailAuthImpl.verifyCredential error = %v", err)
				return
			}
		})
	}
}

// Apply forgot credential for the auth type (generates a reset password link with code and expiry and sends it to given identifier for email auth type)
func TestEmail_ForgotCredential(t *testing.T) {
	emailAuth, log := newEmailTestAuth(t)
	emailAuthType := model.AuthType{Code: "email", Params: map[string]interface{}{"verify_email": true, "verify_expiry": 1}}

	type args struct {
		identifier string
		password   string

		newCreds map[string]interface{}
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "success explicit password", args: args{identifier: "test@email.com", password: "sample_password", newCreds: map[string]interface{}{"email": "test@email.com", "password": "sample_password"}}, wantErr: false},
		{name: "success random password", args: args{identifier: "test@email.com", password: "", newCreds: map[string]interface{}{"email": "test@email.com"}}, wantErr: false},
		{name: "email send fail", args: args{identifier: "bad_email", password: "sample_password"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			credential, err := emailAuth.forgotCredential(emailAuthType, "Email Test", log)
			if err != nil && !tt.wantErr {
				t.Errorf("emailAuthImpl.verifyCredential error = %v", err)
				return
			}
		})
	}
}

// GetUserIdentifier parses the credentials and returns the user identifier
// Returns:
//
//	userIdentifier (string): User identifier
func TestEmail_GetUserIdentifier(t *testing.T) {
	emailAuth, log := newEmailTestAuth(t)
	emailAuthType := model.AuthType{Code: "email", Params: map[string]interface{}{"verify_email": true, "verify_expiry": 1}}

	type args struct {
		identifier string
		password   string

		newCreds map[string]interface{}
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "success explicit password", args: args{identifier: "test@email.com", password: "sample_password", newCreds: map[string]interface{}{"email": "test@email.com", "password": "sample_password"}}, wantErr: false},
		{name: "success random password", args: args{identifier: "test@email.com", password: "", newCreds: map[string]interface{}{"email": "test@email.com"}}, wantErr: false},
		{name: "email send fail", args: args{identifier: "bad_email", password: "sample_password"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			credential, err := emailAuth.getUserIdentifier(emailAuthType, "Email Test", log)
			if err != nil && !tt.wantErr {
				t.Errorf("emailAuthImpl.verifyCredential error = %v", err)
				return
			}
		})
	}
}

// IsCredentialVerified says if the credential is verified
// Returns:
//
//	verified (bool): is credential verified
//	expired (bool): is credential verification expired
func TestEmail_IsCredentialVerified(t *testing.T) {
	emailAuth, log := newEmailTestAuth(t)
	emailAuthType := model.AuthType{Code: "email", Params: map[string]interface{}{"verify_email": true, "verify_expiry": 1}}

	type args struct {
		identifier string
		password   string

		newCreds map[string]interface{}
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "success explicit password", args: args{identifier: "test@email.com", password: "sample_password", newCreds: map[string]interface{}{"email": "test@email.com", "password": "sample_password"}}, wantErr: false},
		{name: "success random password", args: args{identifier: "test@email.com", password: "", newCreds: map[string]interface{}{"email": "test@email.com"}}, wantErr: false},
		{name: "email send fail", args: args{identifier: "bad_email", password: "sample_password"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			credential, err := emailAuth.isCredentialVerified(emailAuthType, "Email Test", log)
			if err != nil && !tt.wantErr {
				t.Errorf("emailAuthImpl.verifyCredential error = %v", err)
				return
			}
		})
	}
}

// CheckCredentials checks if the account credentials are valid for the account auth type
func TestEmail_CheckCredentials(t *testing.T) {
	emailAuth, log := newEmailTestAuth(t)
	emailAuthType := model.AuthType{Code: "email", Params: map[string]interface{}{"verify_email": true, "verify_expiry": 1}}

	type args struct {
		identifier string
		password   string

		newCreds map[string]interface{}
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "success explicit password", args: args{identifier: "test@email.com", password: "sample_password", newCreds: map[string]interface{}{"email": "test@email.com", "password": "sample_password"}}, wantErr: false},
		{name: "success random password", args: args{identifier: "test@email.com", password: "", newCreds: map[string]interface{}{"email": "test@email.com"}}, wantErr: false},
		{name: "email send fail", args: args{identifier: "bad_email", password: "sample_password"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			credential, err := emailAuth.checkCredentials(emailAuthType, "Email Test", log)
			if err != nil && !tt.wantErr {
				t.Errorf("emailAuthImpl.verifyCredential error = %v", err)
				return
			}
		})
	}
}
*/
