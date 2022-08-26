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

const (
	zeroTimeString string = "0001-01-01T00:00:00Z"
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

				if credential["reset_code"] != "" {
					t.Errorf("emailAuthImpl.signUp credential.reset_code = %v", credential["reset_code"])
					return
				}
				if credential["reset_expiry"] != zeroTimeString {
					t.Errorf("emailAuthImpl.signUp credential.reset_expiry = %v", credential["reset_expiry"])
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

				if credential["reset_code"] != "" {
					t.Errorf("emailAuthImpl.signUpAdmin credential.reset_code = %v", credential["reset_code"])
					return
				}
				if credential["reset_expiry"] != zeroTimeString {
					t.Errorf("emailAuthImpl.signUpAdmin credential.reset_expiry = %v", credential["reset_expiry"])
				}
			}
		})
	}
}

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
				t.Errorf("emailAuthImpl.verifyCredential credential value = %v, expected %v", credential, tt.args.newCreds)
			}

			if !tt.wantErr && updatedCredentialValue["verification_code"] != "" {
				t.Errorf("emailAuthImpl.verifyCredential credential.verification_code = %v", updatedCredentialValue["verification_code"])
				return
			}
			if !tt.wantErr && updatedCredentialValue["verification_expiry"] != zeroTimeString {
				t.Errorf("emailAuthImpl.verifyCredential credential.verification_expiry = %v", updatedCredentialValue["verification_expiry"])
			}
		})
	}
}

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

func TestEmail_ResetCredential(t *testing.T) {
	emailAuth, log := newEmailTestAuth(t)
	resetCodeStr := "sample_reset_code"
	resetCode, _ := bcrypt.GenerateFromPassword([]byte(resetCodeStr), bcrypt.DefaultCost)
	incorrectCode := "incorrect_reset_code"
	credential := model.Credential{Value: map[string]interface{}{
		"email":             "test@email.com",
		"password":          "old_password",
		"reset_code":        string(resetCode),
		"verification_code": "sample_verification_code",
	}}

	type args struct {
		params          string
		resetCode       *string
		resetExpiration time.Time

		newCreds map[string]interface{}
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "success with code", args: args{params: `{"new_password": "sample_password", "confirm_password": "sample_password"}`, resetCode: &resetCodeStr, resetExpiration: time.Now().UTC().Add(time.Minute), newCreds: map[string]interface{}{"email": "test@email.com", "password": "sample_password"}}, wantErr: false},
		{name: "success without code", args: args{params: `{"new_password": "sample_password", "confirm_password": "sample_password"}`, newCreds: map[string]interface{}{"email": "test@email.com", "password": "sample_password"}}, wantErr: false},
		{name: "mismatched passwords", args: args{params: `{"new_password": "sample_password", "confirm_password": "different_password"}`}, wantErr: true},
		{name: "missing password", args: args{params: `{"confirm_password": "sample_password"}`}, wantErr: true},
		{name: "missing confirm password", args: args{params: `{"new_password": "sample_password"}`}, wantErr: true},
		{name: "expired reset code", args: args{params: `{"new_password": "sample_password", "confirm_password": "sample_password"}`, resetCode: &resetCodeStr, resetExpiration: time.Now().UTC().Add(-time.Minute)}, wantErr: true},
		{name: "incorrect reset code", args: args{params: `{"new_password": "sample_password", "confirm_password": "sample_password"}`, resetCode: &incorrectCode, resetExpiration: time.Now().UTC().Add(time.Minute)}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			credential.Value["reset_expiry"] = utils.FormatTime(&tt.args.resetExpiration)
			updatedCredentialValue, err := emailAuth.resetCredential(&credential, tt.args.resetCode, tt.args.params, log)
			if err != nil && !tt.wantErr {
				t.Errorf("emailAuthImpl.resetCredential error = %v", err)
				return
			}
			if (updatedCredentialValue == nil) != (tt.args.newCreds == nil) {
				t.Errorf("emailAuthImpl.resetCredential credential = %v, expected %v", credential, tt.args.newCreds)
				return
			}
			if tt.args.newCreds != nil {
				if tt.args.newCreds["email"] != updatedCredentialValue["email"] {
					t.Errorf("emailAuthImpl.resetCredential credential.email = %v, expected %v", updatedCredentialValue["email"], tt.args.newCreds["email"])
					return
				}

				storedPassword, _ := updatedCredentialValue["password"].(string)
				expectedPlaintext, _ := tt.args.newCreds["password"].(string)
				if bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(expectedPlaintext)) != nil {
					t.Errorf("emailAuthImpl.resetCredential password check error: credential.password = %s, plaintext %s", storedPassword, expectedPlaintext)
					return
				}

				if tt.args.resetCode != nil && updatedCredentialValue["reset_code"] != "" {
					t.Errorf("emailAuthImpl.resetCredential credential.reset_code = %v", updatedCredentialValue["reset_code"])
					return
				}
				if updatedCredentialValue["reset_expiry"] != zeroTimeString {
					t.Errorf("emailAuthImpl.resetCredential credential.reset_expiry = %v", updatedCredentialValue["reset_expiry"])
				}
			}
		})
	}
}

func TestEmail_ForgotCredential(t *testing.T) {
	emailAuth, log := newEmailTestAuth(t)
	credential := model.Credential{ID: "email_cred", Value: map[string]interface{}{}}

	type args struct {
		identifier string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "success explicit password", args: args{identifier: "test@email.com"}, wantErr: false},
		{name: "email send fail", args: args{identifier: "bad_email"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			credential.Value["email"] = tt.args.identifier
			updatedCredentialValue, err := emailAuth.forgotCredential(&credential, "Email Test", tt.args.identifier, log)
			if err != nil && !tt.wantErr {
				t.Errorf("emailAuthImpl.forgotCredential error = %v", err)
				return
			}
			if !tt.wantErr && updatedCredentialValue["reset_code"] == "" {
				t.Error("emailAuthImpl.forgotCredential credential.reset_code missing")
				return
			}
			if !tt.wantErr && updatedCredentialValue["reset_expiry"] == zeroTimeString {
				t.Errorf("emailAuthImpl.forgotCredential credential.reset_expiry = %s", zeroTimeString)
			}
		})
	}
}

func TestEmail_GetUserIdentifier(t *testing.T) {
	emailAuth, _ := newEmailTestAuth(t)

	type args struct {
		creds      string
		identifier string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "success", args: args{creds: `{"email": "test@email.com", "password": "sample_password"}`, identifier: "test@email.com"}, wantErr: false},
		{name: "malformed creds", args: args{creds: `{email: test@email.com}`, identifier: "test@email.com"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identifier, err := emailAuth.getUserIdentifier(tt.args.creds)
			if err != nil && !tt.wantErr {
				t.Errorf("emailAuthImpl.getUserIdentifier error = %v", err)
				return
			}
			if !tt.wantErr && identifier != tt.args.identifier {
				t.Errorf("emailAuthImpl.getUserIdentifier identifier = %s, expected = %s", identifier, tt.args.identifier)
			}
		})
	}
}

func TestEmail_IsCredentialVerified(t *testing.T) {
	emailAuth, log := newEmailTestAuth(t)
	emailAuthType := model.AuthType{Code: "email", Params: map[string]interface{}{}}
	credential := model.Credential{ID: "email_cred", AuthType: emailAuthType, Value: map[string]interface{}{}}

	type args struct {
		verified    bool
		expiration  time.Time
		verifyEmail bool
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "verified not expired", args: args{verified: true, expiration: time.Now().UTC().Add(time.Minute)}, wantErr: false},
		{name: "verified expired", args: args{verified: true, expiration: time.Time{}}, wantErr: false},
		{name: "not verified expired", args: args{verified: false, expiration: time.Now().UTC().Add(-time.Minute), verifyEmail: true}, wantErr: false},
		{name: "not verified not expired", args: args{verified: false, expiration: time.Now().UTC().Add(time.Minute), verifyEmail: true}, wantErr: false},
		{name: "no email verification", args: args{verified: true}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			credential.AuthType.Params["verify_email"] = tt.args.verifyEmail
			credential.Verified = tt.args.verified
			credential.Value["verification_expiry"] = utils.FormatTime(&tt.args.expiration)
			verified, verificationExpired, err := emailAuth.isCredentialVerified(&credential, log)
			if err != nil && !tt.wantErr {
				t.Errorf("emailAuthImpl.isCredentialVerified error = %v", err)
				return
			}
			if !tt.wantErr {
				if verified == nil {
					t.Errorf("emailAuthImpl.isCredentialVerified verified flag missing")
					return
				}
				if *verified != tt.args.verified {
					t.Errorf("emailAuthImpl.isCredentialVerified verified = %t", *verified)
					return
				}
				if tt.args.verifyEmail && *verificationExpired != tt.args.expiration.Before(time.Now().UTC()) {
					t.Errorf("emailAuthImpl.isCredentialVerified verificationExpired = %t", *verificationExpired)
				}
			}
		})
	}
}

/*
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
