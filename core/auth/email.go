package auth

import (
	"core-building-block/core/model"
	"core-building-block/utils"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rokmetro/logging-library/errors"
	"github.com/rokmetro/logging-library/logs"
	"github.com/rokmetro/logging-library/logutils"
	"golang.org/x/crypto/bcrypt"
)

// Email implementation of authType
type emailAuthImpl struct {
	auth     *Auth
	authType string
}

const (
	typeTime       logutils.MessageDataType = "time.Time"
	authTypeEmail  string                   = "email"
	typeEmailCreds logutils.MessageDataType = "emailCreds"
)

//credentials represents the emailCreds struct for email auth
type emailCreds struct {
	Email              string    `json:"email" bson:"email" validate:"required"`
	Password           string    `json:"password" bson:"password"`
	VerificationCode   string    `json:"verification_code" bson:"verification_code" validate:"required"`
	VerificationExpiry time.Time `json:"verification_expiry" bson:"verification_expiry"`
}

// check(creds string, orgID string, appID string, params string, l *logs.Log) (*model.UserAuth, error)
func (a *emailAuthImpl) checkCredentials(accountAuthType *model.AccountAuthType, creds string, params string, appOrg model.ApplicationOrganization, l *logs.Log) (*string, map[string]interface{}, error) {
	appID := appOrg.Application.ID
	orgID := appOrg.Organization.ID
	var credID string
	if accountAuthType != nil {
		credID = accountAuthType.Credential.ID
	}
	var requestCreds *emailCreds
	err := json.Unmarshal([]byte(creds), requestCreds)
	if err != nil {
		return nil, nil, err
	}
	paramsMap := make(map[string]interface{})
	err = json.Unmarshal([]byte(params), &paramsMap)
	if err != nil {
		return nil, nil, err
	}
	newUser, ok := paramsMap["newUser"].(bool)
	if !ok {
		return nil, nil, errors.New("newUser flag missing or invalid")
	}

	credential, err := a.auth.storage.FindCredentialByID(credID)
	if err != nil {
		errFields := logutils.FieldArgs{"_id": credID}
		l.LogAction(logs.Warn, logutils.StatusError, logutils.ActionFind, model.TypeCredential, &errFields)
		return nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeCredential, nil, err)
	}
	var user *emailCreds
	if credential != nil {
		user, err = mapToEmailCreds(credential.Value)
		if err != nil {
			return nil, nil, err
		}
	}

	//Handle sign up
	if accountAuthType == nil {
		if !newUser {
			return nil, nil, errors.New("no account found newUser flag must be set")
		}
		// if user != nil {
		// 	return nil, nil, errors.New("email is not verified yet")
		// }
		newCreds, err := a.handleSignup(requestCreds, user, appID, orgID)
		if err != nil {
			return nil, nil, err
		}
		newCredsMap, err := emailCredsToMap(newCreds)
		if err != nil {
			return nil, nil, err
		}
		return &user.Email, newCredsMap, nil
	}

	if err = a.handleSignin(requestCreds, user); err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionValidate, typeEmailCreds, nil, err)
	}
	return &user.Email, credential.Value, nil
}

func (a *emailAuthImpl) handleSignup(requestCreds *emailCreds, storageCreds *emailCreds, appID string, orgID string) (*emailCreds, error) {
	if storageCreds != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAuthCred, nil, errors.New("email already in use"))
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(requestCreds.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCompute, model.TypeAuthCred, nil, errors.New("failed to generate hash from password"))
	}
	newCreds := emailCreds{}
	newCreds.Email = requestCreds.Email
	code, err := utils.GenerateRandomString(64)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCompute, model.TypeAuthCred, nil, errors.New("failed to generate random string for verify code"))

	}
	newCreds.VerificationCode = code
	newCreds.Password = string(hashedPassword)
	newCreds.VerificationExpiry = time.Now().Add(time.Hour * 24)
	if err = a.sendVerificationCode(newCreds.Email, newCreds.VerificationCode, appID, orgID); err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAuthCred, nil, errors.New("failed to send verification email for user"))
	}
	return &newCreds, nil
}

func (a *emailAuthImpl) handleSignin(requestCreds *emailCreds, storageCreds *emailCreds) error {
	if storageCreds == nil {
		return errors.WrapErrorAction(logutils.ActionValidate, model.TypeAuthCred, nil, errors.New("no credentials found in storage"))
	}
	if err := bcrypt.CompareHashAndPassword([]byte(storageCreds.Password), []byte(requestCreds.Password)); err != nil {
		return errors.WrapErrorAction(logutils.ActionValidate, model.TypeAuthCred, nil, err)
	}
	return nil
}

func (a *emailAuthImpl) sendVerificationCode(email string, verificationCode string, appID string, orgID string) error {
	verificationLink := a.auth.host + fmt.Sprintf("/auth/verify/%v/%v/%v/%v/%v", a.authType, email, verificationCode, appID, orgID)
	return a.auth.sendEmail(email, "Verify your email", "Please click the link below to verify your email:\n"+verificationLink, "")
}

//TODO: To be used in password reset flow
// func (a *emailAuthImpl) sendPasswordReset(email string, password string) error {
// 	return a.auth.SendEmail(email, "Password Reset", "Your temporary password is "+password, "")
// }

func (a *emailAuthImpl) verify(accountAuthType *model.AccountAuthType, id string, verification string, l *logs.Log) error {
	credID := accountAuthType.Credential.ID
	credential, err := a.auth.storage.FindCredentialByID(credID)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeCredential, nil, errors.New("no credentials found in storage"))
	}

	credBytes, err := json.Marshal(credential.Value)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionMarshal, typeEmailCreds, nil, err)
	}

	var creds *emailCreds
	err = json.Unmarshal(credBytes, &creds)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUnmarshal, typeEmailCreds, nil, err)
	}
	err = a.compareVerifyCode(creds.VerificationCode, verification, creds.VerificationExpiry, l)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionValidate, model.TypeAuthCred, &logutils.FieldArgs{"verification_code": verification}, errors.New("invalid verification code"))
	}
	//Update verification data
	creds.VerificationCode = ""
	creds.VerificationExpiry = time.Time{}
	credsMap, err := emailCredsToMap(creds)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionCast, typeEmailCreds, nil, err)
	}
	credential.Value = credsMap
	credential.Verified = true

	if err = a.auth.storage.UpdateCredential(credential); err != nil {
		return err
	}
	return nil
}

func (a *emailAuthImpl) compareVerifyCode(credCode string, requestCode string, expiryTime time.Time, l *logs.Log) error {
	if expiryTime.Before(time.Now()) {
		return errors.WrapErrorAction(logutils.ActionValidate, typeTime, nil, errors.New("verification code has expired"))
	}

	if credCode != requestCode {
		return errors.WrapErrorAction(logutils.ActionValidate, typeTime, nil, errors.New("Invalid verification code"))
	}
	return nil

}
func (a *emailAuthImpl) userExist(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, creds string, l *logs.Log) (*model.Account, *model.AccountAuthType, error) {
	appID := appOrg.Application.ID
	orgID := appOrg.Organization.ID
	authTypeID := authType.ID
	accountAuthTypeIdentifier := "silyana.y@inabyte.com" //TODO get it from the creds string

	account, err := a.auth.storage.FindAccount(appID, orgID, authTypeID, accountAuthTypeIdentifier)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err) //TODO add args..
	}

	accountAuthType, err := a.auth.FindAccountAuthType(account, authTypeID, accountAuthTypeIdentifier)
	if accountAuthType == nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccountAuthType, nil, err) //TODO add args..
	}

	return account, accountAuthType, nil
}

func emailCredsToMap(creds *emailCreds) (map[string]interface{}, error) {
	credBytes, err := json.Marshal(creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionMarshal, model.TypeAuthCred, nil, err)
	}
	var credsMap map[string]interface{}
	err = json.Unmarshal(credBytes, &credsMap)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, model.TypeAuthCred, nil, err)
	}
	return credsMap, nil
}

func mapToEmailCreds(credsMap map[string]interface{}) (*emailCreds, error) {
	credBytes, err := json.Marshal(credsMap)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionMarshal, typeEmailCreds, nil, err)
	}
	var creds *emailCreds
	err = json.Unmarshal(credBytes, creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeEmailCreds, nil, err)
	}
	return creds, nil
}

//initEmailAuth initializes and registers a new email auth instance
func initEmailAuth(auth *Auth) (*emailAuthImpl, error) {
	email := &emailAuthImpl{auth: auth, authType: authTypeEmail}

	err := auth.registerAuthType(email.authType, email)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeAuthType, nil, err)
	}

	return email, nil
}
