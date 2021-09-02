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
	typeTime      logutils.MessageDataType = "time.Time"
	authTypeEmail string                   = "email"
)

//credentials represents the emailCreds struct for email auth
type emailCreds struct {
	Email              string    `json:"email" bson:"email" validate:"required"`
	Password           string    `json:"password" bson:"password"`
	IsVerified         bool      `json:"is_verified" bson:"is_verified"`
	VerificationCode   string    `json:"verification_code" bson:"verification_code" validate:"required"`
	VerificationExpiry time.Time `json:"verification_expiry" bson:"verification_expiry"`
}

func (a *emailAuthImpl) check(creds string, orgID string, appID string, params string, l *logs.Log) (*model.UserAuth, error) {
	var c *emailCreds
	err := json.Unmarshal([]byte(creds), &c)
	if err != nil {
		return nil, err
	}
	paramsMap := make(map[string]interface{})
	err = json.Unmarshal([]byte(params), &paramsMap)
	if err != nil {
		return nil, err
	}
	newUser, ok := paramsMap["newUser"].(bool)
	if !ok {
		return nil, errors.New("newUser flag missing or invalid")
	}

	authCreds, err := a.auth.storage.FindCredentials("", "", authTypeEmail, c.Email)
	if err != nil {
		errFields := logutils.FieldArgs{"org_id": "", "app_id": "", "type": authTypeEmail, "user_id": c.Email}
		l.LogAction(logs.Warn, logutils.StatusError, logutils.ActionFind, model.TypeAuthCred, &errFields)
		return nil, fmt.Errorf("no credentials found: %s", err.Error())
	}

	credBytes, err := json.Marshal(authCreds.Creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionMarshal, model.TypeAuthCred, nil, err)
	}

	var user *emailCreds
	err = json.Unmarshal(credBytes, &user)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, model.TypeAuthCred, nil, err)
	}
	claims := &model.UserAuth{Email: c.Email, UserID: c.Email}
	//Handle sign up
	if newUser {
		newCreds, err := a.handleSignup(c, user)
		if err != nil {
			return nil, err
		}
		claims.NewCreds = newCreds
		return claims, nil
	}

	if err = a.handleSignin(c, user); err != nil {
		return nil, err
	}
	claims.AccountID = authCreds.AccountID
	return claims, nil
}

func (a *emailAuthImpl) handleSignup(requestCreds *emailCreds, storageCreds *emailCreds) (*emailCreds, error) {
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
	if err = a.sendVerificationCode(newCreds.Email, newCreds.VerificationCode); err != nil {
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

func (a *emailAuthImpl) sendVerificationCode(email string, verificationCode string) error {
	verificationLink := a.auth.host + fmt.Sprintf("/auth/verify/%v/%v/%v", "emailAuthImpl", email, verificationCode)
	return a.auth.sendEmail(email, "Verify your email", "Please click the link below to verify your email:\n"+verificationLink, "")
}

//TODO: To be used in password reset flow
// func (a *emailAuthImpl) sendPasswordReset(email string, password string) error {
// 	return a.auth.SendEmail(email, "Password Reset", "Your temporary password is "+password, "")
// }

func (a *emailAuthImpl) verify(id string, verification string, l *logs.Log) error {
	authCreds, err := a.auth.storage.FindCredentials("", "", authTypeEmail, id)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeAuthCred, nil, errors.New("no credentials found in storage"))
	}

	credBytes, err := json.Marshal(authCreds.Creds)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionMarshal, model.TypeAuthCred, nil, err)
	}

	var creds *emailCreds
	err = json.Unmarshal(credBytes, &creds)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUnmarshal, model.TypeAuthCred, nil, err)
	}
	err = a.compareVerifyCode(creds.VerificationCode, verification, creds.VerificationExpiry, l)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionValidate, model.TypeAuthCred, &logutils.FieldArgs{"verification_code": verification}, errors.New("invalid verification code"))
	}
	//Update verification data
	creds.IsVerified = true
	creds.VerificationCode = ""
	creds.VerificationExpiry = time.Time{}
	authCreds.Creds = creds
	if err = a.auth.storage.UpdateCredentials("", "", authTypeEmail, authCreds); err != nil {
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

//refresh is enabled for email auth, but no operation is needed
func (a *emailAuthImpl) refresh(refreshToken string, orgID string, appID string, l *logs.Log) (*model.UserAuth, error) {
	return nil, nil
}

func (a *emailAuthImpl) getLoginURL(orgID string, appID string, redirectURI string, l *logs.Log) (string, map[string]interface{}, error) {
	return "", nil, errors.Newf("get login url operation invalid for auth_type=%s", a.authType)
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
