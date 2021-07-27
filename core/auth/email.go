package auth

import (
	"core-building-block/core/model"
	"core-building-block/utils"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"

	log "github.com/rokmetro/logging-library/loglib"
)

// Email implementation of authType
type emailAuthImpl struct {
	auth *Auth
}

const (
	typeTime      log.LogData = "time.Time"
	typeCreds     log.LogData = "creds"
	authTypeEmail string      = "email"
)

//credentials represents the emailCreds struct for email auth
type emailCreds struct {
	Email              string    `json:"email" bson:"email" validate:"required"`
	Password           string    `json:"password" bson:"password"`
	IsVerified         bool      `json:"is_verified" bson:"is_verified"`
	VerificationCode   string    `json:"verification_code" bson:"verification_code" validate:"required"`
	VerificationExpiry time.Time `json:"verification_expiry" bson:"verification_expiry"`
}

func (a *emailAuthImpl) check(creds string, params string, l *log.Log) (*model.UserAuth, error) {
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
		errFields := log.FieldArgs{"org_id": "", "app_id": "", "type": authTypeEmail, "user_id": c.Email}
		l.LogAction(log.Warn, log.StatusError, log.ActionFind, model.TypeAuthCred, &errFields)
		return nil, fmt.Errorf("no credentials found: %s", err.Error())
	}

	credBytes, err := json.Marshal(authCreds.Creds)
	if err != nil {
		return nil, log.WrapActionError(log.ActionMarshal, model.TypeAuthCred, nil, err)
	}

	var user *emailCreds
	err = json.Unmarshal(credBytes, &user)
	if err != nil {
		return nil, log.WrapActionError(log.ActionUnmarshal, model.TypeAuthCred, nil, err)
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
		return nil, log.WrapActionError(log.ActionFind, typeCreds, nil, log.NewError("email already in use"))
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(requestCreds.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, log.WrapActionError(log.ActionCompute, typeCreds, nil, log.NewError("failed to generate hash from password"))
	}
	newCreds := emailCreds{}
	newCreds.Email = requestCreds.Email
	newCreds.VerificationCode = utils.RandSeq(8)
	newCreds.Password = string(hashedPassword)
	newCreds.VerificationExpiry = time.Now().Add(time.Hour * 24)
	if err = a.sendVerificationCode(newCreds.Email, newCreds.VerificationCode); err != nil {
		return nil, log.WrapActionError(log.ActionFind, typeCreds, nil, log.NewError("failed to send verification email for user"))
	}
	return &newCreds, nil
}

func (a *emailAuthImpl) handleSignin(requestCreds *emailCreds, storageCreds *emailCreds) error {
	if storageCreds == nil {
		return log.WrapActionError(log.ActionValidate, typeCreds, nil, log.NewError("no credentials found in storage"))
	}
	if err := bcrypt.CompareHashAndPassword([]byte(storageCreds.Password), []byte(requestCreds.Password)); err != nil {
		return log.WrapActionError(log.ActionValidate, typeCreds, nil, err)
	}
	return nil
}

func (a *emailAuthImpl) sendVerificationCode(email string, verificationCode string) error {
	return a.auth.SendEmail(email, "Verify your email", "Your verification code is "+verificationCode, "")
}

//TODO: To be used in password reset flow
// func (a *emailAuthImpl) sendPasswordReset(email string, password string) error {
// 	return a.auth.SendEmail(email, "Password Reset", "Your temporary password is "+password, "")
// }

func (a *emailAuthImpl) verify(id string, verification string, l *log.Log) error {
	authCreds, err := a.auth.storage.FindCredentials("", "", authTypeEmail, id)
	if err != nil {
		errFields := log.FieldArgs{"org_id": "", "app_id": "", "type": authTypeEmail, "user_id": id}
		l.LogAction(log.Warn, log.StatusError, log.ActionFind, model.TypeAuthCred, &errFields)
		return log.WrapActionError(log.ActionFind, typeCreds, nil, log.NewError("no credentials found in storage"))
	}

	credBytes, err := json.Marshal(authCreds.Creds)
	if err != nil {
		return log.WrapActionError(log.ActionMarshal, typeCreds, nil, err)
	}

	var creds *emailCreds
	err = json.Unmarshal(credBytes, &creds)
	if err != nil {
		return log.WrapActionError(log.ActionUnmarshal, typeCreds, nil, err)
	}
	valid, err := a.compareVerifyCode(creds.VerificationCode, verification, creds.VerificationExpiry, l)
	if err != nil {
		return err
	}
	if !valid {
		return log.WrapActionError(log.ActionValidate, typeCreds, &log.FieldArgs{"verification_code": verification}, log.NewError("invalid verification code"))
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

//Update these guys
func (a *emailAuthImpl) compareVerifyCode(credCode string, requestCode string, expiryTime time.Time, l *log.Log) (bool, error) {
	if expiryTime.Before(time.Now()) {
		return false, log.WrapActionError(log.ActionValidate, typeTime, nil, log.NewError("verification code has expired"))
	}

	if credCode != requestCode {
		return false, nil
	}
	return true, nil

}

//initEmailAuth initializes and registers a new email auth instance
func initEmailAuth(auth *Auth) (*emailAuthImpl, error) {
	email := &emailAuthImpl{auth: auth}

	err := auth.registerAuthType("email", email)
	if err != nil {
		return nil, log.WrapActionError(log.ActionRegister, typeAuthType, nil, err)
	}

	return email, nil
}
