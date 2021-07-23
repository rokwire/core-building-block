package auth

import (
	"core-building-block/core/model"
	"core-building-block/utils"
	"encoding/json"
	"errors"
	"time"

	"golang.org/x/crypto/bcrypt"

	log "github.com/rokmetro/logging-library/loglib"
)

// Email implementation of authType
type emailAuthImpl struct {
	auth *Auth
}

const (
	typeTime  log.LogData = "time.Time"
	typeCreds log.LogData = "creds"
)

//credentials represents the credential struct for email auth
type credential struct {
	Email              string    `json:"email" bson:"email" validate:"required"`
	Password           string    `json:"password" bson:"password"`
	IsVerified         bool      `json:"is_verified" bson:"is_verified"`
	VerificationCode   string    `json:"verification_code" bson:"verification_code" validate:"required"`
	VerificationExpiry time.Time `json:"verification_expiry" bson:"verification_expiry"`
}

func (a *emailAuthImpl) check(creds string, params string, l *log.Log) (*model.UserAuth, error) {
	var c *credential
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

	user, err := a.auth.storage.GetEmailCredential(c.Email)
	if err != nil {
		return nil, errors.New("failed to get user credentials")
	}

	//Handle sign up
	if newUser {
		if err = a.handleSignup(c, user); err != nil {
			return nil, err
		}
		return &model.UserAuth{Email: c.Email}, nil
	}

	if err = a.handleSignin(c, user); err != nil {
		return nil, err
	}
	claims := &model.UserAuth{Email: c.Email}
	return claims, nil
}

func (a *emailAuthImpl) handleSignup(c *credential, user *credential) error {
	if user != nil {
		return errors.New("email already in use")
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(c.Password), bcrypt.DefaultCost)
	if err != nil {
		return errors.New("failed to generate hash from password")
	}

	c.VerificationCode = utils.RandSeq(8)
	c.Password = string(hashedPassword)
	c.VerificationExpiry = time.Now().Add(time.Hour * 24)
	if err = a.sendVerificationCode(c.Email, c.VerificationCode); err != nil {
		return errors.New("failed to send verification email for user")
	}
	err = a.auth.storage.CreateEmailCredential(c)
	if err != nil {
		return errors.New("failed to store credentials to DB")
	}
	return nil
}

func (a *emailAuthImpl) handleSignin(c *credential, user *credential) error {
	if user == nil {
		return errors.New("no user credentials found")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(c.Password)); err != nil {
		return errors.New("invalid password")
	}
	return nil
}

func (a *emailAuthImpl) sendVerificationCode(email string, verificationCode string) error {
	return a.auth.SendEmail(email, "Verify your email", "Your verification code is "+verificationCode, "")
}

func (a *emailAuthImpl) sendPasswordReset(email string, password string) error {
	return a.auth.SendEmail(email, "Password Reset", "Your temporary password is "+password, "")
}

func (a *emailAuthImpl) verify(id string, verification string, l *log.Log) error {
	creds, err := a.auth.storage.GetEmailCredential(id)
	if err != nil {
		return log.WrapActionError(log.ActionFind, typeCreds, nil, err)
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
	if err = a.auth.storage.UpdateEmailCredential(creds); err != nil {
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
