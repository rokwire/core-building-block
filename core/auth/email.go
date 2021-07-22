package auth

import (
	"core-building-block/core/model"
	"core-building-block/utils"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/go-playground/validator.v9"
)

// Email implementation of authType
type emailAuthImpl struct {
	auth *Auth
}

//credentials represents the credential struct for email auth
type credential struct {
	Email              string    `json:"email" bson:"email" validate:"required"`
	Password           string    `json:"password" bson:"password"`
	IsVerified         bool      `json:"is_verified" bson:"is_verified"`
	VerificationCode   string    `json:"verification_code" bson:"verification_code" validate:"required"`
	VerificationExpiry time.Time `json:"verification_expiry" bson:"verification_expiry"`
}

func (a *emailAuthImpl) check(creds string, params string) (*model.UserAuth, error) {
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

//Handler for verify endpoint
func (a *emailAuthImpl) VerifyCodeHandler(w http.ResponseWriter, r *http.Request) {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error on marshalling credential - %s\n", err.Error())
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	var c credential
	err = json.Unmarshal(data, &c)
	if err != nil {
		log.Printf("Error on unmarshal the credential request data - %s\n", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	//validate
	validate := validator.New()
	err = validate.Struct(c)
	if err != nil {
		log.Printf("Error on validating credential data - %s\n", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err = a.verifyCode(&c); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Successfully verified code"))
}

func (a *emailAuthImpl) verifyCode(c *credential) error {
	credsFromDB, err := a.auth.storage.GetEmailCredential(c.Email)
	if err != nil {
		return errors.New("failed to fetch credential from DB")
	}
	valid, err := a.compareVerifyCode(credsFromDB, c)
	if err != nil {
		return err
	}
	if !valid {
		return errors.New("invalid code")
	}
	//Update verification data
	c.IsVerified = true
	c.VerificationCode = ""
	c.VerificationExpiry = time.Time{}
	if err = a.auth.storage.UpdateEmailCredential(c); err != nil {
		return err
	}
	return nil
}

func (a *emailAuthImpl) compareVerifyCode(actualCred *credential, requestCred *credential) (bool, error) {
	if actualCred.VerificationExpiry.Before(time.Now()) {
		return false, errors.New("verify code has expired")
	}

	if actualCred.VerificationCode != requestCred.VerificationCode {
		//log info
		return false, nil
	}
	return true, nil

}

//initEmailAuth initializes and registers a new email auth instance
func initEmailAuth(auth *Auth) (*emailAuthImpl, error) {
	email := &emailAuthImpl{auth: auth}

	err := auth.registerAuthType("email", email)
	if err != nil {
		return nil, err
	}

	return email, nil
}
