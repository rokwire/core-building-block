package auth

import (
	"core-building-block/core/model"
	"encoding/json"
	"errors"

	"golang.org/x/crypto/bcrypt"
)

// Email implementation of authType
type emailAuthImpl struct {
	auth *Auth
}

func (a *emailAuthImpl) check(creds string, params string) (*Claims, error) {
	//TODO: Implement
	var c *model.Credential
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
		return &Claims{Email: c.Email}, nil
	}

	if err = a.handleSignin(c, user); err != nil {
		return nil, err
	}
	claims := &Claims{ID: c.Email, Email: c.Email}
	return claims, nil
}

func (a *emailAuthImpl) handleSignup(c *model.Credential, user *model.Credential) error {
	if user != nil {
		return errors.New("email already in use")
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(c.Password), bcrypt.DefaultCost)
	if err != nil {
		return errors.New("failed to generate hash from password")
	}
	err = a.auth.storage.SetEmailCredential(c.Email, string(hashedPassword))
	if err != nil {
		return errors.New("failed to store credentials to DB")
	}
	return nil
}

func (a *emailAuthImpl) handleSignin(c *model.Credential, user *model.Credential) error {
	if user == nil {
		return errors.New("no user credentials found")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(c.Password)); err != nil {
		return errors.New("invalid password")
	}
	return nil
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
