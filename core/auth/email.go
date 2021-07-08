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

	user, err := a.auth.storage.GetEmailCredential(c.Email)
	if err != nil {
		return nil, errors.New("failed to get user credentials")
	}
	if user == nil {
		//Handle sign up
		if c.NewUser {
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(c.Password), bcrypt.DefaultCost)
			if err != nil {
				return nil, errors.New("failed to generate hash from password")
			}
			err = a.auth.storage.SetEmailCredential(c.Email, string(hashedPassword))
			if err != nil {
				return nil, errors.New("failed to store credentials to DB")
			}
			return &Claims{Email: c.Email}, nil
		} else {
			return nil, errors.New("no user credentials found")
		}
	} else if c.NewUser {
		return nil, errors.New("email already in use")
	}

	if err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(c.Password)); err != nil {
		return nil, errors.New("invalid password")
	}
	claims := &Claims{ID: c.Email, Email: c.Email}
	return claims, nil
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
