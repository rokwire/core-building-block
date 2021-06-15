package auth

import "errors"

// Phone implementation of authType
type phoneAuthImpl struct {
	auth *Auth
}

func (a *phoneAuthImpl) check(creds string) (*Claims, error) {
	//TODO: Implement
	return nil, errors.New("Unimplemented")
}

//initPhoneAuth initializes and registers a new phone auth instance
func initPhoneAuth(auth *Auth) (*phoneAuthImpl, error) {
	phone := &phoneAuthImpl{auth: auth}

	err := auth.registerAuthType("phone", phone)
	if err != nil {
		return nil, err
	}

	return phone, nil
}
