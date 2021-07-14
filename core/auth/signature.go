package auth

import (
	"errors"
)

//Signature implementation of authType
type signatureAuthImpl struct {
	auth *Auth
}

func (a *signatureAuthImpl) check(creds string, params string) (*UserAuth, error) {
	//TODO: Implement
	return nil, errors.New("Unimplemented")
}

//initSignatureAuth initializes and registers a new stignature auth instance
func initSignatureAuth(auth *Auth) (*signatureAuthImpl, error) {
	signature := &signatureAuthImpl{auth: auth}

	err := auth.registerAuthType("signature", signature)
	if err != nil {
		return nil, err
	}

	return signature, nil
}
