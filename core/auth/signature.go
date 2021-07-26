package auth

import (
	"core-building-block/core/model"

	log "github.com/rokmetro/logging-library/loglib"
)

const (
	authTypeSignature string = "signature"
)

//Signature implementation of authType
type signatureAuthImpl struct {
	auth *Auth
}

func (a *signatureAuthImpl) check(creds string, params string, l *log.Log) (*model.UserAuth, error) {
	//TODO: Implement
	return nil, log.NewError(log.Unimplemented)
}

func (a *signatureAuthImpl) refresh(refreshToken string, l *log.Log) (*model.UserAuth, error) {
	return nil, log.NewErrorf("refresh operation invalid for auth_type=%s", authTypeSignature)
}

//initSignatureAuth initializes and registers a new signature auth instance
func initSignatureAuth(auth *Auth) (*signatureAuthImpl, error) {
	signature := &signatureAuthImpl{auth: auth}

	err := auth.registerAuthType(authTypeSignature, signature)
	if err != nil {
		return nil, log.WrapActionError(log.ActionRegister, typeAuthType, nil, err)
	}

	return signature, nil
}
