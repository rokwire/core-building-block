package auth

import (
	"core-building-block/core/model"

	log "github.com/rokmetro/logging-library/loglib"
)

//Signature implementation of authType
type signatureAuthImpl struct {
	auth *Auth
}

func (a *signatureAuthImpl) check(creds string, params string, l *log.Log) (*model.UserAuth, error) {
	//TODO: Implement
	return nil, log.NewError(log.Unimplemented)
}

func (a *signatureAuthImpl) set(userAuth *model.UserAuth, orgID string, appID string) (*model.AuthCred, error) {
	return nil, log.NewError(log.Unimplemented)
}

//initSignatureAuth initializes and registers a new stignature auth instance
func initSignatureAuth(auth *Auth) (*signatureAuthImpl, error) {
	signature := &signatureAuthImpl{auth: auth}

	err := auth.registerAuthType("signature", signature)
	if err != nil {
		return nil, log.WrapActionError(log.ActionRegister, typeAuthType, nil, err)
	}

	return signature, nil
}
