package auth

import log "github.com/rokmetro/logging-library/loglib"

//Signature implementation of authType
type signatureAuthImpl struct {
	auth *Auth
}

func (a *signatureAuthImpl) check(creds string, params string, l *log.Log) (*UserAuth, error) {
	//TODO: Implement
	return nil, log.NewError(log.Unimplemented)
}

//initSignatureAuth initializes and registers a new stignature auth instance
func initSignatureAuth(auth *Auth) (*signatureAuthImpl, error) {
	signature := &signatureAuthImpl{auth: auth}

	err := auth.registerAuthType("signature", signature)
	if err != nil {
		return nil, log.WrapActionError(log.RegisterAction, typeAuthType, nil, err)
	}

	return signature, nil
}
