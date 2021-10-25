package auth

import (
	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logutils"
)

const (
	//MfaTypeTotp totp mfa type
	MfaTypeTotp string = "totp"
)

// TOTP implementation of mfaType
type totpMfaImpl struct {
	auth    *Auth
	mfaType string
}

func (m *totpMfaImpl) verify(code string) {

}

func (m *totpMfaImpl) enroll() {

}

func (m *totpMfaImpl) remove() {

}

//initTotpMfa initializes and registers a new totp mfa instance
func initTotpMfa(auth *Auth) (*totpMfaImpl, error) {
	totp := &totpMfaImpl{auth: auth, mfaType: MfaTypeTotp}

	err := auth.registerMfaType(totp.mfaType, totp)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeAuthType, nil, err)
	}

	return totp, nil
}
