package auth

import (
	"bytes"
	"core-building-block/core/model"
	"image/png"
	"time"

	"github.com/pquerna/otp/totp"
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

func (m *totpMfaImpl) verify(accountID string, code string) (*model.MFAType, error) {
	return nil, nil
}

func (m *totpMfaImpl) enroll(accountID string) (*model.MFAType, error) {
	totpOpts := totp.GenerateOpts{
		Issuer:      m.auth.host,
		AccountName: accountID, //TODO: should use some more readable string instead (email, phone, username, etc.)
	}
	key, err := totp.Generate(totpOpts)
	if err != nil {
		return nil, errors.WrapErrorAction("generate", "TOTP key", nil, err)
	}

	var buf bytes.Buffer
	image, err := key.Image(256, 256)
	if err != nil {
		return nil, errors.WrapErrorAction("generate", "TOTP image", nil, err)
	}
	err = png.Encode(&buf, image)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionEncode, "TOTP image", nil, err)
	}
	qrCode := buf.String()

	now := time.Now().UTC()
	params := map[string]interface{}{
		"secret": key.Secret(),
	}

	//Recipient is empty for totp
	return &model.MFAType{Type: MfaTypeTotp, Verified: false, QRCode: qrCode, Params: params, DateCreated: now}, nil
}

//sendCode not used for TOTP
func (m *totpMfaImpl) sendCode(accountID string) (string, error) {
	return "", nil
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
