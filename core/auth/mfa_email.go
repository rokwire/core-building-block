package auth

import (
	"core-building-block/core/model"
	"core-building-block/driven/storage"
	"core-building-block/utils"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logutils"
)

const (
	//MfaTypeEmail email mfa type
	MfaTypeEmail string = "email"
)

// Email implementation of mfaType
type emailMfaImpl struct {
	auth    *Auth
	mfaType string
}

func (m *emailMfaImpl) verify(context storage.TransactionContext, mfa *model.MFAType, accountID string, code string) (*string, error) {
	if mfa == nil || mfa.Params == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, "mfa params", nil)
	}

	var message string

	storedCode, ok := mfa.Params["code"].(string)
	if !ok {
		return nil, errors.ErrorData(logutils.StatusInvalid, "stored mfa code", nil)
	}
	if code != storedCode {
		message = "invalid code"
		return &message, errors.ErrorData(logutils.StatusInvalid, "mfa code", nil)
	}

	expiry, ok := mfa.Params["expires"].(time.Time)
	if !ok {
		return nil, errors.ErrorData(logutils.StatusInvalid, "stored expiry", nil)
	}
	if time.Now().UTC().After(expiry) {
		message = "expired code"
		return &message, errors.ErrorData(logutils.StatusInvalid, "expired code", nil)
	}

	//remove code and expiration from params in storage
	delete(mfa.Params, "code")
	delete(mfa.Params, "expires")
	err := m.auth.storage.UpdateMFAType(context, mfa, accountID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUpdate, model.TypeMFAType, nil, err)
	}

	return nil, nil
}

func (m *emailMfaImpl) enroll(identifier string) (*model.MFAType, error) {
	if identifier == "" {
		return nil, errors.ErrorData(logutils.StatusMissing, "identifier", nil)
	}

	//TODO: check identifier is valid email address

	params := map[string]interface{}{
		"identifier": identifier,
	}

	id, _ := uuid.NewUUID()
	return &model.MFAType{ID: id.String(), Type: MfaTypeEmail, Verified: false, Params: params, DateCreated: time.Now().UTC()}, nil
}

func (m *emailMfaImpl) sendCode(identifier string) (string, *time.Time, error) {
	code := fmt.Sprintf("%06d", utils.GenerateRandomInt(mfaCodeMax))
	expires := time.Now().Add(time.Duration(mfaCodeExpiration) * time.Minute)

	//TODO: send code to identifier, store both in DB

	return code, &expires, errors.New(logutils.Unimplemented)
}

//initEmailMfa initializes and registers a new email mfa instance
func initEmailMfa(auth *Auth) (*emailMfaImpl, error) {
	email := &emailMfaImpl{auth: auth, mfaType: MfaTypeEmail}

	err := auth.registerMfaType(email.mfaType, email)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeMfaType, nil, err)
	}

	return email, nil
}
