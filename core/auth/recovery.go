package auth

import (
	"core-building-block/core/model"
	"core-building-block/utils"
	"time"

	"github.com/google/uuid"
	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logutils"
)

const (
	//MfaTypeRecovery recovery mfa type
	MfaTypeRecovery string = "recovery"

	numCodes   int = 10
	codeLength int = 16
)

// Recovery implementation of mfaType
type recoveryMfaImpl struct {
	auth    *Auth
	mfaType string
}

func (m *recoveryMfaImpl) verify(params map[string]interface{}, code string) (*string, error) {
	var message string

	codes, ok := params["codes"].([]string)
	if !ok {
		return nil, errors.ErrorData(logutils.StatusInvalid, "stored recovery codes", nil)
	}
	//TODO: what happens if codes list is empty? -> maybe admin reset

	for _, rc := range codes {
		if code == rc {
			//TODO: update MFA type in storage by removing code
			return nil, nil
		}
	}

	message = "invalid code"
	return &message, errors.New(logutils.Unimplemented)
}

func (m *recoveryMfaImpl) enroll(identifier string) (*model.MFAType, error) {
	codes := make([]string, numCodes)
	for i := 0; i < numCodes; i++ {
		newCode, err := utils.GenerateRandomString(codeLength)
		if err != nil {
			return nil, errors.WrapErrorAction("generating", "recovery code", nil, err)
		}
		codes[i] = string(newCode)
	}

	now := time.Now().UTC()
	params := map[string]interface{}{
		"identifier": identifier,
		"codes":      codes,
	}

	id, _ := uuid.NewUUID()
	return &model.MFAType{ID: id.String(), Type: MfaTypeRecovery, Verified: true, Params: params, DateCreated: now}, nil
}

//sendCode not used for recovery
func (m *recoveryMfaImpl) sendCode(identifier string) (string, *time.Time, error) {
	return "", nil, errors.New(logutils.Unimplemented)
}

//initRecoveryMfa initializes and registers a new recovery mfa instance
func initRecoveryMfa(auth *Auth) (*recoveryMfaImpl, error) {
	recovery := &recoveryMfaImpl{auth: auth, mfaType: MfaTypeRecovery}

	err := auth.registerMfaType(recovery.mfaType, recovery)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeMfaType, nil, err)
	}

	return recovery, nil
}
