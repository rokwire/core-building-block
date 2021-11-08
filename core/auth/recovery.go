package auth

import (
	"core-building-block/core/model"
	"core-building-block/driven/storage"
	"core-building-block/utils"
	"encoding/json"
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

func (m *recoveryMfaImpl) verify(context storage.TransactionContext, mfa *model.MFAType, accountID string, code string) (*string, error) {
	if mfa == nil || mfa.Params == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, "mfa params", nil)
	}

	var codes []string
	data, err := json.Marshal(mfa.Params["codes"])
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionMarshal, "stored recovery codes", nil, err)
	}
	err = json.Unmarshal(data, &codes)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, "stored recovery codes", nil, err)
	}

	if len(codes) == 0 {
		message := "no valid codes"
		return &message, errors.ErrorData(logutils.StatusMissing, "recovery codes", nil)
	}

	for i, rc := range codes {
		if code == rc {
			mfa.Params["codes"] = append(codes[:i], codes[i+1:]...)
			now := time.Now().UTC()
			mfa.DateUpdated = &now

			err := m.auth.storage.UpdateMFAType(context, mfa, accountID)
			if err != nil {
				return nil, errors.WrapErrorAction(logutils.ActionUpdate, model.TypeMFAType, &logutils.FieldArgs{"account_id": accountID, "id": mfa.ID}, err)
			}
			return nil, nil
		}
	}

	message := "invalid code"
	return &message, errors.ErrorData(logutils.StatusInvalid, "recovery code", nil)
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

	params := map[string]interface{}{
		"identifier": identifier,
		"codes":      codes,
	}

	id, _ := uuid.NewUUID()
	return &model.MFAType{ID: id.String(), Type: MfaTypeRecovery, Verified: true, Params: params, DateCreated: time.Now().UTC()}, nil
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
