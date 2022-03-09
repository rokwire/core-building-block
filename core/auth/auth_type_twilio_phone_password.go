package auth

import (
	"core-building-block/core/model"
	"core-building-block/utils"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
	"golang.org/x/crypto/bcrypt"
)

const (
	//AuthTypePhone phone auth type
	AuthPhoneEmail string = "phone"

	//typeTime              logutils.MessageDataType = "time.Time"
	typeTwilioPhoneCreds  logutils.MessageDataType = "phone creds"
	typeTwilioPhoneParams logutils.MessageDataType = "phone params"
)

//phoneCreds represents the creds struct for phone auth
type phoneCreds struct {
	Phone              string    `json:"phone" bson:"" validate:"required"`
	Password           string    `json:"password" bson:"password"`
	VerificationCode   string    `json:"verification_code" bson:"verification_code"`
	VerificationExpiry time.Time `json:"verification_expiry" bson:"verification_expiry"`
	ResetCode          string    `json:"reset_code" bson:"reset_code"`
	ResetExpiry        time.Time `json:"reset_expiry" bson:"reset_expiry"`
}

// Phone implementation of authType
type phoneAuthImpl struct {
	auth     *Auth
	authType string
}

func (a *phoneAuthImpl) signUp(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, creds string, params string, newCredentialID string, l *logs.Log) (string, map[string]interface{}, error) {
	type signUpPhoneParams struct {
		ConfirmPassword string `json:"confirm_password"`
	}

	var sPhoneCreds phoneCreds
	err := json.Unmarshal([]byte(creds), &sPhoneCreds)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeTwilioPhoneCreds, nil, err)
	}

	var sPhoneParams signUpPhoneParams
	err = json.Unmarshal([]byte(params), &sPhoneParams)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeTwilioPhoneParams, nil, err)
	}

	phone := sPhoneCreds.Phone
	password := sPhoneCreds.Password
	confirmPassword := sPhoneParams.ConfirmPassword
	if len(phone) == 0 {
		return "", nil, errors.ErrorData(logutils.StatusMissing, typeTwilioPhoneCreds, logutils.StringArgs("phone"))
	}
	if len(password) == 0 {
		return "", nil, errors.ErrorData(logutils.StatusMissing, typeTwilioPhoneParams, logutils.StringArgs("password"))
	}
	if len(confirmPassword) == 0 {
		return "", nil, errors.ErrorData(logutils.StatusMissing, typeTwilioPhoneParams, logutils.StringArgs("confirm_password"))
	}
	//check if the passwrod matches with the confirm password one
	if password != confirmPassword {
		return "", nil, errors.WrapErrorAction("passwords fields do not match", "", nil, err)
	}

	//password hash
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionCompute, model.TypeAuthCred, nil, errors.New("failed to generate hash from password"))
	}

	//verification code
	code, err := utils.GenerateRandomString(64)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionCompute, model.TypeAuthCred, nil, errors.New("failed to generate random string for verify code"))
	}

	verifyPhone := a.getVerifyPhone(authType)
	verifyExpiryTime := a.getVerifyExpiry(authType)

	var phoneCredValue phoneCreds
	if verifyPhone {
		phoneCredValue = phoneCreds{Phone: phone, Password: string(hashedPassword), VerificationCode: code, VerificationExpiry: time.Now().Add(time.Hour * time.Duration(verifyExpiryTime))}
	} else {
		phoneCredValue = phoneCreds{Phone: phone, Password: string(hashedPassword)}
	}

	phoneCredValueMap, err := phoneCredsToMap(&phoneCredValue)
	if err != nil {
		return "", nil, errors.WrapErrorAction("failed phone params to map", "", nil, err)
	}

	if verifyPhone {
		//send verification code
		if err = a.sendVerificationCode(phone, code, newCredentialID); err != nil {
			return "", nil, errors.WrapErrorAction(logutils.ActionSend, "verification phone number", nil, err)
		}
	}

	return "verification code sent successfully", phoneCredValueMap, nil
}

func (a *phoneAuthImpl) isCredentialVerified(credential *model.Credential, l *logs.Log) (*bool, *bool, error) {
	if credential.Verified {
		verified := true
		return &verified, nil, nil
	}

	//check if phone verification is off
	verifyPhone := a.getVerifyPhone(credential.AuthType)
	if !verifyPhone {
		verified := true
		return &verified, nil, nil
	}

	//it is unverified
	verified := false
	//check if the verification is expired
	storedCreds, err := mapToPhoneCreds(credential.Value)
	if err != nil {
		return nil, nil, errors.WrapErrorAction("error on map to email creds when checking is credential verified", "", nil, err)
	}
	expired := false
	if storedCreds.VerificationExpiry.Before(time.Now()) {
		expired = true
	}
	return &verified, &expired, nil
}

func (a *phoneAuthImpl) checkCredentials(accountAuthType model.AccountAuthType, creds string, l *logs.Log) (string, error) {
	//get stored credential
	storedCreds, err := mapToPhoneCreds(accountAuthType.Credential.Value)
	if err != nil {
		return "", errors.WrapErrorAction("error on map to phone creds", "", nil, err)
	}

	//get request credential
	type signInPasswordCred struct {
		Password string `json:"password"`
	}
	var sPasswordParams signInPasswordCred
	err = json.Unmarshal([]byte(creds), &sPasswordParams)
	if err != nil {
		return "", errors.WrapErrorAction("error getting sign_in password creds", "", nil, err)
	}
	requestPassword := sPasswordParams.Password

	//compare stored and requets ones
	err = bcrypt.CompareHashAndPassword([]byte(storedCreds.Password), []byte(requestPassword))
	if err != nil {
		return "", errors.WrapErrorAction("bad credentials", "", nil, err).SetStatus(utils.ErrorStatusInvalid)
	}

	return "", nil
}

func (a *phoneAuthImpl) getVerifyPhone(authType model.AuthType) bool {
	verifyPhone := true
	verifyPhoneParam, ok := authType.Params["verify_phone"].(bool)
	if ok {
		verifyPhone = verifyPhoneParam
	}
	return verifyPhone
}

//Time in seconds to wait before sending another verification email
func (a *phoneAuthImpl) getVerifyWaitTime(authType model.AuthType) int {
	//Default is 30 seconds
	verifyWaitTime := 30
	verifyWaitTimeParam, ok := authType.Params["verify_wait_time"].(int)
	if ok {
		verifyWaitTime = verifyWaitTimeParam
	}
	return verifyWaitTime
}

//Time in hours before verification code expires
func (a *phoneAuthImpl) getVerifyExpiry(authType model.AuthType) int {
	//Default is 24 hours
	verifyExpiry := 24
	verifyExpiryParam, ok := authType.Params["verify_expiry"].(int)
	if ok {
		verifyExpiry = verifyExpiryParam
	}
	return verifyExpiry
}

func (a *phoneAuthImpl) sendVerificationCode(phone string, verificationCode string, credentialID string) error {
	params := url.Values{}
	params.Add("id", credentialID)
	params.Add("code", verificationCode)

	verificationLink := a.auth.host + fmt.Sprintf("/services/auth/credential/verify?%s", params.Encode())

	return a.auth.phone.Send(phone, "Verify your phone number", "Please click the link below to verify your phone number:\n"+verificationLink+"\n\nIf you did not request this verification link, please ignore this message.", nil)
}

func (a *phoneAuthImpl) sendPasswordResetPhone(credentialID string, resetCode string, phone string) error {
	params := url.Values{}
	params.Add("id", credentialID)
	params.Add("code", resetCode)
	passwordResetLink := a.auth.host + fmt.Sprintf("/ui/reset-credential?%s", params.Encode())
	return a.auth.phone.Send(phone, "Password Reset", "Please click the link below to reset your password:\n"+passwordResetLink+"\n\nIf you did not request a password reset, please ignore this message.", nil)
}

func (a *phoneAuthImpl) verifyCredential(credential *model.Credential, verification string, l *logs.Log) (map[string]interface{}, error) {
	credBytes, err := json.Marshal(credential.Value)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionMarshal, typeTwilioPhoneCreds, nil, err)
	}

	var creds *phoneCreds
	err = json.Unmarshal(credBytes, &creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeTwilioPhoneCreds, nil, err)
	}
	err = a.compareCode(creds.VerificationCode, verification, creds.VerificationExpiry, l)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionValidate, model.TypeAuthCred, &logutils.FieldArgs{"verification_code": verification}, errors.New("invalid verification code"))
	}

	//Update verification data
	creds.VerificationCode = ""
	creds.VerificationExpiry = time.Time{}
	credsMap, err := phoneCredsToMap(creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCast, typeEmailCreds, nil, err)
	}

	return credsMap, nil
}

func (a *phoneAuthImpl) sendVerifyCredential(credential *model.Credential, l *logs.Log) error {
	//Check if verify phone number is disabled for the given authType
	authType := credential.AuthType
	verifyPhone := a.getVerifyPhone(authType)
	if !verifyPhone {
		return errors.ErrorAction(logutils.ActionSend, logutils.TypeString, logutils.StringArgs("verify phone number is disabled for authType"))
	}
	verifyWaitTime := a.getVerifyWaitTime(authType)
	verifyExpiryTime := a.getVerifyExpiry(authType)

	//Parse credential value to phoneCreds
	phoneCreds, err := mapToPhoneCreds(credential.Value)
	if err != nil {
		return errors.WrapErrorAction("error on map to phone creds", "", nil, err)
	}
	//Check if previous verification phone number was sent less than 30 seconds ago
	now := time.Now()
	prevTime := phoneCreds.VerificationExpiry.Add(time.Duration(-verifyExpiryTime) * time.Hour)
	if now.Sub(prevTime) < time.Duration(verifyWaitTime)*time.Second {
		return errors.ErrorAction(logutils.ActionSend, "verify code", logutils.StringArgs("resend requested too soon"))
	}
	//verification code
	code, err := utils.GenerateRandomString(64)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionCompute, model.TypeAuthCred, nil, errors.New("failed to generate random string for verify code"))
	}

	//send verification email
	if err = a.sendVerificationCode(phoneCreds.Phone, code, credential.ID); err != nil {
		return errors.WrapErrorAction(logutils.ActionSend, "verification phone number", nil, err)
	}

	//Update verification data in credential value
	phoneCreds.VerificationCode = code
	phoneCreds.VerificationExpiry = time.Now().Add(time.Hour * time.Duration(verifyExpiryTime))
	credsMap, err := phoneCredsToMap(phoneCreds)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionCast, typeTwilioPhoneCreds, nil, err)
	}

	credential.Value = credsMap
	if err = a.auth.storage.UpdateCredential(nil, credential); err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeCredential, nil, err)
	}

	return nil
}

func (a *phoneAuthImpl) restartCredentialVerification(credential *model.Credential, l *logs.Log) error {
	storedCreds, err := mapToPhoneCreds(credential.Value)
	if err != nil {
		return errors.WrapErrorAction("error on map to phone creds when checking is credential verified", "", nil, err)
	}
	//Generate new verification code
	newCode, err := utils.GenerateRandomString(64)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionCompute, model.TypeAuthCred, nil, errors.New("failed to generate random string for verify code"))

	}
	//send new verification code for future
	if err = a.sendVerificationCode(storedCreds.Phone, newCode, credential.ID); err != nil {
		return errors.WrapErrorAction(logutils.ActionSend, "verification phone number", nil, err)
	}
	//update new verification data in credential value
	storedCreds.VerificationCode = newCode
	storedCreds.VerificationExpiry = time.Now().Add(time.Hour * 24)
	phoneCredValueMap, err := phoneCredsToMap(storedCreds)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionCast, typeTwilioPhoneCreds, nil, err)
	}

	err = a.auth.storage.UpdateCredentialValue(credential.ID, phoneCredValueMap)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeCredential, nil, err)
	}
	return nil
}

func (a *phoneAuthImpl) compareCode(credCode string, requestCode string, expiryTime time.Time, l *logs.Log) error {
	if expiryTime.Before(time.Now()) {
		return errors.New("Code has expired")
	}

	if subtle.ConstantTimeCompare([]byte(credCode), []byte(requestCode)) == 0 {
		return errors.ErrorData(logutils.StatusInvalid, "Invalid code", nil)
	}
	return nil
}

func (a *phoneAuthImpl) resetCredential(credential *model.Credential, resetCode *string, params string, l *logs.Log) (map[string]interface{}, error) {
	//get the data from params
	type Params struct {
		NewPassword     string `json:"new_password"`
		ConfirmPassword string `json:"confirm_password"`
	}

	var paramsData Params
	err := json.Unmarshal([]byte(params), &paramsData)
	if err != nil {
		return nil, errors.New("error parsing new_password and confirm_password")
	}
	newPassword := paramsData.NewPassword
	confirmPassword := paramsData.ConfirmPassword

	if len(newPassword) == 0 {
		return nil, errors.ErrorData(logutils.StatusMissing, logutils.TypeString, logutils.StringArgs("new_password"))
	}
	if len(confirmPassword) == 0 {
		return nil, errors.ErrorData(logutils.StatusMissing, logutils.TypeString, logutils.StringArgs("confirm_password"))
	}
	//check if the password matches with the confirm password one
	if newPassword != confirmPassword {
		return nil, errors.New("passwords fields do not match")
	}

	credBytes, err := json.Marshal(credential.Value)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionMarshal, typeTwilioPhoneCreds, nil, err)
	}

	var creds *phoneCreds
	err = json.Unmarshal(credBytes, &creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeTwilioPhoneCreds, nil, err)
	}
	//reset password from link
	if resetCode != nil {
		if creds.ResetExpiry.Before(time.Now()) {
			return nil, errors.WrapErrorAction(logutils.ActionValidate, typeTime, nil, errors.New("reset code has expired"))
		}
		err = bcrypt.CompareHashAndPassword([]byte(creds.ResetCode), []byte(*resetCode))
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionValidate, model.TypeAuthCred, &logutils.FieldArgs{"reset_code": *resetCode}, errors.New("invalid reset code"))
		}

		//Update verification data
		creds.ResetCode = ""
		creds.ResetExpiry = time.Time{}
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCompute, model.TypeAuthCred, nil, errors.New("failed to generate hash from new password"))
	}

	//Update verification data
	creds.Password = string(hashedPassword)
	credsMap, err := phoneCredsToMap(creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCast, typeTwilioPhoneCreds, nil, err)
	}

	return credsMap, nil
}

func (a *phoneAuthImpl) forgotCredential(credential *model.Credential, identifier string, l *logs.Log) (map[string]interface{}, error) {
	phoneCreds, err := mapToPhoneCreds(credential.Value)
	if err != nil {
		return nil, errors.WrapErrorAction("error on map to phone creds", "", nil, err)
	}
	resetCode, err := utils.GenerateRandomString(64)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCompute, logutils.TypeString, nil, errors.New("failed to generate random string for reset code"))

	}
	hashedResetCode, err := bcrypt.GenerateFromPassword([]byte(resetCode), bcrypt.DefaultCost)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCompute, logutils.TypeString, nil, errors.New("failed to generate hash from reset code"))
	}
	phoneCreds.ResetCode = string(hashedResetCode)
	phoneCreds.ResetExpiry = time.Now().Add(time.Hour * 24)
	err = a.sendPasswordResetPhone(credential.ID, resetCode, identifier)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionSend, logutils.TypeString, nil, err)
	}
	credsMap, err := phoneCredsToMap(phoneCreds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCast, typeTwilioPhoneCreds, nil, err)
	}
	return credsMap, nil
}

func (a *phoneAuthImpl) getUserIdentifier(creds string) (string, error) {
	var requestCreds phoneCreds
	err := json.Unmarshal([]byte(creds), &requestCreds)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionUnmarshal, typeTwilioPhoneCreds, nil, err)
	}

	return requestCreds.Phone, nil
}

func phoneCredsToMap(creds *phoneCreds) (map[string]interface{}, error) {
	credBytes, err := json.Marshal(creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionMarshal, model.TypeAuthCred, nil, err)
	}
	var credsMap map[string]interface{}
	err = json.Unmarshal(credBytes, &credsMap)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, model.TypeAuthCred, nil, err)
	}
	return credsMap, nil
}

func mapToPhoneCreds(credsMap map[string]interface{}) (*phoneCreds, error) {
	credBytes, err := json.Marshal(credsMap)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionMarshal, typeTwilioPhoneCreds, nil, err)
	}
	var creds phoneCreds
	err = json.Unmarshal(credBytes, &creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeTwilioPhoneCreds, nil, err)
	}
	return &creds, nil
}

//initTwilioPhoneAuth initializes and registers a new phone auth instance
func initTwilioPhoneAuth(auth *Auth) (*phoneAuthImpl, error) {
	phone := &phoneAuthImpl{auth: auth, authType: AuthTypeEmail}

	err := auth.registerAuthType(phone.authType, phone)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeAuthType, nil, err)
	}

	return phone, nil
}
