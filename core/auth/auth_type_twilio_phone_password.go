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
	//AuthTypePhonePassword phone_password auth type
	AuthTypePhonePassword string = "twilio_phone_password"

	typePhonePasswordTime   logutils.MessageDataType = "time.Time"
	typePhonePasswordCreds  logutils.MessageDataType = "twilio_phone_password creds"
	typePhonePasswordParams logutils.MessageDataType = "twilio_phone_password  params"
)

//phonePasswordCreds represents the creds struct for phone_password auth
type phonePasswordCreds struct {
	PhonePassword      string    `json:"phone_password" bson:"phone_password" validate:"required"`
	Code               string    `json:"code"`
	Password           string    `json:"password" bson:"password"`
	VerificationCode   string    `json:"verification_code" bson:"verification_code"`
	VerificationExpiry time.Time `json:"verification_expiry" bson:"verification_expiry"`
	ResetCode          string    `json:"reset_code" bson:"reset_code"`
	ResetExpiry        time.Time `json:"reset_expiry" bson:"reset_expiry"`
}

// Phone_password implementation of authType
type twilioPhonePasswordAuthImpl struct {
	auth     *Auth
	authType string
}

func (a *twilioPhonePasswordAuthImpl) signUp(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, creds string, params string, newCredentialID string, l *logs.Log) (string, map[string]interface{}, error) {
	type signUpPhonePasswordParams struct {
		ConfirmPassword string `json:"confirm_password"`
	}

	var sPhonePasswordCreds phonePasswordCreds
	err := json.Unmarshal([]byte(creds), &sPhonePasswordCreds)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typePhonePasswordCreds, nil, err)
	}

	var sPhonePasswordParams signUpPhonePasswordParams
	err = json.Unmarshal([]byte(params), &sPhonePasswordParams)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typePhonePasswordParams, nil, err)
	}

	phonePassword := sPhonePasswordCreds.PhonePassword
	password := sPhonePasswordCreds.Password
	confirmPassword := sPhonePasswordParams.ConfirmPassword
	if len(phonePassword) == 0 {
		return "", nil, errors.ErrorData(logutils.StatusMissing, typePhonePasswordCreds, logutils.StringArgs("phone_password"))
	}
	if len(password) == 0 {
		return "", nil, errors.ErrorData(logutils.StatusMissing, typePhonePasswordCreds, logutils.StringArgs("password"))
	}
	if len(confirmPassword) == 0 {
		return "", nil, errors.ErrorData(logutils.StatusMissing, typePhonePasswordParams, logutils.StringArgs("confirm_password"))
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

	verifyPhonePassword := a.getVerifyPhonePassword(authType)
	verifyExpiryTime := a.getVerifyExpiry(authType)

	var phonePasswordCredValue phonePasswordCreds
	if verifyPhonePassword {
		phonePasswordCredValue = phonePasswordCreds{PhonePassword: phonePassword, Password: string(hashedPassword), VerificationCode: code, VerificationExpiry: time.Now().Add(time.Hour * time.Duration(verifyExpiryTime))}
	} else {
		phonePasswordCredValue = phonePasswordCreds{PhonePassword: phonePassword, Password: string(hashedPassword)}
	}

	phonePasswordCredValueMap, err := phonePasswordCredsToMap(&phonePasswordCredValue)
	if err != nil {
		return "", nil, errors.WrapErrorAction("failed phone_password params to map", "", nil, err)
	}

	if verifyPhonePassword {
		//send verification code
		if _, err = a.sendVerificationCode(sPhonePasswordCreds.PhonePassword, code, newCredentialID); err != nil {
			return "", nil, errors.WrapErrorAction(logutils.ActionSend, "verification phone_password", nil, err)
		}
	}

	return "verification code sent successfully", phonePasswordCredValueMap, nil
}

func (a *twilioPhonePasswordAuthImpl) isCredentialVerified(credential *model.Credential, l *logs.Log) (*bool, *bool, error) {
	if credential.Verified {
		verified := true
		return &verified, nil, nil
	}

	//check if phone_password verification is off
	verifyPhonePassword := a.getVerifyPhonePassword(credential.AuthType)
	if !verifyPhonePassword {
		verified := true
		return &verified, nil, nil
	}

	//it is unverified
	verified := false
	//check if the verification is expired
	storedCreds, err := mapToPhonePasswordCreds(credential.Value)
	if err != nil {
		return nil, nil, errors.WrapErrorAction("error on map to phone_password creds when checking is credential verified", "", nil, err)
	}
	expired := false
	if storedCreds.VerificationExpiry.Before(time.Now()) {
		expired = true
	}
	return &verified, &expired, nil
}

func (a *twilioPhonePasswordAuthImpl) checkCredentials(accountAuthType model.AccountAuthType, creds string, l *logs.Log) (string, error) {
	//get stored credential
	storedCreds, err := mapToPhonePasswordCreds(accountAuthType.Credential.Value)
	if err != nil {
		return "", errors.WrapErrorAction("error on map to phone_password creds", "", nil, err)
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

func (a *twilioPhonePasswordAuthImpl) getVerifyPhonePassword(authType model.AuthType) bool {
	verifyPhonePassword := true
	verifyPhonePasswordParam, ok := authType.Params["verify_phone_password"].(bool)
	if ok {
		verifyPhonePassword = verifyPhonePasswordParam
	}
	return verifyPhonePassword
}

//Time in seconds to wait before sending another verification phone_password
func (a *twilioPhonePasswordAuthImpl) getVerifyWaitTime(authType model.AuthType) int {
	//Default is 30 seconds
	verifyWaitTime := 30
	verifyWaitTimeParam, ok := authType.Params["verify_wait_time"].(int)
	if ok {
		verifyWaitTime = verifyWaitTimeParam
	}
	return verifyWaitTime
}

//Time in hours before verification code expires
func (a *twilioPhonePasswordAuthImpl) getVerifyExpiry(authType model.AuthType) int {
	//Default is 24 hours
	verifyExpiry := 24
	verifyExpiryParam, ok := authType.Params["verify_expiry"].(int)
	if ok {
		verifyExpiry = verifyExpiryParam
	}
	return verifyExpiry
}

func (a *twilioPhonePasswordAuthImpl) sendVerificationCode(phonePassword string, verificationCode string, credentialID string) (string, error) {
	params := url.Values{}
	params.Add("id", credentialID)
	params.Add("code", verificationCode)

	verificationLink := a.auth.host + fmt.Sprintf("/services/auth/credential/verify?%s", params.Encode())

	//return a.auth.emailer.Send(phonePassword, "Verify your phone_password address", "Please click the link below to verify your phone_password address:\n"+verificationLink+"\n\nIf you did not request this verification link, please ignore this message.", nil)
	return verificationLink, nil
}

/*func (a *twilioPhonePasswordAuthImpl) sendPasswordResetPhonePassword(credentialID string, resetCode string, phonePassword string) error {
	params := url.Values{}
	params.Add("id", credentialID)
	params.Add("code", resetCode)
	passwordResetLink := a.auth.host + fmt.Sprintf("/ui/reset-credential?%s", params.Encode())
	return a.auth.emailer.Send(phonePassword, "Password Reset", "Please click the link below to reset your password:\n"+passwordResetLink+"\n\nIf you did not request a password reset, please ignore this message.", nil)
}*/

func (a *twilioPhonePasswordAuthImpl) verifyCredential(credential *model.Credential, verification string, l *logs.Log) (map[string]interface{}, error) {
	credBytes, err := json.Marshal(credential.Value)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionMarshal, typePhonePasswordCreds, nil, err)
	}

	var creds *phonePasswordCreds
	err = json.Unmarshal(credBytes, &creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typePhonePasswordCreds, nil, err)
	}
	err = a.compareCode(creds.VerificationCode, verification, creds.VerificationExpiry, l)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionValidate, model.TypeAuthCred, &logutils.FieldArgs{"verification_code": verification}, errors.New("invalid verification code"))
	}

	//Update verification data
	creds.VerificationCode = ""
	creds.VerificationExpiry = time.Time{}
	credsMap, err := phonePasswordCredsToMap(creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCast, typePhonePasswordCreds, nil, err)
	}

	return credsMap, nil
}

func (a *twilioPhonePasswordAuthImpl) sendVerifyCredential(credential *model.Credential, l *logs.Log) error {
	//Check if verify phone_password is disabled for the given authType
	authType := credential.AuthType
	verifyPhonePassword := a.getVerifyPhonePassword(authType)
	if !verifyPhonePassword {
		return errors.ErrorAction(logutils.ActionSend, logutils.TypeString, logutils.StringArgs("verify phone_password is disabled for authType"))
	}
	verifyWaitTime := a.getVerifyWaitTime(authType)
	verifyExpiryTime := a.getVerifyExpiry(authType)

	//Parse credential value to phonePasswordCreds
	phonePasswordCreds, err := mapToPhonePasswordCreds(credential.Value)
	if err != nil {
		return errors.WrapErrorAction("error on map to phone_password creds", "", nil, err)
	}
	//Check if previous verification phone_password was sent less than 30 seconds ago
	now := time.Now()
	prevTime := phonePasswordCreds.VerificationExpiry.Add(time.Duration(-verifyExpiryTime) * time.Hour)
	if now.Sub(prevTime) < time.Duration(verifyWaitTime)*time.Second {
		return errors.ErrorAction(logutils.ActionSend, "verify code", logutils.StringArgs("resend requested too soon"))
	}
	//verification code
	code, err := utils.GenerateRandomString(64)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionCompute, model.TypeAuthCred, nil, errors.New("failed to generate random string for verify code"))
	}

	//send verification phone_password
	if _, err = a.sendVerificationCode(phonePasswordCreds.PhonePassword, code, credential.ID); err != nil {
		return errors.WrapErrorAction(logutils.ActionSend, "verification phone_password", nil, err)
	}

	//Update verification data in credential value
	phonePasswordCreds.VerificationCode = code
	phonePasswordCreds.VerificationExpiry = time.Now().Add(time.Hour * time.Duration(verifyExpiryTime))
	credsMap, err := phonePasswordCredsToMap(phonePasswordCreds)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionCast, typePhonePasswordCreds, nil, err)
	}

	credential.Value = credsMap
	if err = a.auth.storage.UpdateCredential(nil, credential); err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeCredential, nil, err)
	}

	return nil
}

func (a *twilioPhonePasswordAuthImpl) restartCredentialVerification(credential *model.Credential, l *logs.Log) error {
	storedCreds, err := mapToPhonePasswordCreds(credential.Value)
	if err != nil {
		return errors.WrapErrorAction("error on map to phone_password creds when checking is credential verified", "", nil, err)
	}
	//Generate new verification code
	newCode, err := utils.GenerateRandomString(64)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionCompute, model.TypeAuthCred, nil, errors.New("failed to generate random string for verify code"))

	}
	//send new verification code for future
	if _, err = a.sendVerificationCode(storedCreds.PhonePassword, newCode, credential.ID); err != nil {
		return errors.WrapErrorAction(logutils.ActionSend, "verification phone_password", nil, err)
	}
	//update new verification data in credential value
	storedCreds.VerificationCode = newCode
	storedCreds.VerificationExpiry = time.Now().Add(time.Hour * 24)
	phonePasswordCredValueMap, err := phonePasswordCredsToMap(storedCreds)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionCast, typePhonePasswordCreds, nil, err)
	}

	err = a.auth.storage.UpdateCredentialValue(credential.ID, phonePasswordCredValueMap)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeCredential, nil, err)
	}
	return nil
}

func (a *twilioPhonePasswordAuthImpl) compareCode(credCode string, requestCode string, expiryTime time.Time, l *logs.Log) error {
	if expiryTime.Before(time.Now()) {
		return errors.New("Code has expired")
	}

	if subtle.ConstantTimeCompare([]byte(credCode), []byte(requestCode)) == 0 {
		return errors.ErrorData(logutils.StatusInvalid, "Invalid code", nil)
	}
	return nil
}

func (a *twilioPhonePasswordAuthImpl) resetCredential(credential *model.Credential, resetCode *string, params string, l *logs.Log) (map[string]interface{}, error) {
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
		return nil, errors.WrapErrorAction(logutils.ActionMarshal, typePhonePasswordCreds, nil, err)
	}

	var creds *phonePasswordCreds
	err = json.Unmarshal(credBytes, &creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typePhonePasswordCreds, nil, err)
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
	credsMap, err := phonePasswordCredsToMap(creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCast, typePhonePasswordCreds, nil, err)
	}

	return credsMap, nil
}

func (a *twilioPhonePasswordAuthImpl) forgotCredential(credential *model.Credential, identifier string, l *logs.Log) (map[string]interface{}, error) {
	phonePasswordCreds, err := mapToPhonePasswordCreds(credential.Value)
	if err != nil {
		return nil, errors.WrapErrorAction("error on map to phone_password creds", "", nil, err)
	}
	resetCode, err := utils.GenerateRandomString(64)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCompute, logutils.TypeString, nil, errors.New("failed to generate random string for reset code"))

	}
	hashedResetCode, err := bcrypt.GenerateFromPassword([]byte(resetCode), bcrypt.DefaultCost)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCompute, logutils.TypeString, nil, errors.New("failed to generate hash from reset code"))
	}
	phonePasswordCreds.ResetCode = string(hashedResetCode)
	phonePasswordCreds.ResetExpiry = time.Now().Add(time.Hour * 24)
	/*err = a.sendPasswordResetPhonePassword(credential.ID, resetCode, identifier)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionSend, logutils.TypeString, nil, err)
	}*/
	credsMap, err := phonePasswordCredsToMap(phonePasswordCreds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCast, typePhonePasswordCreds, nil, err)
	}
	return credsMap, nil
}

func (a *twilioPhonePasswordAuthImpl) getUserIdentifier(creds string) (string, error) {
	var requestCreds phonePasswordCreds
	err := json.Unmarshal([]byte(creds), &requestCreds)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionUnmarshal, typePhonePasswordCreds, nil, err)
	}

	return requestCreds.PhonePassword, nil
}

func phonePasswordCredsToMap(creds *phonePasswordCreds) (map[string]interface{}, error) {
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

func mapToPhonePasswordCreds(credsMap map[string]interface{}) (*phonePasswordCreds, error) {
	credBytes, err := json.Marshal(credsMap)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionMarshal, typePhonePasswordCreds, nil, err)
	}
	var creds phonePasswordCreds
	err = json.Unmarshal(credBytes, &creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typePhonePasswordCreds, nil, err)
	}
	return &creds, nil
}

//initPhonePasswordAuth initializes and registers a new phone_password auth instance
func initPhonePasswordAuth(auth *Auth) (*twilioPhonePasswordAuthImpl, error) {
	phonePassword := &twilioPhonePasswordAuthImpl{auth: auth, authType: AuthTypePhonePassword}

	err := auth.registerAuthType(phonePassword.authType, phonePassword)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeAuthType, nil, err)
	}

	return phonePassword, nil
}
