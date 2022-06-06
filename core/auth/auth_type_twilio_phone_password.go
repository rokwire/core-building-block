package auth

import (
	"context"
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
	//AuthTypeEmail email auth type
	AuthTypePhonePassword string = "phone_password"

	typePPTime              logutils.MessageDataType = "time.Time"
	typePhonePasswordCreds  logutils.MessageDataType = "phonePassword creds"
	typePhonePasswordParams logutils.MessageDataType = "PhonePassword params"
	verificationsPPPathPart                          = "Verifications"
	verificationPPCheckPart                          = "VerificationCheck"
)

//phonePasswordCreds represents the creds struct for phonePassword auth
type phonePasswordCreds struct {
	Phone              string    `json:"phone" bson:"phone" validate:"required"`
	Password           string    `json:"password" bson:"password"`
	VerificationCode   string    `json:"verification_code" bson:"verification_code"`
	VerificationExpiry time.Time `json:"verification_expiry" bson:"verification_expiry"`
	ResetCode          string    `json:"reset_code" bson:"reset_code"`
	ResetExpiry        time.Time `json:"reset_expiry" bson:"reset_expiry"`
}

// PhonePasswordAuthImpl implementation of authType
type PhonePasswordAuthImpl struct {
	auth             *Auth
	authType         string
	twilioAccountSID string
	twilioToken      string
	twilioServiceSID string
}

func (a *PhonePasswordAuthImpl) signUp(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, creds string, params string, newCredentialID string, l *logs.Log) (string, map[string]interface{}, error) {
	type signUpPhonePasswordParams struct {
		ConfirmPassword string `json:"confirm_password"`
	}

	var sphonePasswordCreds phonePasswordCreds
	err := json.Unmarshal([]byte(creds), &sphonePasswordCreds)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typePhonePasswordCreds, nil, err)
	}

	var sPhonePasswordParams signUpPhonePasswordParams
	err = json.Unmarshal([]byte(params), &sPhonePasswordParams)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typePhonePasswordParams, nil, err)
	}

	phone := sphonePasswordCreds.Phone
	password := sphonePasswordCreds.Password
	confirmPassword := sPhonePasswordParams.ConfirmPassword
	if len(phone) == 0 {
		return "", nil, errors.ErrorData(logutils.StatusMissing, typePhonePasswordCreds, logutils.StringArgs("phone"))
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
		phonePasswordCredValue = phonePasswordCreds{Phone: phone, Password: string(hashedPassword), VerificationCode: code, VerificationExpiry: time.Now().Add(time.Hour * time.Duration(verifyExpiryTime))}
	} else {
		phonePasswordCredValue = phonePasswordCreds{Phone: phone, Password: string(hashedPassword)}
	}

	phonePasswordCredValueMap, err := phonePasswordCredsToMap(&phonePasswordCredValue)
	if err != nil {
		return "", nil, errors.WrapErrorAction("failed phone params to map", "", nil, err)
	}

	if verifyPhonePassword {
		//send verification code
		if err = a.sendVerificationCode(phone, appType.Application.Name, code, newCredentialID); err != nil {
			return "", nil, errors.WrapErrorAction(logutils.ActionSend, "verification", nil, err)
		}
	}

	return "verification code sent successfully", phonePasswordCredValueMap, nil
}

func (a *PhonePasswordAuthImpl) isCredentialVerified(credential *model.Credential, l *logs.Log) (*bool, *bool, error) {
	if credential.Verified {
		verified := true
		return &verified, nil, nil
	}

	//check if phone verification is off
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
		return nil, nil, errors.WrapErrorAction("error on map to phone creds when checking is credential verified", "", nil, err)
	}
	expired := false
	if storedCreds.VerificationExpiry.Before(time.Now()) {
		expired = true
	}
	return &verified, &expired, nil
}

func (a *PhonePasswordAuthImpl) checkCredentials(accountAuthType model.AccountAuthType, creds string, l *logs.Log) (string, error) {
	//get stored credential
	storedCreds, err := mapToPhonePasswordCreds(accountAuthType.Credential.Value)
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

func (a *PhonePasswordAuthImpl) getVerifyPhonePassword(authType model.AuthType) bool {
	verifyPhonePassword := true
	verifyPhonePassowrdParam, ok := authType.Params["verify_phone"].(bool)
	if ok {
		verifyPhonePassword = verifyPhonePassowrdParam
	}
	return verifyPhonePassword
}

//Time in seconds to wait before sending another verification phone
func (a *PhonePasswordAuthImpl) getVerifyWaitTime(authType model.AuthType) int {
	//Default is 30 seconds
	verifyWaitTime := 30
	verifyWaitTimeParam, ok := authType.Params["verify_wait_time"].(int)
	if ok {
		verifyWaitTime = verifyWaitTimeParam
	}
	return verifyWaitTime
}

//Time in hours before verification code expires
func (a *PhonePasswordAuthImpl) getVerifyExpiry(authType model.AuthType) int {
	//Default is 24 hours
	verifyExpiry := 24
	verifyExpiryParam, ok := authType.Params["verify_expiry"].(int)
	if ok {
		verifyExpiry = verifyExpiryParam
	}
	return verifyExpiry
}

func (a *PhonePasswordAuthImpl) sendVerificationCode(phonePassword string, appName string, verificationCode string, credentialID string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	//urlStr := "https://verify.twilio.com/v2/Services"
	params := url.Values{}
	params.Add("id", credentialID)
	params.Add("code", verificationCode)
	params.Add("To", phonePassword)
	params.Add("Channel", "sms")
	verificationLink := a.auth.host + fmt.Sprintf("/ui/credential/verify?%s", params.Encode())
	message := "Please click the link below to verify your phone number:<br><a href=" + verificationLink + ">" + verificationLink + "</a><br><br>If you did not request this verification link, please ignore this message."
	params.Set("Body", message)
	//msgDataReader := *strings.NewReader(params.Encode())
	subject := "Verify your phone number"
	if appName != "" {
		subject += " for " + appName
	}
	body, err := makeRequest(ctx, "POST", servicesPathPart+"/"+a.twilioServiceSID+"/"+verificationPPCheckPart, params, a.twilioAccountSID, a.twilioToken)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionSend, logutils.TypeRequest, nil, err)
	}

	err = json.Unmarshal(body, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUnmarshal, typeVerificationResponse, nil, err)
	}

	/*	client := &http.Client{}
		req, _ := http.NewRequest("POST", urlStr, &msgDataReader)
		req.SetBasicAuth(a.twilioAccountSID, a.twilioToken)
		req.Header.Add("Accept", "application/json")
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		resp, _ := client.Do(req)
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			var data map[string]interface{}
			decoder := json.NewDecoder(resp.Body)
			err := decoder.Decode(&data)
			if err == nil {
				fmt.Println(data["sid"])
			}
		} else {
			fmt.Println(resp.Status)
		}*/

	return nil
}
func (a *PhonePasswordAuthImpl) sendPasswordResetEmail(credentialID string, resetCode string, phonePassword string, appName string) (string, error) {
	params := url.Values{}
	params.Add("id", credentialID)
	params.Add("code", resetCode)
	passwordResetLink := a.auth.host + fmt.Sprintf("/ui/credential/reset?%s", params.Encode())
	subject := "Reset your password"
	if appName != "" {
		subject += " for " + appName
	}
	body := "Please click the link below to reset your password:<br><a href=" + passwordResetLink + ">" + passwordResetLink + "</a><br><br>If you did not request a password reset, please ignore this message."

	return body, nil

}

func (a *PhonePasswordAuthImpl) verifyCredential(credential *model.Credential, verification string, l *logs.Log) (map[string]interface{}, error) {
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

func (a *PhonePasswordAuthImpl) sendVerifyCredential(credential *model.Credential, appName string, l *logs.Log) error {
	//Check if verify phone is disabled for the given authType
	authType := credential.AuthType
	verifyEmail := a.getVerifyPhonePassword(authType)
	if !verifyEmail {
		return errors.ErrorAction(logutils.ActionSend, logutils.TypeString, logutils.StringArgs("verify phone is disabled for authType"))
	}
	verifyWaitTime := a.getVerifyWaitTime(authType)
	verifyExpiryTime := a.getVerifyExpiry(authType)

	//Parse credential value to phonePasswordCreds
	phonePasswordCreds, err := mapToPhonePasswordCreds(credential.Value)
	if err != nil {
		return errors.WrapErrorAction("error on map to phone creds", "", nil, err)
	}
	//Check if previous verification email was sent less than 30 seconds ago
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

	//send verification
	if err = a.sendVerificationCode(phonePasswordCreds.Phone, appName, code, credential.ID); err != nil {
		return errors.WrapErrorAction(logutils.ActionSend, "verification phone number", nil, err)
	}

	//Update verification data in credential value
	phonePasswordCreds.VerificationCode = code
	phonePasswordCreds.VerificationExpiry = time.Now().Add(time.Hour * time.Duration(verifyExpiryTime))
	credsMap, err := phonePasswordCredsToMap(phonePasswordCreds)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionCast, typeEmailCreds, nil, err)
	}

	credential.Value = credsMap
	if err = a.auth.storage.UpdateCredential(nil, credential); err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeCredential, nil, err)
	}

	return nil
}

func (a *PhonePasswordAuthImpl) restartCredentialVerification(credential *model.Credential, appName string, l *logs.Log) error {
	storedCreds, err := mapToPhonePasswordCreds(credential.Value)
	if err != nil {
		return errors.WrapErrorAction("error on map to phonePassword creds when checking is credential verified", "", nil, err)
	}
	//Generate new verification code
	newCode, err := utils.GenerateRandomString(64)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionCompute, model.TypeAuthCred, nil, errors.New("failed to generate random string for verify code"))

	}
	//send new verification code for future
	if err = a.sendVerificationCode(storedCreds.Phone, appName, newCode, credential.ID); err != nil {
		return errors.WrapErrorAction(logutils.ActionSend, "verification link", nil, err)
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

func (a *PhonePasswordAuthImpl) compareCode(credCode string, requestCode string, expiryTime time.Time, l *logs.Log) error {
	if expiryTime.Before(time.Now()) {
		return errors.New("Code has expired")
	}

	if subtle.ConstantTimeCompare([]byte(credCode), []byte(requestCode)) == 0 {
		return errors.ErrorData(logutils.StatusInvalid, "Invalid code", nil)
	}
	return nil
}

func (a *PhonePasswordAuthImpl) resetCredential(credential *model.Credential, resetCode *string, params string, l *logs.Log) (map[string]interface{}, error) {
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
		return nil, errors.WrapErrorAction(logutils.ActionMarshal, typeEmailCreds, nil, err)
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

func (a *PhonePasswordAuthImpl) forgotCredential(credential *model.Credential, identifier string, appName string, l *logs.Log) (map[string]interface{}, error) {
	phonePasswordCreds, err := mapToPhonePasswordCreds(credential.Value)
	if err != nil {
		return nil, errors.WrapErrorAction("error on map to phonePassword creds", "", nil, err)
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
	_, err = a.sendPasswordResetEmail(credential.ID, resetCode, identifier, appName)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionSend, logutils.TypeString, nil, err)
	}
	credsMap, err := phonePasswordCredsToMap(phonePasswordCreds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCast, typePhonePasswordCreds, nil, err)
	}
	return credsMap, nil
}

func (a *PhonePasswordAuthImpl) getUserIdentifier(creds string) (string, error) {
	var requestCreds phonePasswordCreds
	err := json.Unmarshal([]byte(creds), &requestCreds)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionUnmarshal, typePhonePasswordCreds, nil, err)
	}

	return requestCreds.Phone, nil
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

//initPhonePasswordAuth initializes and registers a new email auth instance
func initPhonePasswordAuth(auth *Auth) (*PhonePasswordAuthImpl, error) {
	phoneP := &PhonePasswordAuthImpl{auth: auth, authType: AuthTypePhonePassword}

	err := auth.registerAuthType(phoneP.authType, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeAuthType, nil, err)
	}

	return phoneP, nil
}
