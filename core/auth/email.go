package auth

import (
	"core-building-block/core/model"
	"core-building-block/utils"
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
	AuthTypeEmail string = "email"

	typeTime        logutils.MessageDataType = "time.Time"
	typeEmailCreds  logutils.MessageDataType = "email creds"
	typeEmailParams logutils.MessageDataType = "email params"
)

//enailCreds represents the creds struct for email auth
type emailCreds struct {
	Email              string    `json:"email" bson:"email" validate:"required"`
	Password           string    `json:"password" bson:"password"`
	VerificationCode   string    `json:"verification_code" bson:"verification_code"`
	VerificationExpiry time.Time `json:"verification_expiry" bson:"verification_expiry"`
}

// Email implementation of authType
type emailAuthImpl struct {
	auth     *Auth
	authType string
}

func (a *emailAuthImpl) signUp(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, creds string, params string, newCredentialID string, l *logs.Log) (string, map[string]interface{}, error) {
	type signUpEmailParams struct {
		ConfirmPassword string `json:"confirm_password"`
	}

	var sEmailCreds emailCreds
	err := json.Unmarshal([]byte(creds), &sEmailCreds)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeEmailCreds, nil, err)
	}

	var sEmailParams signUpEmailParams
	err = json.Unmarshal([]byte(params), &sEmailParams)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeEmailParams, nil, err)
	}

	email := sEmailCreds.Email
	password := sEmailCreds.Password
	confirmPassword := sEmailParams.ConfirmPassword
	if len(email) == 0 {
		return "", nil, errors.ErrorData(logutils.StatusMissing, typeEmailCreds, logutils.StringArgs("email"))
	}
	if len(password) == 0 {
		return "", nil, errors.ErrorData(logutils.StatusMissing, typeEmailCreds, logutils.StringArgs("password"))
	}
	if len(confirmPassword) == 0 {
		return "", nil, errors.ErrorData(logutils.StatusMissing, typeEmailParams, logutils.StringArgs("confirm_password"))
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

	verifyEmail := a.getVerifyEmail(authType)

	var emailCredValue emailCreds
	if verifyEmail {
		emailCredValue = emailCreds{Email: email, Password: string(hashedPassword), VerificationCode: code, VerificationExpiry: time.Now().Add(time.Hour * 24)}
	} else {
		emailCredValue = emailCreds{Email: email, Password: string(hashedPassword)}
	}

	emailCredValueMap, err := emailCredsToMap(&emailCredValue)
	if err != nil {
		return "", nil, errors.WrapErrorAction("failed email params to map", "", nil, err)
	}

	if verifyEmail {
		//send verification code
		if err = a.sendVerificationCode(email, code, newCredentialID); err != nil {
			return "", nil, errors.WrapErrorAction(logutils.ActionSend, "verification email", nil, err)
		}
	}

	return "verification code sent successfully", emailCredValueMap, nil
}

func (a *emailAuthImpl) checkCredentials(accountAuthType model.AccountAuthType, creds string, l *logs.Log) (string, *bool, error) {
	verifyEmail := a.getVerifyEmail(accountAuthType.AuthType)
	if verifyEmail {
		//check is verified
		if !accountAuthType.Credential.Verified {
			return "", nil, errors.ErrorAction("not verified", "", nil)
		}
	}

	//get stored credential
	storedCreds, err := mapToEmailCreds(accountAuthType.Credential.Value)
	if err != nil {
		return "", nil, errors.WrapErrorAction("error on map to email creds", "", nil, err)
	}

	//get request credential
	type signInPasswordCred struct {
		Password string `json:"password"`
	}
	var sPasswordParams signInPasswordCred
	err = json.Unmarshal([]byte(creds), &sPasswordParams)
	if err != nil {
		return "", nil, errors.WrapErrorAction("error getting sign_in password creds", "", nil, err)
	}
	requestPassword := sPasswordParams.Password

	//compare stored and requets ones
	err = bcrypt.CompareHashAndPassword([]byte(storedCreds.Password), []byte(requestPassword))
	if err != nil {
		return "", nil, errors.WrapErrorAction("bad credentials", "", nil, err)
	}

	valid := true
	return "", &valid, nil
}

func (a *emailAuthImpl) getVerifyEmail(authType model.AuthType) bool {
	verifyEmail := true
	verifyEmailParam, ok := authType.Params["verify_email"].(bool)
	if ok {
		verifyEmail = verifyEmailParam
	}
	return verifyEmail
}

func (a *emailAuthImpl) sendVerificationCode(email string, verificationCode string, credentialID string) error {
	params := url.Values{}
	params.Add("id", credentialID)
	params.Add("code", verificationCode)

	verificationLink := a.auth.host + fmt.Sprintf("/services/auth/verify?%s", params.Encode())

	return a.auth.emailer.Send(email, "Verify your email address", "Please click the link below to verify your email address:\n"+verificationLink+"\n\nIf you did not request this verification link, please ignore this message.", nil)
}

//TODO: To be used in password reset flow
// func (a *emailAuthImpl) sendPasswordReset(email string, password string) error {
// 	return a.auth.Send(email, "Password Reset", "Your temporary password is "+password, "")
// }

func (a *emailAuthImpl) verify(credential *model.Credential, verification string, l *logs.Log) (map[string]interface{}, error) {
	credBytes, err := json.Marshal(credential.Value)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionMarshal, typeEmailCreds, nil, err)
	}

	var creds *emailCreds
	err = json.Unmarshal(credBytes, &creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeEmailCreds, nil, err)
	}
	err = a.compareVerifyCode(creds.VerificationCode, verification, creds.VerificationExpiry, l)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionValidate, model.TypeAuthCred, &logutils.FieldArgs{"verification_code": verification}, errors.New("invalid verification code"))
	}

	//Update verification data
	creds.VerificationCode = ""
	creds.VerificationExpiry = time.Time{}
	credsMap, err := emailCredsToMap(creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCast, typeEmailCreds, nil, err)
	}

	return credsMap, nil
}

func (a *emailAuthImpl) compareVerifyCode(credCode string, requestCode string, expiryTime time.Time, l *logs.Log) error {
	if expiryTime.Before(time.Now()) {
		return errors.WrapErrorAction(logutils.ActionValidate, typeTime, nil, errors.New("verification code has expired"))
	}

	if credCode != requestCode {
		return errors.WrapErrorAction(logutils.ActionValidate, typeTime, nil, errors.New("Invalid verification code"))
	}
	return nil

}

func (a *emailAuthImpl) getUserIdentifier(creds string) (string, error) {
	var requestCreds emailCreds
	err := json.Unmarshal([]byte(creds), &requestCreds)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionUnmarshal, typeEmailCreds, nil, err)
	}

	return requestCreds.Email, nil
}

func emailCredsToMap(creds *emailCreds) (map[string]interface{}, error) {
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

func mapToEmailCreds(credsMap map[string]interface{}) (*emailCreds, error) {
	credBytes, err := json.Marshal(credsMap)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionMarshal, typeEmailCreds, nil, err)
	}
	var creds emailCreds
	err = json.Unmarshal(credBytes, &creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeEmailCreds, nil, err)
	}
	return &creds, nil
}

//initEmailAuth initializes and registers a new email auth instance
func initEmailAuth(auth *Auth) (*emailAuthImpl, error) {
	email := &emailAuthImpl{auth: auth, authType: AuthTypeEmail}

	err := auth.registerAuthType(email.authType, email)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeAuthType, nil, err)
	}

	return email, nil
}
