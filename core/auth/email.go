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
	ResetCode          string    `json:"reset_code" bson:"reset_code"`
	ResetExpiry        time.Time `json:"reset_expiry" bson:"reset_expiry"`
}

// Email implementation of authType
type emailAuthImpl struct {
	auth     *Auth
	authType string
}

func (a *emailAuthImpl) signUp(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, creds string, params string, newCredentialID string, l *logs.Log) (string, *string, map[string]interface{}, error) {
	type signUpEmailParams struct {
		ConfirmPassword string `json:"confirm_password"`
	}

	var sEmailCreds emailCreds
	err := json.Unmarshal([]byte(creds), &sEmailCreds)
	if err != nil {
		return "", nil, nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeEmailCreds, nil, err)
	}

	var sEmailParams signUpEmailParams
	err = json.Unmarshal([]byte(params), &sEmailParams)
	if err != nil {
		return "", nil, nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeEmailParams, nil, err)
	}

	email := sEmailCreds.Email
	password := sEmailCreds.Password
	confirmPassword := sEmailParams.ConfirmPassword
	if len(email) == 0 {
		return "", nil, nil, errors.ErrorData(logutils.StatusMissing, typeEmailCreds, logutils.StringArgs("email"))
	}
	if len(password) == 0 {
		return "", nil, nil, errors.ErrorData(logutils.StatusMissing, typeEmailCreds, logutils.StringArgs("password"))
	}
	if len(confirmPassword) == 0 {
		return "", nil, nil, errors.ErrorData(logutils.StatusMissing, typeEmailParams, logutils.StringArgs("confirm_password"))
	}
	//check if the passwrod matches with the confirm password one
	if password != confirmPassword {
		return "", nil, nil, errors.WrapErrorAction("passwords fields do not match", "", nil, err)
	}

	//password hash
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", nil, nil, errors.WrapErrorAction(logutils.ActionCompute, model.TypeAuthCred, nil, errors.New("failed to generate hash from password"))
	}

	//verification code
	code, err := utils.GenerateRandomString(64)
	if err != nil {
		return "", nil, nil, errors.WrapErrorAction(logutils.ActionCompute, model.TypeAuthCred, nil, errors.New("failed to generate random string for verify code"))

	}

	emailCredValue := emailCreds{Email: email, Password: string(hashedPassword), VerificationCode: code, VerificationExpiry: time.Now().Add(time.Hour * 24)}
	emailCredValueMap, err := emailCredsToMap(&emailCredValue)
	if err != nil {
		return "", nil, nil, errors.WrapErrorAction("failed email params to map", "", nil, err)
	}

	//send verification code
	if err = a.sendVerificationCode(email, code, newCredentialID); err != nil {
		return "", nil, nil, errors.WrapErrorAction(logutils.ActionSend, "verification email", nil, err)
	}

	return "verification code sent successfully", &email, emailCredValueMap, nil
}

func (a *emailAuthImpl) checkCredentials(accountAuthType model.AccountAuthType, creds string, l *logs.Log) (string, *bool, map[string]interface{}, error) {
	//get stored credential
	storedCreds, err := mapToEmailCreds(accountAuthType.Credential.Value)
	if err != nil {
		return "", nil, nil, errors.WrapErrorAction("error on map to email creds", "", nil, err)
	}
	//check is verified
	if !accountAuthType.Credential.Verified {
		if storedCreds.VerificationExpiry.Before(time.Now()) {
			//Generate new verification code
			newCode, err := utils.GenerateRandomString(64)
			if err != nil {
				return "", nil, nil, errors.WrapErrorAction(logutils.ActionCompute, model.TypeAuthCred, nil, errors.New("failed to generate random string for verify code"))

			}
			//send new verification code for future
			if err = a.sendVerificationCode(storedCreds.Email, newCode, accountAuthType.Credential.ID); err != nil {
				return "", nil, nil, errors.WrapErrorAction(logutils.ActionSend, "verification email", nil, err)
			}
			//update new verification data in credential value
			storedCreds.VerificationCode = newCode
			storedCreds.VerificationExpiry = time.Now().Add(time.Hour * 24)
			emailCredValueMap, err := emailCredsToMap(storedCreds)
			if err != nil {
				return "", nil, nil, errors.WrapErrorAction(logutils.ActionCast, typeEmailCreds, nil, err)
			}
			return "new verification code sent successfully", nil, emailCredValueMap, nil
		}
		return "you must verify your email address", nil, nil, nil
	}

	//get request credential
	type signInPasswordCred struct {
		Password string `json:"password"`
	}
	var sPasswordParams signInPasswordCred
	err = json.Unmarshal([]byte(creds), &sPasswordParams)
	if err != nil {
		return "", nil, nil, errors.WrapErrorAction("error getting sign_in password creds", "", nil, err)
	}
	requestPassword := sPasswordParams.Password

	//compare stored and requets ones
	err = bcrypt.CompareHashAndPassword([]byte(storedCreds.Password), []byte(requestPassword))
	if err != nil {
		return "", nil, nil, errors.WrapErrorAction("bad credentials", "", nil, err)
	}

	valid := true
	return "", &valid, nil, nil
}

func (a *emailAuthImpl) sendVerificationCode(email string, verificationCode string, credentialID string) error {
	params := url.Values{}
	params.Add("id", credentialID)
	params.Add("code", verificationCode)

	verificationLink := a.auth.host + fmt.Sprintf("/services/auth/verify?%s", params.Encode())

	return a.auth.emailer.Send(email, "Verify your email address", "Please click the link below to verify your email address:\n"+verificationLink+"\n\nIf you did not request this verification link, please ignore this message.", nil)
}

func (a *emailAuthImpl) sendPasswordResetEmail(credentialID string, resetCode string, email string) error {
	params := url.Values{}
	params.Add("id", credentialID)
	params.Add("code", resetCode)
	passwordResetLink := a.auth.host + fmt.Sprintf("/services/auth/reset-password-landing-page?%s", params.Encode())
	return a.auth.emailer.Send(email, "Password Reset", "Please click the link below to reset your password:\n"+passwordResetLink+"\n\nIf you did not request a password reset, please ignore this message.", nil)
}

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
	err = a.compareCode(creds.VerificationCode, verification, creds.VerificationExpiry, l)
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

func (a *emailAuthImpl) compareCode(credCode string, requestCode string, expiryTime time.Time, l *logs.Log) error {
	if expiryTime.Before(time.Now()) {
		return errors.WrapErrorAction(logutils.ActionValidate, typeTime, nil, errors.New("Code has expired"))
	}

	if credCode != requestCode {
		return errors.WrapErrorAction(logutils.ActionValidate, typeTime, nil, errors.New("Invalid code"))
	}
	return nil

}

func (a *emailAuthImpl) resetPassword(credential *model.Credential, resetCode *string, password *string, newPassword string, confirmPassword string, l *logs.Log) (map[string]interface{}, error) {
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

	var creds *emailCreds
	err = json.Unmarshal(credBytes, &creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeEmailCreds, nil, err)
	}
	//reset password from client app
	if password != nil {
		//validate old password
		err = bcrypt.CompareHashAndPassword([]byte(creds.Password), []byte(*password))
		if err != nil {
			return nil, errors.WrapErrorAction("bad credentials", "", nil, err)
		}
		//reset password from link
	} else if resetCode != nil {
		err = a.compareCode(creds.ResetCode, *resetCode, creds.ResetExpiry, l)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionValidate, model.TypeAuthCred, &logutils.FieldArgs{"reset_code": *resetCode}, errors.New("invalid reset code"))
		}
		//Update verification data
		creds.ResetCode = ""
		creds.ResetExpiry = time.Time{}
	} else {
		return nil, errors.New("Missing both resetCode and old password")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCompute, model.TypeAuthCred, nil, errors.New("failed to generate hash from new password"))
	}

	//Update verification data
	creds.Password = string(hashedPassword)
	credsMap, err := emailCredsToMap(creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCast, typeEmailCreds, nil, err)
	}

	return credsMap, nil
}

func (a *emailAuthImpl) forgotPassword(credential *model.Credential, identifier string, l *logs.Log) (map[string]interface{}, error) {
	emailCreds, err := mapToEmailCreds(credential.Value)
	if err != nil {
		return nil, errors.WrapErrorAction("error on map to email creds", "", nil, err)
	}
	resetCode, err := utils.GenerateRandomString(64)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCompute, logutils.TypeString, nil, errors.New("failed to generate random string for reset code"))

	}
	emailCreds.ResetCode = resetCode
	emailCreds.ResetExpiry = time.Now().Add(time.Hour * 24)
	err = a.sendPasswordResetEmail(credential.ID, resetCode, identifier)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionSend, logutils.TypeString, nil, err)
	}
	credsMap, err := emailCredsToMap(emailCreds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCast, typeEmailCreds, nil, err)
	}
	return credsMap, nil
}

func (a *emailAuthImpl) userExist(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, creds string, l *logs.Log) (*model.AccountAuthType, error) {
	appID := appOrg.Application.ID
	orgID := appOrg.Organization.ID
	authTypeID := authType.ID

	var requestCreds emailCreds
	err := json.Unmarshal([]byte(creds), &requestCreds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeEmailCreds, logutils.StringArgs("request"), err)
	}

	account, err := a.auth.storage.FindAccount(appID, orgID, authTypeID, requestCreds.Email)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err) //TODO add args..
	}

	if account == nil {
		return nil, nil
	}

	accountAuthType, err := a.auth.findAccountAuthType(account, &authType, requestCreds.Email)
	if accountAuthType == nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccountAuthType, nil, err) //TODO add args..
	}

	return accountAuthType, nil
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
