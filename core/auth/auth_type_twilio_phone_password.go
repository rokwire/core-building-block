package auth

import (
	"context"
	"core-building-block/core/model"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
	"gopkg.in/go-playground/validator.v9"
)

const (
	//AuthTypeTwilioPhone phone auth type
	AuthTypeTwilioPhonePassword string = "twilio_phone_password"

	serPathPart                                      = "https://verify.twilio.com/v2/Services"
	verificationsPath                                = "Verifications"
	verificationCheck                                = "VerificationCheck"
	verifyServiceID         logutils.MessageDataType = "phone_password verification service id"
	verifyServiceToken      logutils.MessageDataType = "phone_password verification service token"
	verificationResponse    logutils.MessageDataType = "phone_password verification response"
	verificationStatus      logutils.MessageDataType = "phone_password verification staus"
	verificationSID         logutils.MessageDataType = "phone_password verification sid"
	phoneCreds              logutils.MessageDataType = "phone_password creds"
	phoneNumber             logutils.MessageDataType = "E.164 phone_password number"
	typePhonePasswordParams logutils.MessageDataType = "phone_password params"
)

// Phone_password implementation of authType
type twilioPhonePasswordAuthImpl struct {
	auth             *Auth
	authType         string
	twilioAccountSID string
	twilioToken      string
	twilioServiceSID string
}

type twilioPhonePasswordCreds struct {
	Phone              string    `json:"phone" validate:"required"`
	Password           string    `json:"password" bson:"password"`
	VerificationCode   string    `json:"verification_code" bson:"verification_code"`
	VerificationExpiry time.Time `json:"verification_expiry" bson:"verification_expiry"`
	ResetCode          string    `json:"reset_code" bson:"reset_code"`
	ResetExpiry        time.Time `json:"reset_expiry" bson:"reset_expiry"`
}

func (a *twilioPhonePasswordAuthImpl) checkRequestCreds(creds string) (*twilioPhonePasswordCreds, error) {
	var requestCreds twilioPhonePasswordCreds
	err := json.Unmarshal([]byte(creds), &requestCreds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, phoneCreds, nil, err)
	}

	validate := validator.New()
	err = validate.Struct(requestCreds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionValidate, phoneCreds, nil, err)
	}

	phone := requestCreds.Phone
	validPhone := regexp.MustCompile(`^\+[1-9]\d{1,14}$`)
	if !validPhone.MatchString(phone) {
		return nil, errors.ErrorData(logutils.StatusInvalid, phoneNumber, &logutils.FieldArgs{"phone": phone})
	}

	return &requestCreds, nil
}

func (a *twilioPhonePasswordAuthImpl) signUp(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, creds string, params string, newCredentialID string, l *logs.Log) (string, map[string]interface{}, error) {

	type signUpPhonPasswordParams struct {
		ConfirmPassword string `json:"confirm_password"`
	}

	var sPhonePassowordCreds twilioPhonePasswordCreds
	err := json.Unmarshal([]byte(creds), &sPhonePassowordCreds)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionUnmarshal, phoneCreds, nil, err)
	}

	var sPhonePasswordParams signUpPhonPasswordParams
	err = json.Unmarshal([]byte(params), &sPhonePasswordParams)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typePhonePasswordParams, nil, err)
	}

	phone := sPhonePassowordCreds.Phone
	password := sPhonePassowordCreds.Password
	confirmPassword := sPhonePasswordParams.ConfirmPassword
	if len(phone) == 0 {
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

	requestCreds, err := a.checkRequestCreds(creds)
	if err != nil {
		return "", nil, err
	}

	message, err := a.handlePhoneVerify(requestCreds.Phone, *requestCreds, l)
	if err != nil {
		return "", nil, err
	}

	return message, nil, nil
}

func phoneCredsToMap(creds *twilioPhonePasswordCreds) (map[string]interface{}, error) {
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

func (a *emailAuthImpl) getVerifyPhonePassword(authType model.AuthType) bool {
	verifyPhone := true
	verifyPhoneParam, ok := authType.Params["verify_phone"].(bool)
	if ok {
		verifyPhone = verifyPhoneParam
	}
	return verifyPhone
}

func (a *twilioPhonePasswordAuthImpl) isCredentialVerified(credential *model.Credential, l *logs.Log) (*bool, *bool, error) {
	return nil, nil, nil
}

func (a *twilioPhonePasswordAuthImpl) checkCredentials(accountAuthType model.AccountAuthType, creds string, l *logs.Log) (string, error) {
	requestCreds, err := a.checkRequestCreds(creds)
	if err != nil {
		return "", err
	}

	// existing user
	message, err := a.handlePhoneVerify(requestCreds.Phone, *requestCreds, l)
	if err != nil {
		return "", err
	}

	return message, nil
}

func (a *twilioPhonePasswordAuthImpl) handlePhoneVerify(phone string, verificationCreds twilioPhonePasswordCreds, l *logs.Log) (string, error) {
	if a.twilioAccountSID == "" {
		return "", errors.ErrorData(logutils.StatusMissing, verifyServiceID, nil)
	}

	if a.twilioToken == "" {
		return "", errors.ErrorData(logutils.StatusMissing, verifyServiceToken, nil)
	}

	data := url.Values{}
	data.Add("To", phone)
	if verificationCreds.Password != "" {
		// check verification
		data.Add("Password", verificationCreds.Password)
		//	return "", a.checkVerification(phone, data, l)
	}

	// start verification
	data.Add("Channel", "sms")

	message := ""
	err := a.startVerification(phone, data, l)
	if err == nil {
		message = "verification code sent successfully"
	}
	return message, err
}

func (a *twilioPhonePasswordAuthImpl) startVerification(phone string, data url.Values, l *logs.Log) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	body, err := request(ctx, "POST", serPathPart+"/"+a.twilioServiceSID+"/"+verificationsPathPart, data, a.twilioAccountSID, a.twilioToken)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionSend, logutils.TypeRequest, &logutils.FieldArgs{"verification params": data}, err)
	}

	var verifyResult verifyPhoneResponse
	err = json.Unmarshal(body, &verifyResult)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUnmarshal, verificationResponse, nil, err)
	}

	if verifyResult.To != phone {
		return errors.ErrorData(logutils.StatusInvalid, logutils.TypeString, &logutils.FieldArgs{"expected phone": phone, "actual phone": verifyResult.To})
	}
	if verifyResult.Status != "pending" {
		return errors.ErrorData(logutils.StatusInvalid, verificationStatus, &logutils.FieldArgs{"expected pending, actual:": verifyResult.Status})
	}
	if verifyResult.Sid == "" {
		return errors.ErrorData(logutils.StatusMissing, verificationSID, nil)
	}

	return nil
}

func request(ctx context.Context, method string, pathPart string, data url.Values, user string, token string) ([]byte, error) {
	client := &http.Client{}
	rb := new(strings.Reader)
	logAction := logutils.ActionSend

	if data != nil && (method == "POST" || method == "PUT") {
		rb = strings.NewReader(data.Encode())
	}
	if method == "GET" && data != nil {
		pathPart = pathPart + "?" + data.Encode()
		logAction = logutils.ActionRead
	}

	req, err := http.NewRequest(method, pathPart, rb)
	if err != nil {
		return nil, errors.WrapErrorAction(logAction, logutils.TypeRequest, &logutils.FieldArgs{"path": pathPart}, err)
	}

	if token != "" {
		req.Header.Add("Authorization", "Basic "+basicAuthorization(user, token))
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.WrapErrorAction(logAction, logutils.TypeRequest, nil, err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err)
	}
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		return nil, errors.ErrorData(logutils.StatusInvalid, logutils.TypeResponse, &logutils.FieldArgs{"status_code": resp.StatusCode, "error": string(body)})
	}
	return body, nil
}

func basicAuthorization(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func (a *twilioPhonePasswordAuthImpl) getUserIdentifier(creds string) (string, error) {
	var requestCreds twilioPhonePasswordCreds
	err := json.Unmarshal([]byte(creds), &requestCreds)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionUnmarshal, phoneCreds, nil, err)
	}

	return requestCreds.Phone, nil
}

func (a *twilioPhonePasswordAuthImpl) verifyCredential(credential *model.Credential, verification string, l *logs.Log) (map[string]interface{}, error) {
	return nil, errors.New(logutils.Unimplemented)
}

func (a *twilioPhonePasswordAuthImpl) sendVerifyCredential(credential *model.Credential, l *logs.Log) error {
	return nil
}

func (a *twilioPhonePasswordAuthImpl) restartCredentialVerification(credential *model.Credential, l *logs.Log) error {
	return nil
}

func (a *twilioPhonePasswordAuthImpl) resetCredential(credential *model.Credential, resetCode *string, params string, l *logs.Log) (map[string]interface{}, error) {
	return nil, nil
}

func (a *twilioPhonePasswordAuthImpl) forgotCredential(credential *model.Credential, identifier string, l *logs.Log) (map[string]interface{}, error) {
	return nil, nil
}

//initPhonePasswordAuth initializes and registers a new phone auth instance
func initPhonePasswordAuth(auth *Auth, twilioAccountSID string, twilioToken string, twilioServiceSID string) (*twilioPhonePasswordAuthImpl, error) {
	phone := &twilioPhonePasswordAuthImpl{auth: auth, authType: AuthTypeTwilioPhonePassword, twilioAccountSID: twilioAccountSID, twilioToken: twilioToken, twilioServiceSID: twilioServiceSID}

	err := auth.registerAuthType(phone.authType, phone)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeAuthType, nil, err)
	}

	return phone, nil
}
