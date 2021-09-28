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

	"github.com/rokmetro/logging-library/errors"
	"github.com/rokmetro/logging-library/logs"
	"github.com/rokmetro/logging-library/logutils"
	"gopkg.in/go-playground/validator.v9"
)

const (
	//AuthTypeTwilioPhone phone auth type
	AuthTypeTwilioPhone      string                   = "twilio_phone"
	servicesPathPart                                  = "https://verify.twilio.com/v2/Services"
	verificationsPathPart                             = "Verifications"
	verificationCheckPart                             = "VerificationCheck"
	typeVerifyServiceID      logutils.MessageDataType = "phone verification service id"
	typeVerifyServiceToken   logutils.MessageDataType = "phone verification service token"
	typeVerificationResponse logutils.MessageDataType = "phone verification response"
	typeVerificationStatus   logutils.MessageDataType = "phone verification staus"
	typeVerificationSID      logutils.MessageDataType = "phone verification sid"
	typePhoneCreds           logutils.MessageDataType = "phone creds"
	typePhoneNumber          logutils.MessageDataType = "E.164 phone number"
)

// Phone implementation of authType
type twilioPhoneAuthImpl struct {
	auth             *Auth
	authType         string
	twilioAccountSID string
	twilioToken      string
	twilioServiceSID string
}

type twilioPhoneCreds struct {
	Phone string `json:"phone" validate:"required"`
	Code  string `json:"code"`
	// TODO: Password?
}

type verifyPhoneResponse struct {
	Sid         string    `json:"sid"`
	ServiceSid  string    `json:"service_sid"`
	AccountSid  string    `json:"account_sid"`
	To          string    `json:"to" validate:"required"`
	Channel     string    `json:"channel" validate:"required"`
	Status      string    `json:"status"`
	Lookup      string    `json:"lookup"`
	Amount      string    `json:"amount"`
	Payee       string    `json:"payee"`
	DateCreated time.Time `json:"date_created"`
	DateUpdated time.Time `json:"date_updated"`
	URL         string    `json:"url"`
}

type checkStatusResponse struct {
	Sid         string    `json:"sid"`
	ServiceSid  string    `json:"service_sid"`
	AccountSid  string    `json:"account_sid"`
	To          string    `json:"to" validate:"required"`
	Channel     string    `json:"channel"`
	Status      string    `json:"status"`
	Amount      string    `json:"amount"`
	Payee       string    `json:"payee"`
	DateCreated time.Time `json:"date_created"`
	DateUpdated time.Time `json:"date_updated"`
}

func (a *twilioPhoneAuthImpl) checkRequestCreds(creds string) (*twilioPhoneCreds, error) {
	var requestCreds twilioPhoneCreds
	err := json.Unmarshal([]byte(creds), &requestCreds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typePhoneCreds, nil, err)
	}

	validate := validator.New()
	err = validate.Struct(requestCreds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionValidate, typePhoneCreds, nil, err)
	}

	phone := requestCreds.Phone
	validPhone := regexp.MustCompile(`^\+[1-9]\d{1,14}$`)
	if !validPhone.MatchString(phone) {
		return nil, errors.ErrorData(logutils.StatusInvalid, typePhoneNumber, &logutils.FieldArgs{"phone": phone})
	}

	return &requestCreds, nil
}

func (a *twilioPhoneAuthImpl) applySignUp(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, creds string, params string, l *logs.Log) (string, *string, map[string]interface{}, error) {
	requestCreds, err := a.checkRequestCreds(creds)
	if err != nil {
		return "", nil, nil, err
	}

	message, err := a.handlePhoneVerify(requestCreds.Phone, *requestCreds, l)
	if err != nil {
		return "", nil, nil, err
	}

	return message, &requestCreds.Phone, nil, nil
}

func (a *twilioPhoneAuthImpl) checkCredentials(accountAuthType model.AccountAuthType, creds string, l *logs.Log) (string, *bool, error) {
	requestCreds, err := a.checkRequestCreds(creds)
	if err != nil {
		return "", nil, err
	}

	// existing user
	message, err := a.handlePhoneVerify(requestCreds.Phone, *requestCreds, l)
	if err != nil {
		return "", nil, err
	}

	valid := true
	return message, &valid, nil
}

func (a *twilioPhoneAuthImpl) handlePhoneVerify(phone string, verificationCreds twilioPhoneCreds, l *logs.Log) (string, error) {
	if a.twilioAccountSID == "" {
		return "", errors.ErrorData(logutils.StatusMissing, typeVerifyServiceID, nil)
	}

	if a.twilioToken == "" {
		return "", errors.ErrorData(logutils.StatusMissing, typeVerifyServiceToken, nil)
	}

	data := url.Values{}
	data.Add("to", phone)
	if verificationCreds.Code != "" {
		// check verification
		data.Add("code", verificationCreds.Code)
		return "", a.checkVerification(phone, data, l)
	}

	// start verification
	data.Add("channel", "sms")

	message := ""
	err := a.startVerification(phone, data, l)
	if err == nil {
		message = "verification code sent successfully"
	}
	return message, err
}

func (a *twilioPhoneAuthImpl) startVerification(phone string, data url.Values, l *logs.Log) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resp, err := makeRequest(ctx, "POST", servicesPathPart+"/"+a.twilioServiceSID+"/"+verificationsPathPart, data, a.twilioAccountSID, a.twilioToken)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionSend, logutils.TypeRequest, &logutils.FieldArgs{"verification params": data}, err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionRead, logutils.TypeResponseBody, nil, err)
	}

	var verifyResult verifyPhoneResponse
	err = json.Unmarshal(body, &verifyResult)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUnmarshal, typeVerificationResponse, nil, err)
	}

	if verifyResult.To != phone {
		return errors.ErrorData(logutils.StatusInvalid, logutils.TypeString, &logutils.FieldArgs{"expected phone": phone, "actual phone": verifyResult.To})
	}
	if verifyResult.Status != "pending" {
		return errors.ErrorData(logutils.StatusInvalid, typeVerificationStatus, &logutils.FieldArgs{"expected pending, actual:": verifyResult.Status})
	}
	if verifyResult.Sid == "" {
		return errors.ErrorData(logutils.StatusMissing, typeVerificationSID, nil)
	}

	return nil
}

func (a *twilioPhoneAuthImpl) checkVerification(phone string, data url.Values, l *logs.Log) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resp, err := makeRequest(ctx, "POST", servicesPathPart+"/"+a.twilioServiceSID+"/"+verificationCheckPart, data, a.twilioAccountSID, a.twilioToken)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionSend, logutils.TypeRequest, nil, err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionRead, logutils.TypeResponseBody, nil, err)
	}

	var checkResponse checkStatusResponse
	err = json.Unmarshal(body, &checkResponse)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUnmarshal, typeVerificationResponse, nil, err)
	}

	if checkResponse.To != phone {
		return errors.ErrorData(logutils.StatusInvalid, logutils.TypeString, &logutils.FieldArgs{"expected phone": phone, "actual phone": checkResponse.To})
	}
	if checkResponse.Status != "approved" {
		return errors.ErrorData(logutils.StatusInvalid, typeVerificationStatus, &logutils.FieldArgs{"expected approved, actual:": checkResponse.Status})
	}

	return nil
}

// func (a *phoneAuthImpl) getPhoneAuthConfig(orgID string, appID string) (*phoneAuthConfig, error) {
// 	errFields := &logutils.FieldArgs{"org_id": orgID, "app_id": appID, "auth_type": a.authType}

// 	authConfig, err := a.auth.getAuthConfig(orgID, appID, "phone")
// 	if err != nil {
// 		return nil, errors.WrapErrorAction(log.ActionFind, model.TypeAuthConfig, errFields, err)
// 	}

// 	var phoneConfig phoneAuthConfig
// 	err = json.Unmarshal(authConfig.Config, &phoneConfig)
// 	if err != nil {
// 		return nil, errors.WrapErrorAction(log.ActionUnmarshal, model.TypeAuthConfig, errFields, err)
// 	}
// 	validate := validator.New()
// 	err = validate.Struct(phoneConfig)
// 	if err != nil {
// 		return nil, errors.WrapErrorAction(log.ActionValidate, model.TypeAuthConfig, errFields, err)
// 	}

// 	return &phoneConfig, nil
// }

func makeRequest(ctx context.Context, method string, pathPart string, data url.Values, user string, token string) (*http.Response, error) {
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

	req, err := http.NewRequestWithContext(ctx, method, pathPart, rb)
	if err != nil {
		return nil, errors.WrapErrorAction(logAction, logutils.TypeRequest, &logutils.FieldArgs{"path": pathPart}, err)
	}

	if token != "" {
		req.Header.Add("Authorization", "Basic "+basicAuth(user, token))
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.WrapErrorAction(logAction, logutils.TypeRequest, nil, err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err)
	}
	if resp.StatusCode != 200 {
		return nil, errors.ErrorData(logutils.StatusInvalid, logutils.TypeResponse, &logutils.FieldArgs{"status_code": resp.StatusCode, "error": string(body)})
	}
	return resp, nil
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func (a *twilioPhoneAuthImpl) userExist(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, creds string, l *logs.Log) (*model.Account, *model.AccountAuthType, error) {
	appID := appOrg.Application.ID
	orgID := appOrg.Organization.ID
	authTypeID := authType.ID

	var requestCreds twilioPhoneCreds
	err := json.Unmarshal([]byte(creds), &requestCreds)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typePhoneCreds, logutils.StringArgs("request"), err)
	}

	account, err := a.auth.storage.FindAccount(appID, orgID, authTypeID, requestCreds.Phone)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err) //TODO add args..
	}

	if account == nil {
		return nil, nil, nil
	}

	accountAuthType, err := a.auth.findAccountAuthType(account, &authType, requestCreds.Phone)
	if accountAuthType == nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccountAuthType, nil, err) //TODO add args..
	}

	return account, accountAuthType, nil
}

func (a *twilioPhoneAuthImpl) verify(credential *model.Credential, verification string, l *logs.Log) (map[string]interface{}, error) {
	return nil, errors.New(logutils.Unimplemented)
}

// func phoneCredsToMap(creds *phoneCreds) (map[string]interface{}, error) {
// 	credBytes, err := json.Marshal(creds)
// 	if err != nil {
// 		return nil, errors.WrapErrorAction(logutils.ActionMarshal, model.TypeAuthCred, nil, err)
// 	}
// 	var credsMap map[string]interface{}
// 	err = json.Unmarshal(credBytes, &credsMap)
// 	if err != nil {
// 		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, model.TypeAuthCred, nil, err)
// 	}

// 	return credsMap, nil
// }

// func mapToPhoneCreds(credsMap map[string]interface{}) (*phoneCreds, error) {
// 	credBytes, err := json.Marshal(credsMap)
// 	if err != nil {
// 		return nil, errors.WrapErrorAction(logutils.ActionMarshal, typePhoneCreds, nil, err)
// 	}
// 	var creds *phoneCreds
// 	err = json.Unmarshal(credBytes, creds)
// 	if err != nil {
// 		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typePhoneCreds, nil, err)
// 	}

// 	return creds, nil
// }

//initPhoneAuth initializes and registers a new phone auth instance
func initPhoneAuth(auth *Auth, twilioAccountSID string, twilioToken string, twilioServiceSID string) (*twilioPhoneAuthImpl, error) {
	phone := &twilioPhoneAuthImpl{auth: auth, authType: AuthTypeTwilioPhone, twilioAccountSID: twilioAccountSID, twilioToken: twilioToken, twilioServiceSID: twilioServiceSID}

	err := auth.registerAuthType(phone.authType, phone)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeAuthType, nil, err)
	}

	return phone, nil
}
