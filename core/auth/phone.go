package auth

import (
	"context"
	"core-building-block/core/model"
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
	authTypePhone            string                   = "phone"
	servicesPathPart                                  = "https://verify.twilio.com/v2/Services"
	verificationsPathPart                             = "Verifications"
	verificationCheckPart                             = "VerificationCheck"
	typeVerifyServiceID      logutils.MessageDataType = "phone verification service ID"
	typeVerificationResponse logutils.MessageDataType = "phone verification response"
	typeVerificationStatus   logutils.MessageDataType = "phone verification staus"
	typeVerificationSID      logutils.MessageDataType = "phone verification sid"
	typePhoneCreds           logutils.MessageDataType = "phone creds"
	typePhoneNumber          logutils.MessageDataType = "E.164 phone number"
)

// Phone implementation of authType
type phoneAuthImpl struct {
	auth            *Auth
	authType        string
	verifyServiceID string
}

type phoneCreds struct {
	Phone  string `json:"phone" validate:"required"`
	Status string `json:"status"`
	Code   string `json:"code"`
	// TODO: Password
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

func (a *phoneAuthImpl) checkCredentials(accountAuthType *model.AccountAuthType, creds string, appOrg model.ApplicationOrganization, l *logs.Log) (*string, map[string]interface{}, error) {
	var credID string
	if accountAuthType != nil {
		credID = accountAuthType.Credential.ID
	}

	var verificationCreds phoneCreds
	err := json.Unmarshal([]byte(creds), &verificationCreds)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typePhoneCreds, nil, err)
	}
	validate := validator.New()
	err = validate.Struct(verificationCreds)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionValidate, typePhoneCreds, nil, err)
	}

	// phoneAuthConfig, err := a.getPhoneAuthConfig(orgID, appID)
	// if err != nil {
	// 	return nil, errors.WrapErrorAction(log.ActionGet, typePhoneAuthConfig, nil, err)
	// }

	if a.verifyServiceID == "" {
		return nil, nil, errors.ErrorData(logutils.StatusMissing, typeVerifyServiceID, nil)
	}

	phone := verificationCreds.Phone
	validPhone := regexp.MustCompile(`^\+[1-9]\d{1,14}$`)
	if !validPhone.MatchString(phone) {
		return nil, nil, errors.ErrorData(logutils.StatusInvalid, typePhoneNumber, &logutils.FieldArgs{"phone": phone})
	}

	errFields := logutils.FieldArgs{"_id": credID}

	credential, err := a.auth.storage.FindCredentialByID(credID)
	if err != nil {
		l.LogAction(logs.Warn, logutils.StatusError, logutils.ActionFind, model.TypeCredential, &errFields)
		return nil, nil, errors.WrapErrorAction(logutils.ActionFind, typePhoneCreds, &errFields, nil)
	}

	var user *phoneCreds
	if credential != nil {
		user, err = mapToPhoneCreds(credential.Value)
		if err != nil {
			return nil, nil, err
		}
	}
	if len(credential.ID) > 0 {
		// existing user
		_, err := a.handlePhoneVerify(phone, verificationCreds, false, l)
		if err != nil {
			return nil, nil, err
		}

		return &user.Phone, credential.Value, nil
	}

	// new user
	newCredsMap, err := a.handlePhoneVerify(phone, verificationCreds, true, l)
	if err != nil {
		return nil, nil, err
	}

	return &user.Phone, newCredsMap, errors.ErrorData(logutils.StatusMissing, typePhoneCreds, nil)
}

func (a *phoneAuthImpl) handlePhoneVerify(phone string, verificationCreds phoneCreds, newUser bool, l *logs.Log) (map[string]interface{}, error) {
	data := url.Values{}
	data.Add("to", phone)
	if verificationCreds.Code != "" {
		// check verification
		data.Add("code", verificationCreds.Code)
		return a.checkVerification(a.verifyServiceID, phone, data, newUser, l)
	}

	// start verification
	data.Add("channel", "sms")
	return nil, a.startVerification(a.verifyServiceID, phone, data, l)
}

func (a *phoneAuthImpl) startVerification(verifyServiceID string, phone string, data url.Values, l *logs.Log) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resp, err := makeRequest(ctx, "POST", servicesPathPart+"/"+verifyServiceID+"/"+verificationsPathPart, data)
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
		return errors.ErrorData(logutils.StatusInvalid, typeVerificationStatus, &logutils.FieldArgs{"expected approved, actual:": verifyResult.Status})
	}
	if verifyResult.Sid == "" {
		return errors.ErrorData(logutils.StatusMissing, typeVerificationSID, nil)
	}

	return nil
}

func (a *phoneAuthImpl) checkVerification(verifyServiceID string, phone string, data url.Values, newUser bool, l *logs.Log) (map[string]interface{}, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resp, err := makeRequest(ctx, "POST", servicesPathPart+"/"+verifyServiceID+"/"+verificationCheckPart, data)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionSend, logutils.TypeRequest, nil, err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRead, logutils.TypeResponseBody, nil, err)
	}

	var checkResponse checkStatusResponse
	err = json.Unmarshal(body, &checkResponse)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeVerificationResponse, nil, err)
	}

	if checkResponse.To != phone {
		return nil, errors.ErrorData(logutils.StatusInvalid, logutils.TypeString, &logutils.FieldArgs{"expected phone": phone, "actual phone": checkResponse.To})
	}
	if checkResponse.Status != "approved" {
		return nil, errors.ErrorData(logutils.StatusInvalid, typeVerificationStatus, &logutils.FieldArgs{"expected approved, actual:": checkResponse.Status})
	}

	if newUser {
		newCreds := phoneCreds{}
		newCreds.Phone = phone
		newCreds.Status = "approved"
		credsMap, err := phoneCredsToMap(&newCreds)
		if err != nil {
			return nil, err
		}
		return credsMap, nil
	}

	return nil, nil
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

func makeRequest(ctx context.Context, method string, pathPart string, data url.Values) (*http.Response, error) {
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

func (a *phoneAuthImpl) userExist(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, creds string, l *logs.Log) (*model.Account, *model.AccountAuthType, error) {
	appID := appOrg.Application.ID
	orgID := appOrg.Organization.ID
	authTypeID := authType.ID
	identifier := "" // TODO: fetch from creds

	//FindAccount(appID string, orgID string, authTypeID string, accountAuthTypeIdentifier string) (*model.Account, error)
	account, err := a.auth.storage.FindAccount(appID, orgID, authTypeID, identifier)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err) //TODO add args..
	}

	accountAuthType, err := a.auth.FindAccountAuthType(account, authTypeID, identifier)
	if accountAuthType == nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccountAuthType, nil, err)
	}

	return account, accountAuthType, nil
}

func (a *phoneAuthImpl) verify(accountAuthType *model.AccountAuthType, id string, verification string, l *logs.Log) error {
	return errors.New(logutils.Unimplemented)
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
		return nil, errors.WrapErrorAction(logutils.ActionMarshal, typePhoneCreds, nil, err)
	}
	var creds *phoneCreds
	err = json.Unmarshal(credBytes, creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typePhoneCreds, nil, err)
	}

	return creds, nil
}

//initPhoneAuth initializes and registers a new phone auth instance
func initPhoneAuth(auth *Auth) (*phoneAuthImpl, error) {
	phone := &phoneAuthImpl{auth: auth, authType: authTypePhone, verifyServiceID: auth.phoneVerifyServiceID}

	err := auth.registerAuthType(phone.authType, phone)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeAuthType, nil, err)
	}

	return phone, nil
}
