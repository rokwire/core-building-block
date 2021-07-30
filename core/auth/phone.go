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

	log "github.com/rokmetro/logging-library/loglib"
	"gopkg.in/go-playground/validator.v9"
)

const (
	servicesPathPart                     = "https://verify.twilio.com/v2/Services"
	verificationsPathPart                = "Verifications"
	verificationCheckPart                = "VerificationCheck"
	typeVerifyServiceID      log.LogData = "phone verification service ID"
	typeVerificationResponse log.LogData = "phone verification response"
	typeVerificationStatus   log.LogData = "phone verification staus"
	typeVerificationSID      log.LogData = "phone verification sid"
	typePhoneCreds           log.LogData = "phone creds"
	typePhoneNumber          log.LogData = "E.164 phone number"
)

const (
	authTypePhone string = "phone"
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

func (a *phoneAuthImpl) check(creds string, orgID string, appID string, params string, l *log.Log) (*model.UserAuth, error) {
	var verificationCreds phoneCreds
	err := json.Unmarshal([]byte(creds), &verificationCreds)
	if err != nil {
		return nil, log.WrapActionError(log.ActionUnmarshal, typePhoneCreds, nil, err)
	}
	validate := validator.New()
	err = validate.Struct(verificationCreds)
	if err != nil {
		return nil, log.WrapActionError(log.ActionValidate, typePhoneCreds, nil, err)
	}

	// phoneAuthConfig, err := a.getPhoneAuthConfig(orgID, appID)
	// if err != nil {
	// 	return nil, log.WrapActionError(log.ActionGet, typePhoneAuthConfig, nil, err)
	// }

	if a.verifyServiceID == "" {
		return nil, log.DataError(log.StatusMissing, typeVerifyServiceID, nil)
	}
	
	phone := verificationCreds.Phone
	validPhone := regexp.MustCompile(`^\+[1-9]\d{1,14}$`)
	if !validPhone.MatchString(phone) {
		return nil, log.DataError(log.StatusInvalid, typePhoneNumber, &log.FieldArgs{"phone": phone})
	}

	errFields := log.FieldArgs{"org_id": "", "app_id": "", "type": authTypePhone, "user_id": phone}
	authCreds, err := a.auth.storage.FindCredentials("", "", authTypePhone, phone)
	if err != nil {
		return nil, log.WrapActionError(log.ActionFind, typePhoneCreds, &errFields, nil)
	}

	claims := &model.UserAuth{Phone: phone, UserID: phone}

	if len(authCreds.AccountID) > 0 {
		// existing user
		_, err := a.handlePhoneVerify(phone, verificationCreds, false, l)
		if err != nil {
			return nil, err
		}
		claims.AccountID = authCreds.AccountID
		return claims, nil
	}
	
	// new user
	newCreds, err := a.handlePhoneVerify(phone, verificationCreds, true, l)
	if err != nil {
		return nil, err
	}
	if newCreds != nil {
		authCreds.Creds = newCreds
		if err = a.auth.storage.UpdateCredentials("", "", authTypePhone, authCreds); err != nil {
			return nil, log.WrapActionError(log.ActionInsert, model.TypeAuthCred, nil, err)
		}
		claims.NewCreds = newCreds
		return claims, nil
	}

	return nil, log.DataError(log.StatusMissing, typePhoneCreds, nil)
}

func (a *phoneAuthImpl) handlePhoneVerify(phone string, verificationCreds phoneCreds, newUser bool, l *log.Log) (*phoneCreds, error) {
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

func (a *phoneAuthImpl) startVerification(verifyServiceID string, phone string, data url.Values, l *log.Log) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resp, err := makeRequest(ctx, "POST", servicesPathPart+"/"+verifyServiceID+"/"+verificationsPathPart, data)
	if err != nil {
		return log.WrapActionError(log.ActionSend, log.TypeRequest, &log.FieldArgs{"verification params": data}, err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return log.WrapActionError(log.ActionRead, log.TypeResponseBody, nil, err)
	}

	var verifyResult verifyPhoneResponse
	err = json.Unmarshal(body, &verifyResult)
	if err != nil {
		return log.WrapActionError(log.ActionUnmarshal, typeVerificationResponse, nil, err)
	}

	if verifyResult.To != phone {
		return log.DataError(log.StatusInvalid, log.TypeString, &log.FieldArgs{"expected phone": phone, "actual phone": verifyResult.To})
	}
	if verifyResult.Status != "pending" {
		return log.DataError(log.StatusInvalid, typeVerificationStatus, &log.FieldArgs{"expected approved, actual:": verifyResult.Status})
	}
	if verifyResult.Sid == "" {
		return log.DataError(log.StatusMissing, typeVerificationSID, nil)
	}

	return nil
}

func (a *phoneAuthImpl) checkVerification(verifyServiceID string, phone string, data url.Values, newUser bool, l *log.Log) (*phoneCreds, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resp, err := makeRequest(ctx, "POST", servicesPathPart+"/"+verifyServiceID+"/"+verificationCheckPart, data)
	if err != nil {
		return nil, log.WrapActionError(log.ActionSend, log.TypeRequest, nil, err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, log.WrapActionError(log.ActionRead, log.TypeResponseBody, nil, err)
	}

	var checkResponse checkStatusResponse
	err = json.Unmarshal(body, &checkResponse)
	if err != nil {
		return nil, log.WrapActionError(log.ActionUnmarshal, typeVerificationResponse, nil, err)
	}

	if checkResponse.To != phone {
		return nil, log.DataError(log.StatusInvalid, log.TypeString, &log.FieldArgs{"expected phone": phone, "actual phone": checkResponse.To})
	}
	if checkResponse.Status != "approved" {
		return nil, log.DataError(log.StatusInvalid, typeVerificationStatus, &log.FieldArgs{"expected approved, actual:": checkResponse.Status})
	}

	if newUser {
		newCreds := phoneCreds{}
		newCreds.Phone = phone
		newCreds.Status = "approved"
		return &newCreds, nil
	}
	
	return nil, nil
}

// func (a *phoneAuthImpl) getPhoneAuthConfig(orgID string, appID string) (*phoneAuthConfig, error) {
// 	errFields := &log.FieldArgs{"org_id": orgID, "app_id": appID, "auth_type": a.authType}

// 	authConfig, err := a.auth.getAuthConfig(orgID, appID, "phone")
// 	if err != nil {
// 		return nil, log.WrapActionError(log.ActionFind, model.TypeAuthConfig, errFields, err)
// 	}

// 	var phoneConfig phoneAuthConfig
// 	err = json.Unmarshal(authConfig.Config, &phoneConfig)
// 	if err != nil {
// 		return nil, log.WrapActionError(log.ActionUnmarshal, model.TypeAuthConfig, errFields, err)
// 	}
// 	validate := validator.New()
// 	err = validate.Struct(phoneConfig)
// 	if err != nil {
// 		return nil, log.WrapActionError(log.ActionValidate, model.TypeAuthConfig, errFields, err)
// 	}

// 	return &phoneConfig, nil
// }

func makeRequest(ctx context.Context, method string, pathPart string, data url.Values) (*http.Response, error) {
	client := &http.Client{}
	rb := new(strings.Reader)
	logAction := log.ActionSend

	if data != nil && (method == "POST" || method == "PUT") {
		rb = strings.NewReader(data.Encode())
	}
	if method == "GET" && data != nil {
		pathPart = pathPart + "?" + data.Encode()
		logAction = log.ActionRead
	}

	req, err := http.NewRequestWithContext(ctx, method, pathPart, rb)
	if err != nil {
		return nil, log.WrapActionError(logAction, log.TypeRequest, &log.FieldArgs{"path": pathPart}, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, log.WrapActionError(logAction, log.TypeRequest, nil, err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, log.WrapActionError(log.ActionRead, log.TypeRequestBody, nil, err)
	}
	if resp.StatusCode != 200 {
		return nil, log.DataError(log.StatusInvalid, log.TypeResponse, &log.FieldArgs{"status_code": resp.StatusCode, "error": string(body)})
	}
	return resp, nil
}

func (a *phoneAuthImpl) verify(id string, verification string, l *log.Log) error {
	return nil
}

//refresh is enabled for phone auth, but no operation is needed
func (a *phoneAuthImpl) refresh(refreshToken string, orgID string, appID string, l *log.Log) (*model.UserAuth, error) {
	return nil, nil
}

func (a *phoneAuthImpl) getLoginUrl(orgID string, appID string, redirectUri string, l *log.Log) (string, map[string]interface{}, error) {
	return "", nil, log.NewErrorf("get login url operation invalid for auth_type=%s", a.authType)
}

//initPhoneAuth initializes and registers a new phone auth instance
func initPhoneAuth(auth *Auth) (*phoneAuthImpl, error) {
	phone := &phoneAuthImpl{auth: auth, authType: authTypePhone}

	err := auth.registerAuthType(phone.authType, phone)
	if err != nil {
		return nil, log.WrapActionError(log.ActionRegister, typeAuthType, nil, err)
	}

	return phone, nil
}
