package auth

import (
	"context"
	"core-building-block/core/model"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	log "github.com/rokmetro/logging-library/loglib"
	"gopkg.in/go-playground/validator.v9"
)

const (
	servicesPathPart                     = "https://verify.twilio.com/v2/Services"
	verificationsPathPart                = "Verifications"
	verificationCheckPart                = "VerificationCheck"
	typeVerificationResponse log.LogData = "phone verification response"
	typeVerificationStatus   log.LogData = "phone verification staus"
)

// Phone implementation of authType
type phoneAuthImpl struct {
	auth *Auth
}

type phoneCreds struct {
	Phone  string `json:"phone"`
	Status string `json:"status"`
	// TODO: Password
}

type phoneAuthConfig struct {
	VerifyServiceID string `json:"verify_service_id" validate:"required"`
	// AccountSID string `json:"account_sid" validate:"required"`
	// AuthToken  string `json:"auth_token" validate:"required"`
}

type verificationParams struct {
	Code string `json:"code"`
	To   string `json:"to" validate:"required"`
	// OrgID string `json:"org_id" validate:"required"`
	// AppID string `json:"app_id" validate:"required"`
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

func (a *phoneAuthImpl) check(creds string, params string, l *log.Log) (*model.UserAuth, error) {
	var verificationCreds verificationParams
	err := json.Unmarshal([]byte(creds), &verificationCreds)
	if err != nil {
		return nil, err
	}
	validate := validator.New()
	err = validate.Struct(verificationCreds)
	if err != nil {
		return nil, err
	}

	// TODO: fetch phone cred from db if needed, might add password to phone creds later
	// phoneCred := auth.storage.getCredential("phone", phoneNumber)

	// TODO: orgID string, appID string will be in input params
	orgID, appID := "", ""
	phoneAuthConfig, err := a.getPhoneAuthConfig(orgID, appID)
	if err != nil {
		return nil, fmt.Errorf("auth config for orgID %s, appID %s cannot be used for phone verify: %s", appID, orgID, err.Error())
	}
	verifyServiceID := phoneAuthConfig.VerifyServiceID
	data := url.Values{}
	phone := verificationCreds.To
	data.Add("to", phone)

	if verificationCreds.Code != "" {
		// handle check verification
		code := verificationCreds.Code
		data.Add("code", code)
		return a.checkVerification(verifyServiceID, phone, data, l)
	}

	// handle start verification
	data.Add("channel", "sms")
	return a.startVerification(verifyServiceID, phone, data, l)
}

func (a *phoneAuthImpl) startVerification(verifyServiceID string, phone string, data url.Values, l *log.Log) (*model.UserAuth, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resp, err := makeRequest(ctx, "POST", servicesPathPart+"/"+verifyServiceID+"/"+verificationsPathPart, data)
	if err != nil {
		return nil, log.WrapActionError(log.ActionSend, log.TypeRequest, &log.FieldArgs{"verification data": data}, err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, log.WrapActionError(log.ActionRead, log.TypeResponseBody, nil, err)
	}

	var verifyResult verifyPhoneResponse
	err = json.Unmarshal(body, &verifyResult)
	if err != nil {
		return nil, log.WrapActionError(log.ActionUnmarshal, typeVerificationResponse, nil, err)
	}

	if verifyResult.To != phone {
		return nil, log.DataError(log.StatusInvalid, log.TypeString, &log.FieldArgs{"phone verify To expected to be": phone, " but got ": verifyResult.To})
	}
	if verifyResult.Status != "pending" {
		return nil, log.DataError(log.StatusInvalid, typeVerificationStatus, &log.FieldArgs{"check verify response status should be approved, but got ": verifyResult.Status})
	}
	if verifyResult.Sid == "" {
		return nil, log.DataError(log.StatusInvalid, typeVerificationStatus, &log.FieldArgs{"check verify response sid should be specified, but got ": verifyResult.Status})
	}

	return nil, nil
}

func (a *phoneAuthImpl) checkVerification(verifyServiceID string, phone string, data url.Values, l *log.Log) (*model.UserAuth, error) {
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
		return nil, log.DataError(log.StatusInvalid, log.TypeString, &log.FieldArgs{"phone verify To expected to be": phone, " but got ": checkResponse.To})
		// return nil, fmt.Errorf("phone verify expected To to be %s, got %s", phone, checkResponse.To)
	}
	if checkResponse.Status != "approved" {
		return nil, log.DataError(log.StatusInvalid, typeVerificationStatus, &log.FieldArgs{"check verify response status should be approved, but got ": checkResponse.Status})
		// return nil, fmt.Errorf("phone verify expected Status to be %s, got %s", "approved", checkResponse.Status)
	}

	userAuth := model.UserAuth{}
	userAuth.UserID = checkResponse.Sid
	userAuth.Phone = checkResponse.To

	return &userAuth, nil
}

func (a *phoneAuthImpl) getPhoneAuthConfig(orgID string, appID string) (*phoneAuthConfig, error) {
	authConfig, err := a.auth.getAuthConfig(orgID, appID, "phone")
	if err != nil {
		return nil, err
	}

	configBytes, err := json.Marshal(authConfig.Config)
	if err != nil {
		return nil, err
	}
	var phoneConfig phoneAuthConfig
	err = json.Unmarshal(configBytes, &phoneConfig)
	if err != nil {
		return nil, err
	}
	validate := validator.New()
	err = validate.Struct(phoneConfig)
	if err != nil {
		return nil, err
	}

	return &phoneConfig, nil
}

func makeRequest(ctx context.Context, method string, pathPart string, data url.Values) (*http.Response, error) {
	client := &http.Client{}
	rb := new(strings.Reader)
	if data != nil && (method == "POST" || method == "PUT") {
		rb = strings.NewReader(data.Encode())
	}
	if method == "GET" && data != nil {
		pathPart = pathPart + "?" + data.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, method, pathPart, rb)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
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

//initPhoneAuth initializes and registers a new phone auth instance
func initPhoneAuth(auth *Auth) (*phoneAuthImpl, error) {
	phone := &phoneAuthImpl{auth: auth}

	err := auth.registerAuthType("phone", phone)
	if err != nil {
		return nil, log.WrapActionError(log.ActionRegister, typeAuthType, nil, err)
	}

	return phone, nil
}
