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
	typeVerificationResponse log.LogData = "phone verification response"
	typeVerificationStatus   log.LogData = "phone verification staus"
	typeVerificationSID      log.LogData = "phone verification sid"
	typePhoneAuthConfig      log.LogData = "phone auth config"
	typePhoneNumber          log.LogData = "E.164 phone number"
)

const (
	authTypePhone string = "phone"
)

// Phone implementation of authType
type phoneAuthImpl struct {
	auth     *Auth
	authType string
}

type phoneCreds struct {
	Phone  string `json:"phone"`
	Status string `json:"status"`
	// TODO: Password
}

type phoneAuthConfig struct {
	VerifyServiceID string `json:"verify_service_id" validate:"required"`
}

type verificationParams struct {
	Code string `json:"code"`
	To   string `json:"to" validate:"required"`
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

	phoneAuthConfig, err := a.getPhoneAuthConfig(orgID, appID)
	if err != nil {
		return nil, log.WrapActionError(log.ActionGet, typePhoneAuthConfig, nil, err)
	}
	verifyServiceID := phoneAuthConfig.VerifyServiceID
	data := url.Values{}
	phone := verificationCreds.To
	validPhone := regexp.MustCompile(`^\+[1-9]\d{1,14}$`)
	if !validPhone.MatchString(phone) {
		return nil, log.DataError(log.StatusInvalid, typePhoneNumber, &log.FieldArgs{"phone": phone})
	}

	data.Add("to", phone)
	if verificationCreds.Code != "" {
		data.Add("code", verificationCreds.Code)
		return a.checkVerification(verifyServiceID, phone, data, l)
	}

	data.Add("channel", "sms")
	return a.startVerification(verifyServiceID, phone, data, l)
}

func (a *phoneAuthImpl) startVerification(verifyServiceID string, phone string, data url.Values, l *log.Log) (*model.UserAuth, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resp, err := makeRequest(ctx, "POST", servicesPathPart+"/"+verifyServiceID+"/"+verificationsPathPart, data)
	if err != nil {
		return nil, log.WrapActionError(log.ActionSend, log.TypeRequest, &log.FieldArgs{"verification params": data}, err)
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
		return nil, log.DataError(log.StatusInvalid, log.TypeString, &log.FieldArgs{"expected phone": phone, "actual phone": verifyResult.To})
	}
	if verifyResult.Status != "pending" {
		return nil, log.DataError(log.StatusInvalid, typeVerificationStatus, &log.FieldArgs{"expected approved, actual:": verifyResult.Status})
	}
	if verifyResult.Sid == "" {
		return nil, log.DataError(log.StatusMissing, typeVerificationSID, nil)
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
		return nil, log.DataError(log.StatusInvalid, log.TypeString, &log.FieldArgs{"expected phone": phone, "actual phone": checkResponse.To})
	}
	if checkResponse.Status != "approved" {
		return nil, log.DataError(log.StatusInvalid, typeVerificationStatus, &log.FieldArgs{"expected approved, actual:": checkResponse.Status})
	}

	userAuth := model.UserAuth{}
	userAuth.UserID = checkResponse.Sid
	userAuth.Phone = checkResponse.To

	return &userAuth, nil
}

func (a *phoneAuthImpl) getPhoneAuthConfig(orgID string, appID string) (*phoneAuthConfig, error) {
	errFields := &log.FieldArgs{"org_id": orgID, "app_id": appID, "auth_type": a.authType}

	authConfig, err := a.auth.getAuthConfig(orgID, appID, "phone")
	if err != nil {
		return nil, log.WrapActionError(log.ActionFind, model.TypeAuthConfig, errFields, err)
	}

	var phoneConfig phoneAuthConfig
	err = json.Unmarshal(authConfig.Config, &phoneConfig)
	if err != nil {
		return nil, log.WrapActionError(log.ActionUnmarshal, model.TypeAuthConfig, errFields, err)
	}
	validate := validator.New()
	err = validate.Struct(phoneConfig)
	if err != nil {
		return nil, log.WrapActionError(log.ActionValidate, model.TypeAuthConfig, errFields, err)
	}

	return &phoneConfig, nil
}

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
