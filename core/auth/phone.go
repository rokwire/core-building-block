package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"gopkg.in/go-playground/validator.v9"
)

// Verify service
// const VerifyBaseURL = "https://verify.twilio.com"
// const VerifyVersion = "v2"
const servicesPathPart = "https://verify.twilio.com/v2/Services"
const verificationsPathPart = "Verifications"
const verificationCheckPart = "VerificationCheck"

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

func (a *phoneAuthImpl) check(creds string, params string) (*UserAuth, error) {
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

		checkResponse, err := a.checkVerification(verifyServiceID, data)
		if err != nil {
			log.Printf("error in phone check verification - %s", err)
			return nil, err
		}

		if checkResponse.To != phone {
			log.Printf("expected To to be %s, got %s", phone, checkResponse.To)
			return nil, fmt.Errorf("phone verify expected To to be %s, got %s", phone, checkResponse.To)
		}
		if checkResponse.Status != "approved" {
			log.Printf("expected Status to be %s, got %s", "approved", checkResponse.Status)
			return nil, fmt.Errorf("phone verify expected Status to be %s, got %s", "approved", checkResponse.Status)
		}

		userAuth := UserAuth{}
		userAuth.UserID = checkResponse.Sid
		userAuth.Phone = checkResponse.To

		return &userAuth, nil

	} else {
		// handle start verification
		data.Add("channel", "sms")

		verifyResponse, err := a.startVerification(verifyServiceID, data)
		if err != nil {
			log.Printf("error starting phone verification - %s", err)
			return nil, err
		}
		if verifyResponse.To != phone {
			log.Printf("expected To to be %s, got %s", phone, verifyResponse.To)
			return nil, fmt.Errorf("phone verify expected To to be %s, got %s", phone, verifyResponse.To)
		}
		if verifyResponse.Status != "pending" {
			log.Printf("expected Status to be %s, got %s", "pending", verifyResponse.Status)
			return nil, fmt.Errorf("phone verify expected Status to be %s, got %s", "pending", verifyResponse.Status)
		}
		if verifyResponse.Channel != "sms" {
			log.Printf("expected Channel to be %s, got %s", "sms", verifyResponse.Channel)
			return nil, fmt.Errorf("phone verify expected Channel to be %s, got %s", "sms", verifyResponse.Channel)
		}
		if verifyResponse.Sid == "" {
			log.Println("expected Sid to be non-empty")
			return nil, errors.New("phone verify expected Sid to be non-empty")
		}
	}

	return nil, nil
}

func (a *phoneAuthImpl) startVerification(verifyServiceID string, data url.Values) (*verifyPhoneResponse, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resp, err := makeRequest(ctx, "POST", servicesPathPart+"/"+verifyServiceID+"/"+verificationsPathPart, data)
	if err != nil {
		log.Printf("error creating phone verification services - %s", err.Error())
		// return fmt.Errorf("error creating phone verification service - %s", err.Error())
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("error reading the body data for starting verification - %s", err)
		return nil, err
	}

	var verifyResult verifyPhoneResponse
	err = json.Unmarshal(body, &verifyResult)
	if err != nil {
		log.Printf("error converting data for starting the verification - %s", err)
		return nil, err
	}

	return &verifyResult, nil
}

func (a *phoneAuthImpl) fetchVerification(verifyServiceID string, sid string) (*verifyPhoneResponse, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resp, err := makeRequest(ctx, "GET", servicesPathPart+"/"+verifyServiceID+"/"+verificationsPathPart+"/"+sid, nil)
	if err != nil {
		log.Printf("error fetching phone verification - %s", err.Error())
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("error reading the body data for fetching verification - %s", err)
	}

	var verifyResult verifyPhoneResponse
	err = json.Unmarshal(body, &verifyResult)
	if err != nil {
		log.Printf("error converting data for fetching the verification - %s", err)
		return nil, err
	}

	return &verifyResult, nil
}

func (a *phoneAuthImpl) updateVerification(verifyServiceID string, sid string) (*verifyPhoneResponse, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resp, err := makeRequest(ctx, "PUT", servicesPathPart+"/"+verifyServiceID+"/"+verificationsPathPart+"/"+sid, nil)
	if err != nil {
		log.Printf("error updating phone verification - %s", err.Error())
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("error reading the body data for updating verification - %s", err)
	}

	var verifyResult verifyPhoneResponse
	err = json.Unmarshal(body, &verifyResult)
	if err != nil {
		log.Printf("error converting data for updating the verification - %s", err)
		return nil, err
	}

	return &verifyResult, nil
}

func (a *phoneAuthImpl) checkVerification(verifyServiceID string, data url.Values) (*checkStatusResponse, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resp, err := makeRequest(ctx, "POST", servicesPathPart+"/"+verifyServiceID+"/"+verificationCheckPart, data)
	if err != nil {
		log.Printf("error checking phone verification - %s", err.Error())
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("error reading the body data for checking verification - %s", err)
	}

	var checkResult checkStatusResponse
	err = json.Unmarshal(body, &checkResult)
	if err != nil {
		log.Printf("error converting data for checking the verification - %s", err)
		return nil, err
	}

	return &checkResult, nil
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

	if resp.StatusCode != 200 {
		log.Printf("makeRequest() -> error with response code - %d, response body - %s\n", resp.StatusCode, resp.Body)
		// log.Printf("makeRequest() -> error with response body - %s", resp.Body)
		return nil, errors.New("makeRequest() -> error with response code != 200")
	}

	return resp, nil
}

//initPhoneAuth initializes and registers a new phone auth instance
func initPhoneAuth(auth *Auth) (*phoneAuthImpl, error) {
	phone := &phoneAuthImpl{auth: auth}

	err := auth.registerAuthType("phone", phone)
	if err != nil {
		log.Printf("error initializing phone auth - %s", err)
		return nil, err
	}

	return phone, nil
}
