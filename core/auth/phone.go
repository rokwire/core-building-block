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

type phoneAuthConfig struct {
	AccountSID string `json:"account_sid" validate:"required"`
	AuthToken  string `json:"auth_token" validate:"required"`
	ClientID   string `json:"client_id" validate:"required"`
}

type startVerificationParams struct {
	Channel string `json:"channel" validate:"required"`
	To      string `json:"to" validate:"required"`
}

type checkVerificationParams struct {
	Code            string `json:"code" validate:"required"`
	To              string `json:"to"` // either this parameter or the verification_sid must be specified.
	VerificationSid string `json:"verificationSid"`
}

type verifyPhoneResponse struct {
	Sid         string    `json:"sid"`
	ServiceSid  string    `json:"service_sid"`
	AccountSid  string    `json:"account_sid"`
	To          string    `json:"to" validate:"required"`
	Channel     string    `json:"channel" validate:"required"`
	Status      string    `json:"status"`
	Valid       bool      `json:"valid"`
	Lookup      string    `json:"lookup"`
	Amount      string    `json:"amount"`
	Payee       string    `json:"payee"`
	DateCreated time.Time `json:"date_created"`
	DateUpdated time.Time `json:"date_updated"`
	URL         string    `json:"url"`
}

type checkVerificationResponse struct {
	Sid         string    `json:"sid"`
	ServiceSid  string    `json:"service_sid"`
	AccountSid  string    `json:"account_sid"`
	To          string    `json:"to" validate:"required"`
	Channel     string    `json:"channel"`
	Status      string    `json:"status"`
	Valid       bool      `json:"valid"`
	Amount      string    `json:"amount"`
	Payee       string    `json:"payee"`
	DateCreated time.Time `json:"date_created"`
	DateUpdated time.Time `json:"date_updated"`
}

func (a *phoneAuthImpl) check(creds string, params string) (*UserAuth, error) {
	paramsMap := make(map[string]interface{})
	err := json.Unmarshal([]byte(params), &paramsMap)
	if err != nil {
		return nil, err
	}
	// clientID, ok := paramsMap["clientID"].(string)
	// if !ok {
	// 	return nil, errors.New("ClientID parameter missing or invalid")
	// }

	// sid, ok := paramsMap["sid"].(string)
	// if !ok {
	// 	return nil, errors.New("sid parameter missing or invalid")
	// }
	// token, ok := paramsMap["token"].(string)
	// if !ok {
	// 	return nil, errors.New("token parameter missing or invalid")
	// }

	credType, ok := paramsMap["cred_type"].(string)
	if !ok {
		return nil, errors.New("cred_type parameter missing or invalid")
	}

	// twilioClient := twilio.NewClient(sid, token, nil)
	verifyServiceID := "VA9e0bd45bfa7d9b9e7dca86cf94c7d4f8"

	switch credType {
	case "create":
		var startVerificationParams startVerificationParams
		err = json.Unmarshal([]byte(params), &startVerificationParams)
		if err != nil {
			return nil, err
		}
		validate := validator.New()
		err = validate.Struct(startVerificationParams)
		if err != nil {
			return nil, err
		}

		data := url.Values{}
		data.Add("to", startVerificationParams.To)
		data.Add("channel", startVerificationParams.Channel)

		verifyResponse, err := a.startVerification(verifyServiceID, data)
		if err != nil {
			log.Printf("error in start phone verification - %s", err)
			return nil, err
		}
		if verifyResponse.To != startVerificationParams.To {
			log.Printf("expected To to be %s, got %s", startVerificationParams.To, verifyResponse.To)
			return nil, fmt.Errorf("phone verify expected To to be %s, got %s", startVerificationParams.To, verifyResponse.To)
		}
		if verifyResponse.Valid {
			log.Printf("expected Valid to be %t, got %t", false, true)
			return nil, fmt.Errorf("phone verify expected Valid to be %t, got %t", false, true)
		}
		if verifyResponse.Channel != startVerificationParams.Channel {
			log.Printf("expected Channel to be %s, got %s", startVerificationParams.Channel, verifyResponse.Channel)
			return nil, fmt.Errorf("phone verify expected Channel to be %s, got %s", startVerificationParams.Channel, verifyResponse.Channel)
		}
		// if verifyResponse.Lookup.Carrier.Type != "mobile" {
		// 	t.Errorf("expected Lookup.Carrier to be %s, got %s", "mobile", verifyResponse.Lookup.Carrier.Type)
		// }
		if verifyResponse.Sid == "" {
			log.Println("expected Sid to be non-empty")
			return nil, errors.New("phone verify expected Sid to be non-empty")

		}
		userAuth := UserAuth{}
		userAuth.UserID = verifyResponse.Sid
		userAuth.Phone = verifyResponse.To

		return &userAuth, nil

	case "check":
		var checkVerificationParams checkVerificationParams
		err = json.Unmarshal([]byte(params), &checkVerificationParams)
		if err != nil {
			return nil, err
		}
		validate := validator.New()
		err = validate.Struct(checkVerificationParams)
		if err != nil {
			return nil, err
		}

		data := url.Values{}
		data.Add("code", checkVerificationParams.Code)
		if checkVerificationParams.To != "" {
			data.Add("to", checkVerificationParams.To)
		} else if checkVerificationParams.VerificationSid != "" {
			data.Add("verification_sid", checkVerificationParams.VerificationSid)
		} else {
			return nil, errors.New("Either phone number or verification_sid must be specified")
		}

		checkResponse, err := a.checkVerification(verifyServiceID, data)
		if err != nil {
			log.Printf("error in phone check verification - %s", err)
			return nil, err
		}

		if checkResponse.To != checkVerificationParams.To {
			log.Printf("expected To to be %s, got %s", checkVerificationParams.To, checkResponse.To)
			return nil, fmt.Errorf("phone verify expected To to be %s, got %s", checkVerificationParams.To, checkResponse.To)
		}
		if !checkResponse.Valid {
			log.Printf("expected Valid to be %t, got %t", true, false)
			return nil, fmt.Errorf("phone verify expected Valid to be %t, got %t", true, false)
		}
		if checkResponse.Status != "approved" {
			log.Printf("expected Status to be %s, got %s", "approved", checkResponse.Status)
			return nil, fmt.Errorf("phone verify expected Status to be %s, got %s", "approved", checkResponse.Status)
		}
		// if checkResponse.Channel != checkVerificationParams.Channel {
		// 	log.Printf("expected Channel to be %s, got %s", checkVerificationParams.Channel, checkResponse.Channel)
		// 	return nil, fmt.Errorf("phone verify expected Channel to be %s, got %s", checkVerificationParams.Channel, checkResponse.Channel)
		// }

		userAuth := UserAuth{}
		userAuth.UserID = checkResponse.Sid
		userAuth.Phone = checkResponse.To

		return &userAuth, nil
	}

	return nil, errors.New("Unimplemented")
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

	return &verifyResult, err
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

	return &verifyResult, err
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

	return &verifyResult, err
}

func (a *phoneAuthImpl) checkVerification(verifyServiceID string, data url.Values) (*checkVerificationResponse, error) {
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

	var checkResult checkVerificationResponse
	err = json.Unmarshal(body, &checkResult)
	if err != nil {
		log.Printf("error converting data for checking the verification - %s", err)
		return nil, err
	}

	return &checkResult, err
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
