package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/google/uuid"
)

// SAML implementation of authType
type samlAuthImpl struct {
	auth *Auth
}

type samlCheckParams struct {
	Web bool `json:"web"`
}

type samlLoginParams struct {
	Web     bool   `json:"web"`
	xmlBlob []byte `json:"xml_blob"`
}

type samlRefreshParams struct {
	Web bool `json:"web"`
}

type samlRequest struct {
	XMLName                       xml.Name `xml:"samlp:AuthnRequest"`
	XMLNSsamlp                    string   `xml:"xmlns:samlp,attr"`
	XMLNSsaml                     string   `xml:"xmlns:saml,attr"`
	ID                            string   `xml:",attr"`
	Version                       string   `xml:",attr"`
	IssueInstant                  string   `xml:",attr"`
	AssertionConsumerServiceIndex string   `xml:",attr"`
	Issuer                        samlIssuer
	NameIDPolicy                  samlNameIDPolicy
}

type samlArtifactRequest struct {
	XMLName      xml.Name `xml:"samlp:ArtifactResolve"`
	XMLNSsamlp   string   `xml:"xmlns:samlp,attr"`
	XMLNSsaml    string   `xml:"xmlns:saml,attr"`
	ID           string   `xml:",attr"`
	Version      string   `xml:",attr"`
	IssueInstant string   `xml:",attr"`
	Destination  string   `xml:",attr"`
	Issuer       samlIssuer
	Signature    samlSignature
	Artifact     samlArtifact
}

type samlArtifactResponse struct {
	XMLName      xml.Name `xml:"ArtifactResponse"`
	XMLNSsamlp   string   `xml:"xmlns:samlp,attr"`
	ID           string   `xml:",attr"`
	InResponseTo string   `xml:",attr"`
	Version      string   `xml:",attr"`
	IssueInstant string   `xml:",attr"`
	Signature    samlSignature
	StatusCode   samlStatusCode `xml:"Status>StatusCode"`
	Response     samlResponse
}

type samlIssuer struct {
	XMLName xml.Name `xml:"saml:Issuer"`
	URL     string   `xml:",chardata"`
}

type samlNameIDPolicy struct {
	XMLName     xml.Name `xml:"samlp:NameIDPolicy"`
	AllowCreate string   `xml:",attr"`
	Format      string   `xml:",attr"`
}

type samlArtifact struct {
	XMLName xml.Name `xml:"Artifact"`
	Value   string   `xml:",chardata"`
}

type samlSignature struct {
	XMLName xml.Name `xml:"Signature"`
	XMLNSds string   `xml:"xmlns:ds,attr"`
	// potentially many more members
}

type samlEncryptedAssertion struct {
	XMLName xml.Name `xml:"EncryptedAssertion"`
}

type samlResponse struct {
	XMLName            xml.Name `xml:"Response"`
	EncryptedAssertion samlEncryptedAssertion
	StatusCode         samlStatusCode `xml:"Status>StatusCode"`
}

type samlStatusCode struct {
	XMLName xml.Name `xml:"StatusCode"`
	Value   string   `xml:",attr"`
}

func (a *samlAuthImpl) login(creds string, params string) (map[string]interface{}, error) {
	//TODO: Implement
	return nil, errors.New("Unimplemented")
}

// What defines web session vs mobile "session"?
func (a *samlAuthImpl) sessionLogin(creds string, params samlLoginParams) (map[string]interface{}, error) {
	var xmlBlob []byte
	var rawResponseBody []byte
	if params.Web {
		// SAMPLE DATA (WILL CHANGE)
		requestID, err := uuid.NewUUID()
		if err != nil {
			return nil, err
		}
		issuer := samlIssuer{URL: "https://sp.example.com"}
		nameIDPolicy := samlNameIDPolicy{AllowCreate: "true", Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"}
		request := samlRequest{
			XMLNSsamlp:                    "urn:oasis:names:tc:SAML:2.0:protocol",
			XMLNSsaml:                     "urn:oasis:names:tc:SAML:2.0:assertion",
			ID:                            requestID.String(),
			Version:                       "2.0",
			IssueInstant:                  time.Now().UTC().Format("2006-01-02T15:04:05Z"),
			AssertionConsumerServiceIndex: "1",
			Issuer:                        issuer,
			NameIDPolicy:                  nameIDPolicy,
		}
		xmlData, err := xml.Marshal(request)
		if err != nil {
			return nil, err
		}

		bodyData := map[string]string{
			"SAMLRequest": base64.StdEncoding.EncodeToString(xmlData),
			// "RelayState":  "", // optional (encoded string to track some state)
		}
		uri := url.URL{}
		for k, v := range bodyData {
			if len(uri.RawQuery) < 1 {
				uri.RawQuery += fmt.Sprintf("%s=%s", k, v)
			} else {
				uri.RawQuery += fmt.Sprintf("&%s=%s", k, v)
			}
		}
		headers := map[string]string{
			"Content-Type":   "application/x-www-form-urlencoded",
			"Content-Length": strconv.Itoa(len(uri.Query().Encode())),
		}
		jsonData, err := json.Marshal(bodyData)
		if err != nil {
			return nil, err
		}

		client := &http.Client{}
		req, err := http.NewRequest("POST", "http://idp.example.org/saml2/sso/post", bytes.NewReader(jsonData))
		if err != nil {
			return nil, err
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}

		defer resp.Body.Close()
		rawResponseBody, err = ioutil.ReadAll(resp.Body)
		if resp.StatusCode != 200 {
			return nil, errors.New("error with response code != 200")
		}
		if err != nil {
			return nil, err
		}
	}

	// decrypt assertion (if encrypted)
	if len(params.xmlBlob) > 0 {
		xmlBlob = params.xmlBlob
	} else if len(rawResponseBody) > 0 {
		xmlBlob = rawResponseBody
	} else {
		return nil, errors.New("no SAML response to parse")
	}
	// check if received artifact, send request to IDP's artifact resolution service if so

	// check if SAML assertion in response is encrypted, if so decrypt first, then parse
	var response samlResponse
	err := xml.Unmarshal([]byte(xmlBlob), &response)
	if err != nil {
		return nil, err
	}

	return nil, errors.New("Unimplemented")
}

// use if there is no way to refresh user's session
func (a *samlAuthImpl) sessionLogout() {

}

//initSamlAuth initializes and registers a new SAML auth instance
func initSamlAuth(auth *Auth) (*samlAuthImpl, error) {
	saml := &samlAuthImpl{auth: auth}

	err := auth.registerAuthType("saml", saml)
	if err != nil {
		return nil, err
	}

	return saml, nil
}
