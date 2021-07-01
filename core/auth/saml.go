package auth

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// SAML implementation of authType
type samlAuthImpl struct {
	auth *Auth
}

type samlLoginParams struct {
	Web bool `json:"web"`
	// xmlBlob []byte `json:"xml_blob"`
}

type samlRequest struct {
	XMLName                     xml.Name `xml:"samlp:AuthnRequest"`
	XMLNSsamlp                  string   `xml:"xmlns:samlp,attr"`
	ID                          string   `xml:",attr"`
	Destination                 string   `xml:",attr"`
	Version                     string   `xml:",attr"`
	IssueInstant                string   `xml:",attr"`
	ProtocolBinding             string   `xml:",attr"`
	AssertionConsumerServiceURL string   `xml:",attr"`
	Issuer                      samlIssuer
	NameIDPolicy                samlNameIDPolicy
}

type samlArtifactRequest struct {
	XMLName      xml.Name `xml:"samlp:ArtifactResolve"`
	XMLNSsamlp   string   `xml:"xmlns:samlp,attr"`
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
	Artifact     samlArtifact
}

type samlIssuer struct {
	XMLName   xml.Name `xml:"saml:Issuer"`
	XMLNSsaml string   `xml:"xmlns:saml,attr"`
	URL       string   `xml:",chardata"`
}

type samlNameIDPolicy struct {
	XMLName     xml.Name `xml:"samlp:NameIDPolicy"`
	AllowCreate string   `xml:",attr"`
	// Format      string   `xml:",attr"`
}

type samlArtifact struct {
	XMLName xml.Name `xml:"Artifact"`
	Value   string   `xml:",chardata"`
}

type samlSignature struct {
	XMLName xml.Name `xml:"ds:Signature"`
	XMLNSds string   `xml:"xmlns:ds,attr"`
	// potentially many more members
}

type samlAssertion struct {
	XMLName       xml.Name `xml:"Assertion"`
	AuthStatement samlAuthStatement
	Attributes    []samlAttribute `xml:"AttributeStatement>Attribute"`
}

type samlAuthStatement struct {
	XMLName        xml.Name  `xml:"AuthnStatement"`
	IssueTime      time.Time `xml:"AuthnInstant,attr"`
	ExpirationTime time.Time `xml:"SessionNotOnOrAfter,attr"`
	SessionIndex   string    `xml:",attr"`
}

type samlAttribute struct {
	XMLName xml.Name             `xml:"Attribute"`
	Name    string               `xml:",attr"`
	Values  []samlAttributeValue `xml:"AttributeValue"`
}

type samlAttributeValue struct {
	XMLName xml.Name `xml:"AttributeValue"`
	Type    string   `xml:"type,attr"`
	Value   string   `xml:",chardata"`
}

type samlEncryptedAssertion struct {
	XMLName       xml.Name `xml:"EncryptedAssertion"`
	EncryptedData samlEncryptedData
}

type samlEncryptedData struct {
	XMLName      xml.Name         `xml:"EncryptedData"`
	EncryptedKey samlEncryptedKey `xml:"KeyInfo>EncryptedKey"`
	CipherText   string           `xml:"CipherData>CipherValue"`
}

type samlEncryptedKey struct {
	XMLName    xml.Name `xml:"EncryptedKey"`
	CipherText string   `xml:"CipherData>CipherValue"`
}

type samlResponse struct {
	XMLName            xml.Name `xml:"Response"`
	Assertion          samlAssertion
	EncryptedAssertion samlEncryptedAssertion
	StatusCode         samlStatusCode `xml:"Status>StatusCode"`
}

type samlStatusCode struct {
	XMLName xml.Name `xml:"StatusCode"`
	Value   string   `xml:",attr"`
}

func (a *samlAuthImpl) login(creds string, params string) (map[string]interface{}, error) {
	paramsMap := make(map[string]interface{})
	err := json.Unmarshal([]byte(params), &paramsMap)
	if err != nil {
		return nil, err
	}
	credType, ok := paramsMap["cred_type"].(string)
	if !ok {
		return nil, errors.New("cred_type parameter missing or invalid")
	}

	switch credType {
	case "saml_xml":
		var loginParams samlLoginParams
		err := json.Unmarshal([]byte(params), &loginParams)
		if err != nil {
			return nil, err
		}
		samlXML := []byte(creds)
		return a.sessionLogin(samlXML, loginParams)
	case "web_nil":
		var loginParams samlLoginParams
		err := json.Unmarshal([]byte(params), &loginParams)
		if err != nil {
			return nil, err
		}
		return a.sessionLogin(nil, loginParams)
	default:
		return nil, errors.New("unimplemented cred_type")
	}
}

func (a *samlAuthImpl) sessionLogin(samlXML []byte, params samlLoginParams) (map[string]interface{}, error) {
	var xmlBlob []byte
	var rawResponseBody []byte
	var err error
	if params.Web {
		rawResponseBody, err = a.sendSamlRequest()
		if err != nil {
			return nil, err
		}
	}
	if len(samlXML) > 0 {
		// received SAML response XML from mobile client
		xmlBlob = samlXML
	} else if len(rawResponseBody) > 0 {
		// received SAML response XML from previous request (web)
		xmlBlob = rawResponseBody
	} else {
		return nil, errors.New("no SAML response to parse")
	}

	// check if received artifact
	var artifactResp samlArtifactResponse
	err = xml.Unmarshal([]byte(xmlBlob), &artifactResp)
	if err == nil {
		rawResponseBody, err = a.sendSamlArtifactRequest(artifactResp.Artifact.Value)
		if err != nil {
			return nil, err
		}
		if len(rawResponseBody) > 0 {
			xmlBlob = rawResponseBody
		}
	}

	var response samlResponse
	err = xml.Unmarshal([]byte(xmlBlob), &response)
	if err != nil {
		return nil, err
	}
	if !strings.Contains(response.StatusCode.Value, "Success") {
		return nil, errors.New(fmt.Sprintf("saml response error: %s", response.StatusCode.Value))
	}

	// check signatures if desired

	if len(response.EncryptedAssertion.XMLName.Space) > 0 {
		privateKey := "" // load this from environment/secrets
		key, err := decryptKey(response.EncryptedAssertion.EncryptedData.EncryptedKey.CipherText, privateKey)
		if err != nil {
			return nil, err
		}
		decryptedXML, err := decryptXML(response.EncryptedAssertion.EncryptedData.CipherText, key)
		if err != nil {
			return nil, err
		}

		err = xml.Unmarshal(decryptedXML, &response.Assertion)
		if err != nil {
			return nil, err
		}
	}

	// claims to be returned may change
	claimsMap := make(map[string]interface{}, 0)
	for _, attribute := range response.Assertion.Attributes {
		if len(attribute.Values) > 0 {
			attrList := make([]string, 0)
			for _, val := range attribute.Values {
				attrList = append(attrList, val.Value)
			}
			claimsMap[attribute.Name] = attrList
		} else {
			claimsMap[attribute.Name] = attribute.Values[0].Value
		}
	}
	claimsMap["exp"] = response.Assertion.AuthStatement.ExpirationTime
	claimsMap["session_id"] = response.Assertion.AuthStatement.SessionIndex

	return claimsMap, nil
}

func (a *samlAuthImpl) sendSamlRequest() ([]byte, error) {
	// SAMPLE DATA
	requestID, err := uuid.NewUUID()
	if err != nil {
		return nil, err
	}
	request := samlRequest{
		XMLNSsamlp:                  "urn:oasis:names:tc:SAML:2.0:protocol",
		ID:                          requestID.String(),
		Destination:                 "https://idp.example.com/idp/profile/SAML2/POST/SSO",
		Version:                     "2.0",
		IssueInstant:                time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		ProtocolBinding:             "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
		AssertionConsumerServiceURL: "https://dev.rokwire.com",
		Issuer:                      samlIssuer{URL: "https://dev.rokwire.com", XMLNSsaml: "urn:oasis:names:tc:SAML:2.0:assertion"},
		NameIDPolicy:                samlNameIDPolicy{AllowCreate: "1"},
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
	req, err := http.NewRequest("POST", request.Destination, bytes.NewReader(jsonData))
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
	body, err := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, errors.New("error with response code != 200")
	}
	if err != nil {
		return nil, err
	}
	return body, nil
}

func (a *samlAuthImpl) sendSamlArtifactRequest(artifact string) ([]byte, error) {
	// SAMPLE DATA
	requestID, err := uuid.NewUUID()
	if err != nil {
		return nil, err
	}
	request := samlArtifactRequest{
		XMLNSsamlp:   "urn:oasis:names:tc:SAML:2.0:protocol",
		ID:           requestID.String(),
		Destination:  "https://idp.example.com/idp/profile/SAML2/SOAP/ArtifactResolution",
		Version:      "2.0",
		IssueInstant: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		Issuer:       samlIssuer{URL: "https://dev.rokwire.com", XMLNSsaml: "urn:oasis:names:tc:SAML:2.0:assertion"},
		Artifact:     samlArtifact{Value: artifact},
	}
	xmlData, err := xml.Marshal(request)
	if err != nil {
		return nil, err
	}

	// use SOAP binding
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
	req, err := http.NewRequest("POST", request.Destination, bytes.NewReader(jsonData))
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
	body, err := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, errors.New("error with response code != 200")
	}
	if err != nil {
		return nil, err
	}
	return body, nil
}

func decryptXML(encryptedXML string, key []byte) ([]byte, error) {
	decodedEncryptedXML, err := base64.StdEncoding.DecodeString(encryptedXML)
	if err != nil {
		return nil, err
	}
	initVector := decodedEncryptedXML[:16]

	//Decrypt decodedEncryptedXML with AES using given key(CBC mode, PKCS7 padding, IV)
	cipherBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padBlobXML := pkcs7Padding(decodedEncryptedXML, cipherBlock.BlockSize())
	plainText := make([]byte, len(padBlobXML))
	mode := cipher.NewCBCDecrypter(cipherBlock, initVector)
	mode.CryptBlocks(plainText, padBlobXML)
	return padBlobXML, nil
}

func decryptKey(encryptedKey string, privateKey string) ([]byte, error) {
	decodedEncryptedKey, err := base64.StdEncoding.DecodeString(encryptedKey)
	if err != nil {
		return nil, err
	}

	privPem, _ := pem.Decode([]byte(privateKey))
	rsaPrivateKey, err := x509.ParsePKCS1PrivateKey(privPem.Bytes)
	if err != nil {
		return nil, err
	}

	rng := rand.Reader
	plaintext, err := rsa.DecryptOAEP(sha1.New(), rng, rsaPrivateKey, decodedEncryptedKey, []byte(""))
	if err != nil {
		return nil, err
	}

	fmt.Println(plaintext)
	return plaintext, nil
}

// pkcs7Padding returns the data with correct padding for AES block
func pkcs7Padding(ciphertext []byte, blockSize int) []byte {
	n := blockSize - (len(ciphertext) % blockSize)
	pb := make([]byte, len(ciphertext)+n)
	copy(pb, ciphertext)
	copy(pb[len(ciphertext):], bytes.Repeat([]byte{byte(n)}, n))
	return pb
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
