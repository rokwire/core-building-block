package auth

import (
	"encoding/xml"
	"errors"
)

// SAML implementation of authType
type samlAuthImpl struct {
	auth *Auth
}

type samlCheckParams struct {
	Web bool `json:"web"`
}

type samlLoginParams struct {
	Initial bool   `json:"initial"`
	Web     bool   `json:"web"`
	xmlBlob string `json:"xml_blob"`
}

type samlRefreshParams struct {
	Web bool `json:"web"`
}

type samlRequest struct {
	Issuer  string `xml:"issuer"`
	Subject string `xml:"subject"`
}

type samlAssertion struct {
	FirstName string `xml:"givenName"`
	LastName  string `xml:"lastName"`
}

func (a *samlAuthImpl) login(creds string, params string) (map[string]interface{}, error) {
	//TODO: Implement
	return nil, errors.New("Unimplemented")
}

func (a *samlAuthImpl) newToken(creds string, params samlLoginParams) (map[string]interface{}, error) {
	//TODO: Implement
	if params.Initial {
		// send SAML request to IDP
	} else {
		var samlResponse samlAssertion
		err := xml.Unmarshal([]byte(params.xmlBlob), &samlResponse)
		if err != nil {
			return nil, err
		}
	}

	return nil, errors.New("Unimplemented")
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
