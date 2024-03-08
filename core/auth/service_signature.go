// Copyright 2022 Board of Trustees of the University of Illinois.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"core-building-block/core/model"
	"core-building-block/utils"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rokwire/core-auth-library-go/v3/keys"
	"github.com/rokwire/core-auth-library-go/v3/sigauth"
	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logutils"
)

const (
	//ServiceAuthTypeSignature signature service auth type
	ServiceAuthTypeSignature string = "signature"
	//TypeSignatureCreds type signature creds
	TypeSignatureCreds logutils.MessageDataType = "signature creds"
)

// Signature implementation of serviceAuthType
type signatureServiceAuthImpl struct {
	auth            *Auth
	serviceAuthType string
}

func (s *signatureServiceAuthImpl) checkCredentials(r *sigauth.Request, _ interface{}, params map[string]interface{}) ([]model.ServiceAccount, error) {
	sigString, sigAuthHeader, err := s.auth.SignatureAuth.ParseRequestSignature(r)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionParse, "request signature and header", nil, err).SetStatus(utils.ErrorStatusInvalid)
	}

	accounts, err := s.auth.storage.FindServiceAccounts(params)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeServiceAccount, nil, err)
	}
	if len(accounts) == 0 {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeServiceAccount, nil).SetStatus(utils.ErrorStatusNotFound)
	}

	for _, credential := range accounts[0].Credentials {
		if credential.Type == ServiceAuthTypeSignature {
			pubKey, err := s.pubKeyFromCred(&credential, true)
			if err != nil {
				s.auth.logger.Error(err.Error())
				continue
			}
			if pubKey.KeyID != sigAuthHeader.KeyID {
				continue
			}

			err = s.auth.SignatureAuth.CheckParsedRequestSignature(sigString, sigAuthHeader, pubKey)
			if err == nil {
				return accounts, nil
			}
		}
	}

	return nil, errors.WrapErrorAction(logutils.ActionValidate, "signed request", nil, err).SetStatus(utils.ErrorStatusInvalid)
}

func (s *signatureServiceAuthImpl) addCredentials(creds *model.ServiceAccountCredential) (map[string]interface{}, error) {
	if creds == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeServiceAccountCredential, nil)
	}

	pubKey, err := s.pubKeyFromCred(creds, false)
	if err != nil {
		return nil, err
	}

	creds.ID = uuid.NewString()
	creds.Params = map[string]interface{}{
		"key_pem": pubKey.KeyPem,
		"alg":     pubKey.Alg,
	}
	creds.DateCreated = time.Now().UTC()

	displayParams := map[string]interface{}{
		"key_pem": pubKey.KeyPem,
	}
	return displayParams, nil
}

// pubKeyFromCred parses a keys.PubKey from credential params (this does not decode key_pem)
func (s *signatureServiceAuthImpl) pubKeyFromCred(creds *model.ServiceAccountCredential, decode bool) (*keys.PubKey, error) {
	alg, ok := creds.Params["alg"].(string)
	if !ok {
		return nil, errors.ErrorAction(logutils.ActionParse, "public key algorithm", &logutils.FieldArgs{"alg": creds.Params["alg"]})
	}
	keyPem, ok := creds.Params["key_pem"].(string)
	if !ok {
		return nil, errors.ErrorAction(logutils.ActionParse, "public key pem", &logutils.FieldArgs{"key_pem": creds.Params["key_pem"]})
	}
	keyPem = strings.ReplaceAll(keyPem, `\n`, "\n")

	if decode {
		pubKey, err := keys.NewPubKey(alg, keyPem)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionLoad, "public key", nil, err)
		}

		return pubKey, nil
	}

	return &keys.PubKey{Alg: alg, KeyPem: keyPem}, nil
}

// initSignatureServiceAuth initializes and registers a new signature service auth instance
func initSignatureServiceAuth(auth *Auth) (*signatureServiceAuthImpl, error) {
	signature := &signatureServiceAuthImpl{auth: auth, serviceAuthType: ServiceAuthTypeSignature}

	err := auth.registerServiceAuthType(signature.serviceAuthType, signature)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeServiceAuthType, nil, err)
	}

	return signature, nil
}
