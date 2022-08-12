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
	"github.com/rokwire/core-auth-library-go/v2/authservice"
	"github.com/rokwire/core-auth-library-go/v2/sigauth"
	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logutils"
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
	sigString, sigAuthHeader, err := s.auth.SignatureAuth.CheckRequest(r)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionParse, "request signature and header", nil, err).SetStatus(utils.ErrorStatusInvalid)
	}

	params["credentials.params.key_id"] = sigAuthHeader.KeyID
	accounts, err := s.auth.storage.FindServiceAccounts(params)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeServiceAccount, nil, err)
	}
	if len(accounts) == 0 {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeServiceAccount, nil).SetStatus(utils.ErrorStatusNotFound)
	}

	for _, credential := range accounts[0].Credentials {
		if credential.Type == ServiceAuthTypeSignature {
			keyID, ok := credential.Params["key_id"].(string)
			if !ok {
				s.auth.logger.ErrorWithFields("error asserting stored public key ID is string", logutils.Fields{"key_id": credential.Params["key_id"]})
				continue
			}
			if keyID != sigAuthHeader.KeyID {
				continue
			}

			pubKey, err := s.pubKeyFromCred(&credential)
			if err != nil {
				continue
			}
			err = s.auth.SignatureAuth.CheckSignature(pubKey.Key, []byte(sigString), sigAuthHeader.Signature)
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

	pubKey, err := s.pubKeyFromCred(creds)
	if err != nil {
		return nil, err
	}

	creds.ID = uuid.NewString()
	creds.Params = map[string]interface{}{
		"key_pem": pubKey.KeyPem,
		"alg":     pubKey.Alg,
		"key_id":  pubKey.KeyID,
	}
	creds.DateCreated = time.Now().UTC()

	displayParams := map[string]interface{}{
		"key_pem": pubKey.KeyPem,
	}
	return displayParams, nil
}

func (s *signatureServiceAuthImpl) pubKeyFromCred(creds *model.ServiceAccountCredential) (*authservice.PubKey, error) {
	pubKeyPem, ok := creds.Params["key_pem"].(string)
	if !ok {
		return nil, errors.ErrorAction(logutils.ActionParse, "public key pem", &logutils.FieldArgs{"key_pem": creds.Params["key_pem"]})
	}

	pubKeyPem = strings.ReplaceAll(pubKeyPem, `\n`, "\n")
	pubKey := authservice.PubKey{KeyPem: pubKeyPem, Alg: "RS256"}
	if err := pubKey.LoadKeyFromPem(); err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionLoad, "public key", &logutils.FieldArgs{"key_pem": creds.Params["key_pem"]}, err)
	}

	return &pubKey, nil
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
