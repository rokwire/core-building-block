package model

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"

	"github.com/rokmetro/logging-library/errors"

	"github.com/rokmetro/auth-library/authorization"
	"github.com/rokmetro/auth-library/authservice"
	"github.com/rokmetro/logging-library/logutils"
)

const (
	//TypeUserAuth user auth type
	TypeUserAuth logutils.MessageDataType = "user auth"
	//TypeAuthConfig auth config type
	TypeAuthConfig logutils.MessageDataType = "auth config"
	//TypeAuthCred auth cred type
	TypeAuthCred logutils.MessageDataType = "auth cred"
	//TypeServiceReg service reg type
	TypeServiceReg logutils.MessageDataType = "service reg"
	//TypeServiceScope service scope type
	TypeServiceScope logutils.MessageDataType = "service scope"
	//TypeServiceAuthorization service authorization type
	TypeServiceAuthorization logutils.MessageDataType = "service authorization"
	//TypeScope scope type
	TypeScope logutils.MessageDataType = "scope"
	//TypeJSONWebKey JWK type
	TypeJSONWebKey logutils.MessageDataType = "jwk"
	//TypeJSONWebKeySet JWKS type
	TypeJSONWebKeySet logutils.MessageDataType = "jwks"
	//TypePubKey pub key type
	TypePubKey logutils.MessageDataType = "pub key"
)

//UserAuth represents user auth entity
type UserAuth struct {
	UserID       string
	AccountID    string
	Sub          string
	FirstName    string
	LastName     string
	Email        string
	Phone        string
	Picture      []byte
	Exp          *int64
	RefreshToken string
	OrgData      map[string]interface{}
	NewCreds     interface{}
}

//AuthConfig represents auth config entity
type AuthConfig struct {
	OrgID  string `json:"org_id" bson:"org_id" validate:"required"`
	AppID  string `json:"app_id" bson:"app_id" validate:"required"`
	Type   string `json:"type" bson:"type" validate:"required"`
	Config []byte `json:"config" bson:"config" validate:"required"`
}

//AuthCred represents represents a set of credentials used by auth
type AuthCred struct {
	OrgID     string      `bson:"org_id"`
	AppID     string      `bson:"app_id"`
	Type      string      `bson:"type"`
	UserID    string      `bson:"user_id"`
	AccountID string      `bson:"account_id"`
	Creds     interface{} `bson:"creds"`
}

//ServiceReg represents a service registration entity
type ServiceReg struct {
	Registration authservice.ServiceReg `json:"registration" bson:"registration"`
	Name         string                 `json:"name" bson:"name"`
	Description  string                 `json:"description" bson:"description"`
	InfoURL      string                 `json:"info_url" bson:"info_url"`
	LogoURL      string                 `json:"logo_url" bson:"logo_url"`
	Scopes       []ServiceScope         `json:"scopes" bson:"scopes"`
	AuthEndpoint string                 `json:"auth_endpoint" bson:"auth_endpoint"`
	FirstParty   bool                   `json:"first_party" bson:"first_party"`
}

//ServiceScope represents a scope entity
type ServiceScope struct {
	Scope       *authorization.Scope `json:"scope" bson:"scope"`
	Required    bool                 `json:"required" bson:"required"`
	Explanation string               `json:"explanation,omitempty" bson:"explanation,omitempty"`
}

//ServiceAuthorization represents service authorization entity
type ServiceAuthorization struct {
	UserID    string                `json:"user_id" bson:"user_id"`
	ServiceID string                `json:"service_id" bson:"service_id"`
	Scopes    []authorization.Scope `json:"scopes" bson:"scopes"`
}

//JSONWebKeySet represents a JSON Web Key Set (JWKS) entity
type JSONWebKeySet struct {
	Keys []JSONWebKey `json:"keys" bson:"keys"`
}

//JSONWebKey represents a JSON Web Key Set (JWKS) entity
type JSONWebKey struct {
	Kty string `json:"kty" bson:"kty"`
	Use string `json:"use" bson:"use"`
	Kid string `json:"kid" bson:"kid"`
	Alg string `json:"alg" bson:"alg"`
	N   string `json:"n" bson:"n"`
	E   string `json:"e" bson:"e"`
}

func JSONWebKeyFromPubKey(key *authservice.PubKey) (*JSONWebKey, error) {
	if key == nil {
		return nil, errors.ErrorData(logutils.StatusInvalid, TypePubKey, logutils.StringArgs("nil"))
	}

	err := key.LoadKeyFromPem()
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionParse, TypePubKey, nil, err)
	}

	n, e, err := rsaPublicKeyByteValuesFromRaw(key.Key)
	if err != nil || n == nil || e == nil {
		return nil, errors.WrapErrorAction(logutils.ActionEncode, TypePubKey, nil, err)
	}

	//TODO: Should this be RawURLEncoding?
	nString := base64.URLEncoding.EncodeToString(n)
	eString := base64.URLEncoding.EncodeToString(e)

	return &JSONWebKey{Kty: "RSA", Use: "sig", Kid: key.Kid, Alg: key.Alg, N: nString, E: eString}, nil
}

func rsaPublicKeyByteValuesFromRaw(rawKey *rsa.PublicKey) ([]byte, []byte, error) {
	if rawKey == nil || rawKey.N == nil {
		return nil, nil, errors.ErrorData(logutils.StatusInvalid, "public key", nil)
	}
	n := rawKey.N.Bytes()

	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, uint64(rawKey.E))
	i := 0
	for ; i < len(data); i++ {
		if data[i] != 0x0 {
			break
		}
	}
	return n, data[i:], nil
}
