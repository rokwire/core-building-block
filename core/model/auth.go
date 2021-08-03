package model

import (
	"github.com/rokmetro/auth-library/authorization"
	"github.com/rokmetro/auth-library/authservice"
	log "github.com/rokmetro/logging-library/loglib"
)

const (
	//TypeUserAuth user auth type
	TypeUserAuth log.LogData = "user auth"
	//TypeAuthConfig auth config type
	TypeAuthConfig log.LogData = "auth config"
	//TypeServiceReg service reg type
	TypeServiceReg log.LogData = "service reg"
	//TypeServiceScope service scope type
	TypeServiceScope log.LogData = "service scope"
	//TypeServiceAuthorization service authorization type
	TypeServiceAuthorization log.LogData = "service authorization"
	//TypeScope scope type
	TypeScope log.LogData = "scope"
)

//UserAuth represents user auth entity
type UserAuth struct {
	UserID       string
	Sub          string
	Name         string
	Email        string
	Phone        string
	Picture      []byte
	Exp          *int64
	RefreshToken string
	Params       map[string]interface{}
}

//AuthConfig represents auth config entity
type AuthConfig struct {
	OrgID  string `json:"org_id" bson:"org_id" validate:"required"`
	AppID  string `json:"app_id" bson:"app_id" validate:"required"`
	Type   string `json:"type" bson:"type" validate:"required"`
	Config []byte `json:"config" bson:"config" validate:"required"`
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
