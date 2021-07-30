package model

import log "github.com/rokmetro/logging-library/loglib"

const (
	TypeUserAuth   log.LogData = "user auth"
	TypeAuthConfig log.LogData = "auth config"
	TypeAuthCred   log.LogData = "auth cred"
	TypeServiceReg log.LogData = "service reg"
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
