package model

import log "github.com/rokmetro/logging-library/loglib"

const (
	//TypeUserAuth ...
	TypeUserAuth log.LogData = "user auth"
	//TypeAuthConfig ...
	TypeAuthConfig log.LogData = "user auth"
	//TypeServiceReg ...
	TypeServiceReg log.LogData = "service reg"
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

type AuthCred struct {
	OrgID     string      `bson:"org_id"`
	AppID     string      `bson:"app_id"`
	Type      string      `bson:"type"`
	UserID    string      `bson:"user_id"`
	AccountID string      `bson:"account_id"`
	Creds     interface{} `bson:"creds"`
	Refresh   interface{} `bson:"refresh"`
}
