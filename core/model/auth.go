package model

import log "github.com/rokmetro/logging-library/loglib"

const (
	TypeUserAuth   log.LogData = "user auth"
	TypeAuthConfig log.LogData = "user auth"
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
}

//AuthConfig represents auth config entity
type AuthConfig struct {
	OrgID  string `json:"org_id" bson:"org_id" validate:"required"`
	AppID  string `json:"app_id" bson:"app_id" validate:"required"`
	Type   string `json:"type" bson:"type" validate:"required"`
	Config []byte `json:"config" bson:"config" validate:"required"`
}
