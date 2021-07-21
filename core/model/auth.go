package model

//UserAuth represents user auth entity
type UserAuth struct {
	UserID       string
	AccountID    string
	Sub          string
	Name         string
	Email        string
	Phone        string
	Picture      []byte
	Exp          float64
	RefreshToken string
	OrgData      map[string]interface{}
}

//AuthConfig represents auth config entity
type AuthConfig struct {
	OrgID  string      `json:"org_id" bson:"org_id" validate:"required"`
	AppID  string      `json:"app_id" bson:"app_id" validate:"required"`
	Type   string      `json:"type" bson:"type" validate:"required"`
	Config interface{} `json:"config" bson:"config" validate:"required"`
}

type AuthCred struct {
	OrgID     string      `bson:"org_id"`
	AppID     string      `bson:"app_id"`
	Type      string      `bson:"type"`
	UserID    string      `bson:"user_id"`
	AccountID string      `bson:"account_id"`
	Creds     interface{} `bson:"creds"`
}
