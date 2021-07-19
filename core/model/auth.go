package model

type UserAuth struct {
	UserID       string
	Sub          string
	Name         string
	Email        string
	Phone        string
	Picture      []byte
	Exp          float64
	RefreshToken string
}

type AuthConfig struct {
	OrgID  string      `json:"org_id" bson:"org_id" validate:"required"`
	AppID  string      `json:"app_id" bson:"app_id" validate:"required"`
	Type   string      `json:"type" bson:"type" validate:"required"`
	Config interface{} `json:"config" bson:"config" validate:"required"`
}
