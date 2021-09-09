package model

import "github.com/rokmetro/logging-library/logutils"

const (
	//TypeGlobalConfig ...
	TypeFirebaseAdminCred logutils.MessageDataType = "firebase admin creds"
)

//FirebaseAdminCreds represents the Firebase admin credential structure
type FirebaseAdminCreds struct {
	OrgID         string `json:"org_id" bson:"org_id"`
	FirebaseCreds string `json:"firebase_creds" bson:"firebase_creds"`
}
