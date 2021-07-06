package model

//FirebaseAdminCreds represents the Firebase admin credential structure
type FirebaseAdminCreds struct {
	ClientID      string `json:"clientID" bson:"clientID"`
	FirebaseCreds string `json:"firebase_creds" bson:"firebase_creds"`
}
