package model

//Credentials represents the credential struct for email auth
type Credential struct {
	Email    string `json:"email" bson:"email"`
	Password string `json:"password" bson:"password"`
}
