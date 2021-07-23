package auth

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"os"

	"core-building-block/core/model"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"

	log "github.com/rokmetro/logging-library/loglib"
)

// Firebase implementation of authType
type firebaseAuthImpl struct {
	auth *Auth
}

const (
	typeCred log.LogData = "creds"
)

func (a *firebaseAuthImpl) check(creds string, params string, l *log.Log) (*model.UserAuth, error) {
	paramsMap := make(map[string]interface{})
	err := json.Unmarshal([]byte(params), &paramsMap)
	if err != nil {
		return nil, log.WrapActionError(log.ActionUnmarshal, log.TypeString, &log.FieldArgs{"params": params}, err)
	}
	clientID, ok := paramsMap["clientID"].(string)
	if !ok {
		return nil, log.WrapActionError(log.ActionRegister, typeAuthType, nil, err)
	}
	err = a.setFirebaseAdminCreds(clientID)
	if err != nil {
		return nil, log.WrapActionError(log.ActionSave, log.TypeString, nil, err)
	}

	firebaseApp, err := firebase.NewApp(context.Background(), nil)
	if err != nil {
		return nil, log.WrapActionError(log.ActionInitialize, typeCred, nil, err)
	}

	// Access auth service from the firebase app
	firebaseAuth, err := firebaseApp.Auth(context.Background())
	if err != nil {
		return nil, log.WrapActionError(log.ActionInitialize, typeCred, nil, err)
	}

	//Validate the Firebase token
	token, err := firebaseAuth.VerifyIDToken(context.Background(), creds)
	if err != nil {
		return nil, log.WrapActionError(log.ActionValidate, log.TypeToken, &log.FieldArgs{"token": token}, err)
	}
	user, err := firebaseAuth.GetUser(context.Background(), token.Claims["user_id"].(string))
	if err != nil {
		return nil, log.WrapActionError(log.ActionGet, typeCred, nil, err)
	}
	token.Claims["uid"] = token.Claims["user_id"]

	if user.UserInfo.PhoneNumber != "" {
		token.Claims["phone"] = user.UserInfo.PhoneNumber
	}
	if user.UserInfo.Email != "" {
		token.Claims["email"] = user.UserInfo.Email
	}
	if user.UserInfo.DisplayName != "" {
		token.Claims["name"] = user.UserInfo.DisplayName
	}
	claims := &model.UserAuth{UserID: token.Claims["uid"].(string), Name: token.Claims["name"].(string), Phone: token.Claims["phone"].(string), Email: token.Claims["email"].(string), Exp: 0}
	return claims, nil
}

//Create a firebase admin with given email and password
func (a *firebaseAuthImpl) createAdmin(email string, password string) (string, error) {
	firebaseAuth, err := a.getFirebaseAuthClient("admin")
	if err != nil {
		return "", log.WrapActionError(log.ActionGet, typeCred, nil, err)
	}

	params := (&auth.UserToCreate{}).
		Email(email).
		EmailVerified(false).
		Password(password).
		Disabled(false)

	userRecord, err := firebaseAuth.CreateUser(context.Background(), params)
	if err != nil {
		return "", log.WrapActionError(log.ActionCreate, typeCred, nil, err)
	}
	return userRecord.UID, nil
}

//Get a firebase admin by a given email
func (a *firebaseAuthImpl) getAdmin(email string) (string, error) {
	firebaseAuth, err := a.getFirebaseAuthClient("admin")
	if err != nil {
		return "", log.WrapActionError(log.ActionGet, typeCred, nil, err)
	}

	userRecord, err := firebaseAuth.GetUserByEmail(context.Background(), email)
	if err != nil {
		return "", log.WrapActionError(log.ActionGet, typeCred, nil, err)
	}
	return userRecord.UID, nil
}

func (a *firebaseAuthImpl) setFirebaseAdminCreds(clientID string) error {
	creds, err := a.auth.storage.GetFirebaseAdminCreds(clientID)
	if err != nil {
		return err
	}
	os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "./service-account-file.json")
	err = ioutil.WriteFile("./service-account-file.json", []byte(creds.FirebaseCreds), 0644)
	if err != nil {
		return log.WrapActionError(log.ActionUpdate, typeCred, nil, err)

	}
	return nil
}

func (a *firebaseAuthImpl) getFirebaseAuthClient(clientID string) (*auth.Client, error) {
	err := a.setFirebaseAdminCreds(clientID)
	if err != nil {
		return nil, log.WrapActionError(log.ActionSave, log.TypeString, nil, err)
	}

	firebaseApp, err := firebase.NewApp(context.Background(), nil)
	if err != nil {
		return nil, log.WrapActionError(log.ActionInitialize, typeCred, nil, err)
	}

	// Access auth service from the firebase app
	firebaseAuth, err := firebaseApp.Auth(context.Background())
	if err != nil {
		return nil, log.WrapActionError(log.ActionInitialize, typeCred, nil, err)
	}
	return firebaseAuth, nil
}

//initFirebaseAuth initializes and registers a new Firebase auth instance
func initFirebaseAuth(auth *Auth) (*firebaseAuthImpl, error) {
	firebaseAuth := &firebaseAuthImpl{auth: auth}

	err := auth.registerAuthType("firebase", firebaseAuth)
	if err != nil {
		return nil, log.WrapActionError(log.ActionRegister, typeAuthType, nil, err)
	}

	return firebaseAuth, nil
}
