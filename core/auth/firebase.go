package auth

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"os"
	"strings"

	"core-building-block/core/model"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"github.com/rokmetro/logging-library/errors"
	"github.com/rokmetro/logging-library/logs"
	"github.com/rokmetro/logging-library/logutils"
)

const (
	authTypeFirebase string = "firebase"
)

// Firebase implementation of authType
type firebaseAuthImpl struct {
	auth     *Auth
	authType string
}

const (
	typeCred logutils.MessageDataType = "creds"
)

func (a *firebaseAuthImpl) check(creds string, orgID string, appID string, params string, l *logs.Log) (*model.UserAuth, error) {
	paramsMap := make(map[string]interface{})
	err := json.Unmarshal([]byte(params), &paramsMap)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, logutils.TypeString, &logutils.FieldArgs{"params": params}, err)
	}
	clientID, ok := paramsMap["clientID"].(string)
	if !ok {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeAuthType, nil, err)
	}
	err = a.setFirebaseAdminCreds(clientID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionSave, logutils.TypeString, nil, err)
	}

	firebaseApp, err := firebase.NewApp(context.Background(), nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionInitialize, typeCred, nil, err)
	}

	// Access auth service from the firebase app
	firebaseAuth, err := firebaseApp.Auth(context.Background())
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionInitialize, typeCred, nil, err)
	}

	//Validate the Firebase token
	token, err := firebaseAuth.VerifyIDToken(context.Background(), creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionValidate, logutils.TypeToken, &logutils.FieldArgs{"token": token}, err)
	}
	user, err := firebaseAuth.GetUser(context.Background(), token.Claims["user_id"].(string))
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGet, typeCred, nil, err)
	}
	token.Claims["uid"] = token.Claims["user_id"]

	if user.UserInfo.PhoneNumber != "" {
		token.Claims["phone"] = user.UserInfo.PhoneNumber
	}
	if user.UserInfo.Email != "" {
		token.Claims["email"] = user.UserInfo.Email
	}
	if user.UserInfo.DisplayName != "" {
		displayName := strings.Split(user.UserInfo.DisplayName, " ")
		if len(displayName) > 1 {
			token.Claims["first_name"] = displayName[0]
			token.Claims["last_name"] = displayName[1]
		}
	}
	var expiry int64 = 0
	claims := &model.UserAuth{UserID: token.Claims["uid"].(string), FirstName: token.Claims["first_name"].(string), LastName: token.Claims["last_name"].(string), Phone: token.Claims["phone"].(string), Email: token.Claims["email"].(string), Exp: &expiry}
	return claims, nil
}

//Create a firebase admin with given email and password
func (a *firebaseAuthImpl) createAdmin(email string, password string) (string, error) {
	firebaseAuth, err := a.getFirebaseAuthClient("admin")
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionGet, typeCred, nil, err)
	}

	params := (&auth.UserToCreate{}).
		Email(email).
		EmailVerified(false).
		Password(password).
		Disabled(false)

	userRecord, err := firebaseAuth.CreateUser(context.Background(), params)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionCreate, typeCred, nil, err)
	}
	return userRecord.UID, nil
}

//Get a firebase admin by a given email
func (a *firebaseAuthImpl) getAdmin(email string) (string, error) {
	firebaseAuth, err := a.getFirebaseAuthClient("admin")
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionGet, typeCred, nil, err)
	}

	userRecord, err := firebaseAuth.GetUserByEmail(context.Background(), email)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionGet, typeCred, nil, err)
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
		return errors.WrapErrorAction(logutils.ActionUpdate, typeCred, nil, err)

	}
	return nil
}

func (a *firebaseAuthImpl) getFirebaseAuthClient(clientID string) (*auth.Client, error) {
	err := a.setFirebaseAdminCreds(clientID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionSave, logutils.TypeString, nil, err)
	}

	firebaseApp, err := firebase.NewApp(context.Background(), nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionInitialize, typeCred, nil, err)
	}

	// Access auth service from the firebase app
	firebaseAuth, err := firebaseApp.Auth(context.Background())
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionInitialize, typeCred, nil, err)
	}
	return firebaseAuth, nil
}

func (a *firebaseAuthImpl) refresh(refreshToken string, orgID string, appID string, l *logs.Log) (*model.UserAuth, error) {
	return nil, errors.Newf("refresh operation invalid for auth_type=%s", authTypeFirebase)
}

func (a *firebaseAuthImpl) getLoginURL(orgID string, appID string, redirectURI string, l *logs.Log) (string, map[string]interface{}, error) {
	return "", nil, errors.Newf("get login url operation invalid for auth_type=%s", a.authType)
}

//initFirebaseAuth initializes and registers a new Firebase auth instance
func initFirebaseAuth(auth *Auth) (*firebaseAuthImpl, error) {
	firebase := &firebaseAuthImpl{auth: auth, authType: authTypeFirebase}

	err := auth.registerAuthType(firebase.authType, firebase)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeAuthType, nil, err)
	}

	return firebase, nil
}
