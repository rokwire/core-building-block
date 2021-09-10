package auth

import (
	"context"
	"encoding/json"
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
	config, err := a.getFirebaseAdminCreds(orgID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGet, logutils.TypeString, nil, err)
	}

	firebaseApp, err := firebase.NewApp(context.Background(), config)
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
	claims := &model.UserAuth{UserID: token.Claims["user_id"].(string)}
	if user.UserInfo.PhoneNumber != "" {
		claims.Phone = user.UserInfo.PhoneNumber
	}
	if user.UserInfo.Email != "" {
		claims.Email = user.UserInfo.Email
	}
	if user.UserInfo.DisplayName != "" {
		displayName := strings.Split(user.UserInfo.DisplayName, " ")
		if len(displayName) > 1 {
			claims.FirstName = displayName[0]
			claims.LastName = displayName[1]
		}
	}
	var expiry int64 = 0
	claims.Exp = &expiry
	return claims, nil
}

//Create a firebase user with given email and password
func (a *firebaseAuthImpl) createEmailUser(email string, password string, orgID string) (string, error) {
	firebaseAuth, err := a.getFirebaseAuthClient(orgID)
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

//Get a firebase user by a given email
func (a *firebaseAuthImpl) getEmailUser(email string, orgID string) (string, error) {
	firebaseAuth, err := a.getFirebaseAuthClient(orgID)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionGet, typeCred, nil, err)
	}

	userRecord, err := firebaseAuth.GetUserByEmail(context.Background(), email)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionGet, typeCred, nil, err)
	}
	return userRecord.UID, nil
}

func (a *firebaseAuthImpl) getFirebaseAdminCreds(orgID string) (*firebase.Config, error) {
	config := &firebase.Config{}
	creds, err := a.auth.storage.FindFirebaseAdminCreds(orgID)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(creds.FirebaseCreds), config); err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeCred, nil, err)
	}
	// os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "./service-account-file.json")
	// err = ioutil.WriteFile("./service-account-file.json", []byte(creds.FirebaseCreds), 0644)
	// if err != nil {
	// 	return errors.WrapErrorAction(logutils.ActionUpdate, typeCred, nil, err)

	// }
	return config, nil
}

func (a *firebaseAuthImpl) getFirebaseAuthClient(orgID string) (*auth.Client, error) {
	config, err := a.getFirebaseAdminCreds(orgID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGet, logutils.TypeString, nil, err)
	}

	firebaseApp, err := firebase.NewApp(context.Background(), config)
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
