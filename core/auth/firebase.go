package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"os"

	"firebase.google.com/go/auth"
	firebase "firebase.google.com/go/v4"
)

// Firebase implementation of authType
type firebaseAuthImpl struct {
	auth *Auth
}

func (a *firebaseAuthImpl) check(creds string, params string) (*Claims, error) {
	paramsMap := make(map[string]interface{})
	err := json.Unmarshal([]byte(params), &paramsMap)
	if err != nil {
		return nil, err
	}
	clientID, ok := paramsMap["clientID"].(string)
	if !ok {
		return nil, errors.New("ClientID parameter missing or invalid")
	}
	err = a.setFirebaseAdminCreds(clientID)
	if err != nil {
		return nil, err
	}

	firebaseApp, err := firebase.NewApp(context.Background(), nil)
	if err != nil {
		log.Printf("error initializing Firebase app: %v\n", err)
		return nil, err
	}

	// Access auth service from the firebase app
	firebaseAuth, err := firebaseApp.Auth(context.Background())
	if err != nil {
		log.Printf("error getting Firebase Auth client: %v\n", err)
		return nil, err
	}

	//Validate the Firebase token
	token, err := firebaseAuth.VerifyIDToken(context.Background(), creds)
	if err != nil {
		log.Printf("error verifying Firebase ID token: %v\n", err)
		return nil, errors.New("Invalid token")
	}
	log.Printf("Verified Firebase ID token: %v\n", token)
	user, err := firebaseAuth.GetUser(context.Background(), token.Claims["user_id"].(string))
	if err != nil {
		log.Printf("error verifying Firebase ID token: %v\n", err)
		return nil, errors.New("Failed to get Firebase user")
	}
	log.Printf("Claims: %v", token.Claims)
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
	claims := &Claims{ID: token.Claims["uid"].(string), Name: token.Claims["name"].(string), Phone: token.Claims["phone"].(string), Email: token.Claims["email"].(string), Issuer: token.Claims["issuer"].(string), Groups: nil, Exp: 0}
	return claims, nil
}

//Create a firebase admin with given email and password
func (a *firebaseAuthImpl) createAdmin(email string, password string) (string, error) {
	err := a.setFirebaseAdminCreds("admin")
	if err != nil {
		return "", err
	}

	firebaseApp, err := firebase.NewApp(context.Background(), nil)
	if err != nil {
		log.Printf("error initializing Firebase app: %v\n", err)
		return "", err
	}

	// Access auth service from the firebase app
	firebaseAuth, err := firebaseApp.Auth(context.Background())
	if err != nil {
		log.Printf("error getting Firebase Auth client: %v\n", err)
		return "", err
	}

	params := (&auth.UserToCreate{}).
		Email(email).
		EmailVerified(false).
		Password(password).
		Disabled(false)

	userRecord, err := firebaseAuth.CreateUser(context.Background(), params)
	if err != nil {
		log.Printf("error creating firebase user: %v\n", err)
		return "", err
	}
	return userRecord.UID, nil
}

//Get a firebase admin by a given email
func (a *firebaseAuthImpl) getAdmin(email string) (string, error) {
	err := a.setFirebaseAdminCreds("admin")
	if err != nil {
		return "", err
	}
	firebaseApp, err := firebase.NewApp(context.Background(), nil)
	if err != nil {
		log.Printf("error initializing Firebase app: %v\n", err)
		return "", err
	}

	// Access auth service from the firebase app
	firebaseAuth, err := firebaseApp.Auth(context.Background())
	if err != nil {
		log.Printf("error getting Firebase Auth client: %v\n", err)
		return "", err
	}

	userRecord, err := firebaseAuth.GetUserByEmail(context.Background(), email)
	if err != nil {
		log.Printf("error fetching firebase user: %v\n", err)
		return "", err
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
		log.Printf("Unable to write Google credentials to file: " + err.Error())
		return err
	}
	return nil
}

//initFirebaseAuth initializes and registers a new Firebase auth instance
func initFirebaseAuth(auth *Auth) (*firebaseAuthImpl, error) {
	firebaseAuth := &firebaseAuthImpl{auth: auth}

	err := auth.registerAuthType("firebase", firebaseAuth)
	if err != nil {
		return nil, err
	}

	return firebaseAuth, nil
}
