package auth

import (
	"core-building-block/core/model"

	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
)

const (
	//ServiceAuthTypeStaticToken static token service auth type
	ServiceAuthTypeStaticToken string = "static token"
)

//staticTokenCreds represents the creds struct for static token auth
type staticTokenCreds struct {
	Token string `json:"token" bson:"token" validate:"required"`
}

// Static token implementation of serviceAuthType
type staticTokenAuthImpl struct {
	auth            *Auth
	serviceAuthType string
}

func (s *staticTokenAuthImpl) checkCredentials(account *model.ServiceAccount, creds string, l *logs.Log) (*string, error) {
	return nil, errors.New(logutils.Unimplemented)
}

//initStaticTokenAuth initializes and registers a new static token service auth instance
func initStaticTokenAuth(auth *Auth) (*staticTokenAuthImpl, error) {
	staticToken := &staticTokenAuthImpl{auth: auth, serviceAuthType: ServiceAuthTypeStaticToken}

	err := auth.registerServiceAuthType(staticToken.serviceAuthType, staticToken)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeServiceAuthType, nil, err)
	}

	return staticToken, nil
}
