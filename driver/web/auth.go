package web

import (
	"core-building-block/core"
)

//Auth handler
type Auth struct {
	//TODO
	/*apiKeysAuth   *APIKeysAuth
	userAuth      *UserAuth
	adminAuth     *AdminAuth
	providersAuth *ProvidersAuth */
}

//Start starts the auth module
func (auth *Auth) Start() error {
	//auth.adminAuth.start()
	//auth.userAuth.start()

	return nil
}

//NewAuth creates new auth handler
func NewAuth(app *core.Application) *Auth {

	auth := Auth{}
	return &auth
}
