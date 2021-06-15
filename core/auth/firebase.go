package auth

import "errors"

// Firebase implementation of authType
type firebaseAuthImpl struct {
	auth *Auth
}

func (a *firebaseAuthImpl) check(creds string) (*Claims, error) {
	//TODO: Implement
	return nil, errors.New("Unimplemented")
}

//newFirebaseAuth creates a new firebase auth instance
func newFirebaseAuth() *firebaseAuthImpl {
	return &firebaseAuthImpl{}
}
