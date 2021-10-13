package storage

import "core-building-block/core/model"

//LoginSession
func loginSessionToStorage(item *model.LoginSession) *loginSession {
	id := item.ID
	//TODO

	return &loginSession{ID: id}
}
