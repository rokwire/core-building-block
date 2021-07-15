package model

type StorageListener interface {
	OnAuthConfigUpdated()
}

type DefaultStorageListenerImpl struct {
}

func (d *DefaultStorageListenerImpl) OnAuthConfigUpdated() {
}
