package core

import (
	log "github.com/rokmetro/logging-library/loglib"
)

//Services exposes APIs for the driver adapters
type Services interface {
	SerGetVersion(l *log.Log) string
	SerGetAuthTest(l *log.Log) string
	SerGetCommonTest(l *log.Log) string
}

type servicesImpl struct {
	app *Application
}

func (s *servicesImpl) SerGetVersion(l *log.Log) string {
	return s.app.serGetVersion(l)
}

func (s *servicesImpl) SerGetAuthTest(l *log.Log) string {
	return s.app.serGetAuthTest(l)
}

func (s *servicesImpl) SerGetCommonTest(l *log.Log) string {
	return s.app.serGetCommonTest(l)
}

//Administration exposes administration APIs for the driver adapters
type Administration interface {
	AdmGetTest() string
	AdmGetTestModel() string
}

type administrationImpl struct {
	app *Application
}

func (s *administrationImpl) AdmGetTest() string {
	return s.app.admGetTest()
}

func (s *administrationImpl) AdmGetTestModel() string {
	return s.app.admGetTestModel()
}

//Encryption exposes APIs for the Encryption building block
type Encryption interface {
	EncGetTest() string
}

type encryptionImpl struct {
	app *Application
}

func (s *encryptionImpl) EncGetTest() string {
	return s.app.encGetTest()
}

//BBs exposes users related APIs used by the platform building blocks
type BBs interface {
	BBsGetTest() string
}

type bbsImpl struct {
	app *Application
}

func (s *bbsImpl) BBsGetTest() string {
	return s.app.bbsGetTest()
}

//Storage is used by core to storage data - DB storage adapter, file storage adapter etc
type Storage interface {
	SetStorageListener(storageListener StorageListener)
}

//StorageListener listenes for change data storage events
type StorageListener interface {
}

type storageListenerImpl struct {
	app *Application
}

//ApplicationListener represents application listener
type ApplicationListener interface {
}
