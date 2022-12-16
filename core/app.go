// Copyright 2022 Board of Trustees of the University of Illinois.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package core

import (
	"core-building-block/core/interfaces"
	"core-building-block/core/model"
)

// application represents the core application code based on hexagonal architecture
type application struct {
	env     string
	version string
	build   string

	storage interfaces.Storage

	listeners []interfaces.ApplicationListener

	auth interfaces.Auth
}

// start starts the core part of the application
func (app *application) start() {
	//set storage listener
	storageListener := StorageListener{app: app}
	app.storage.RegisterStorageListener(&storageListener)
}

// addListener adds application listener
func (app *application) addListener(listener interfaces.ApplicationListener) {
	//TODO
	//logs.Println("Application -> AddListener")

	app.listeners = append(app.listeners, listener)
}

func (app *application) notifyListeners(message string, data interface{}) {
	go func() {
		// TODO
	}()
}

// StorageListener listenes for change data storage events
type StorageListener struct {
	app *application
	model.DefaultStorageListener
}
