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
	"core-building-block/core/auth"
	"core-building-block/core/model"
	"core-building-block/driven/storage"
	"sync"

	"gopkg.in/go-playground/validator.v9"

	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
)

// application represents the core application code based on hexagonal architecture
type application struct {
	env     string
	version string
	build   string

	storage Storage
	github  VCS

	listeners []ApplicationListener

	auth auth.APIs

	logger *logs.Logger

	cachedWebhookConfig *model.WebhookConfig
	webhookConfigsLock  *sync.RWMutex
}

// start starts the core part of the application
func (a *application) start() error {
	//set storage listener
	storageListener := StorageListener{app: a}
	a.storage.RegisterStorageListener(&storageListener)

	err := a.cacheWebhookConfigsFromVCS()
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionCache, model.TypeWebhookConfig, nil, err)
	}

	return err
}

// addListener adds application listener
func (a *application) addListener(listener ApplicationListener) {
	//TODO
	//logs.Println("Application -> AddListener")

	a.listeners = append(a.listeners, listener)
}

func (a *application) notifyListeners(message string, data interface{}) {
	go func() {
		// TODO:
	}()
}

func (a *application) getAccount(accountID string) (*model.Account, error) {
	//find the account
	account, err := a.storage.FindAccountByID(nil, accountID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}
	return account, nil
}

// UpdateCachedWebhookConfigFromGit updates the webhook configs cache
func (a *application) updateCachedWebhookConfig(config *model.WebhookConfig) error {
	if config == nil {
		return nil
	}
	err := a.storage.UpdateWebhookConfig(*config)
	if err != nil {
		return err
	}
	a.setCachedWebhookConfigs(config)
	return nil
}

func (a *application) cacheWebhookConfigsFromVCS() error {
	a.logger.Info("cacheWebhookConfigs..")

	webhookConfig, err := a.github.LoadWebhookConfig()
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeWebhookConfig, nil, err)
	}

	return a.updateCachedWebhookConfig(webhookConfig)
}

func (a *application) updateCachedWebhookConfigFromStorage() error {
	webhookConfig, err := a.storage.FindWebhookConfig()
	if err != nil {
		return err
	}

	if webhookConfig != nil {
		a.setCachedWebhookConfigs(webhookConfig)
	}

	return nil
}

// FindWebhookConfig finds webhook configs
func (a *application) FindWebhookConfig() (*model.WebhookConfig, error) {
	return a.getCachedWebhookConfig()
}

func (a *application) setCachedWebhookConfigs(webhookConfigs *model.WebhookConfig) {
	if webhookConfigs == nil {
		return
	}

	a.webhookConfigsLock.Lock()
	defer a.webhookConfigsLock.Unlock()

	// sa.cachedWebhookConfigs = &syncmap.Map{}
	validate := validator.New()

	err := validate.Struct(webhookConfigs)
	if err != nil {
		a.logger.Errorf("failed to validate and cache webhook config: %s", err.Error())
	} else {
		a.cachedWebhookConfig = webhookConfigs
	}
}

func (a *application) getCachedWebhookConfig() (*model.WebhookConfig, error) {
	a.webhookConfigsLock.Lock()
	defer a.webhookConfigsLock.Unlock()

	return a.cachedWebhookConfig, nil
}

// StorageListener listens for change data storage events
type StorageListener struct {
	app *application
	storage.DefaultListenerImpl
}

// OnWebhookConfigsUpdated notifies that webhook config file has been updated
func (s *StorageListener) OnWebhookConfigsUpdated() {
	s.app.updateCachedWebhookConfigFromStorage()
}
