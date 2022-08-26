package github

import (
	"context"
	"core-building-block/core"
	"core-building-block/core/model"
	"core-building-block/driven/storage"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/google/go-github/v44/github"
	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
	"golang.org/x/oauth2"
	"gopkg.in/go-playground/validator.v9"
)

// Adapter implements the GitHub interface
type Adapter struct {
	storage core.Storage

	githubToken             string
	githubOrganizationName  string
	githubRepoName          string
	githubWebhookConfigPath string
	githubAppConfigBranch   string

	logger *logs.Logger

	cachedWebhookConfig *model.WebhookConfig
	webhookConfigsLock  *sync.RWMutex
}

// Start starts the github adapter
func (a *Adapter) Start() error {
	storageListener := StorageListener{adapter: a}
	a.storage.RegisterStorageListener(&storageListener)

	err := a.cacheWebhookConfigsFromGit()
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionCache, model.TypeWebhookConfig, nil, err)
	}

	return err
}

// UpdateCachedWebhookConfigFromGit updates the webhook configs cache
func (a *Adapter) UpdateCachedWebhookConfigFromGit() error {
	return a.cacheWebhookConfigsFromGit()
}

func (a *Adapter) cacheWebhookConfigsFromGit() error {
	a.logger.Info("cacheWebhookConfigs..")

	webhookConfigs, err := a.loadWebhookConfigsFromGit()
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeWebhookConfig, nil, err)
	}

	if webhookConfigs != nil {
		a.setCachedWebhookConfigs(webhookConfigs)
		a.storage.UpdateWebhookConfig(*webhookConfigs)
	}

	return nil
}

func (a *Adapter) updateCachedWebhookConfigFromStorage() error {
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
func (a *Adapter) FindWebhookConfig() (*model.WebhookConfig, error) {
	return a.getCachedWebhookConfig()
}

func (a *Adapter) setCachedWebhookConfigs(webhookConfigs *model.WebhookConfig) {
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

func (a *Adapter) getCachedWebhookConfig() (*model.WebhookConfig, error) {
	a.webhookConfigsLock.Lock()
	defer a.webhookConfigsLock.Unlock()

	return a.cachedWebhookConfig, nil
}

func (a *Adapter) loadWebhookConfigsFromGit() (*model.WebhookConfig, error) {
	contentString, _, err := a.GetContents(a.githubWebhookConfigPath)
	if err != nil {
		fmt.Printf("fileContent.GetContent returned error: %v", err)
	}

	var webhookConfig model.WebhookConfig
	err = json.Unmarshal([]byte(contentString), &webhookConfig)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, model.TypeWebhookConfig, nil, err)
	}

	return &webhookConfig, nil
}

// GetContents get file content from GitHub
func (a *Adapter) GetContents(path string) (string, bool, error) {
	isWebhookConfigPath := false
	if path == a.githubWebhookConfigPath {
		isWebhookConfigPath = true
	}

	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: a.githubToken},
	)
	tc := oauth2.NewClient(ctx, ts)

	client := github.NewClient(tc)

	fileContent, _, _, err := client.Repositories.GetContents(ctx, a.githubOrganizationName, a.githubRepoName, path, &github.RepositoryContentGetOptions{Ref: a.githubAppConfigBranch})
	if err != nil || fileContent == nil {
		return "", isWebhookConfigPath, errors.WrapErrorAction(logutils.ActionGet, model.TypeGithubContent, nil, err)
	}

	contentString, err := fileContent.GetContent()
	if err != nil {
		return "", isWebhookConfigPath, errors.WrapErrorAction(logutils.ActionDecode, model.TypeGithubContent, nil, err)
	}

	return contentString, isWebhookConfigPath, nil
}

// NewGitHubAdapter creates a new GitHub adapter instance
func NewGitHubAdapter(githubToken string, githubOrgnizationName string, githubRepoName string, githubWebhookConfigPath string, githubAppConfigBranch string, storage core.Storage, logger *logs.Logger) *Adapter {
	cachedWebhookConfigs := &model.WebhookConfig{}
	webhookConfigsLock := &sync.RWMutex{}

	return &Adapter{storage: storage, cachedWebhookConfig: cachedWebhookConfigs, webhookConfigsLock: webhookConfigsLock, githubToken: githubToken, githubOrganizationName: githubOrgnizationName, githubRepoName: githubRepoName, githubWebhookConfigPath: githubWebhookConfigPath, githubAppConfigBranch: githubAppConfigBranch, logger: logger}
}

// StorageListener represents storage listener implementation for the auth package
type StorageListener struct {
	adapter *Adapter
	storage.DefaultListenerImpl
}

// OnWebhookConfigsUpdated notifies that webhook config file has been updated
func (al *StorageListener) OnWebhookConfigsUpdated() {
	al.adapter.updateCachedWebhookConfigFromStorage()
}
