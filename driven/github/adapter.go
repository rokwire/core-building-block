package github

import (
	"context"
	"core-building-block/core/model"
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
	// cache webhook config
	err := a.cacheWebhookConfigs()
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionCache, model.TypeWebhookConfig, nil, err)
	}

	return err
}

// UpdateCachedWebhookConfigs updates the webhook configs cache
func (a *Adapter) UpdateCachedWebhookConfigs() error {
	return a.cacheWebhookConfigs()
}

func (a *Adapter) cacheWebhookConfigs() error {
	a.logger.Info("cacheWebhookConfigs..")

	webhookConfigs, err := a.loadWebhookConfigs()
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeWebhookConfig, nil, err)
	}

	a.setCachedWebhookConfigs(webhookConfigs)

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

func (a *Adapter) loadWebhookConfigs() (*model.WebhookConfig, error) {
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
func NewGitHubAdapter(githubToken string, githubOrgnizationName string, githubRepoName string, githubWebhookConfigPath string, githubAppConfigBranch string, logger *logs.Logger) *Adapter {
	cachedWebhookConfigs := &model.WebhookConfig{}
	webhookConfigsLock := &sync.RWMutex{}

	return &Adapter{cachedWebhookConfig: cachedWebhookConfigs, webhookConfigsLock: webhookConfigsLock, githubToken: githubToken, githubOrganizationName: githubOrgnizationName, githubRepoName: githubRepoName, githubWebhookConfigPath: githubWebhookConfigPath, githubAppConfigBranch: githubAppConfigBranch, logger: logger}
}
