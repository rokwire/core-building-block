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

//Adapter implements the GitHub interface
type Adapter struct {
	githubToken             string
	githubOrgnizationName   string
	githubRepoName          string
	githubWebhookConfigPath string

	logger *logs.Logger

	cachedWebhookConfig *model.WebhookConfig
	webhookConfigsLock  *sync.RWMutex
}

//Start starts the github adapter
func (sa *Adapter) Start() error {
	// cache webhook config
	err := sa.cacheWebhookConfigs()
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionCache, model.TypeWebhookConfig, nil, err)
	}

	return err
}

// UpdateCachedWebhookConfigs updates the webhook configs cache
func (sa *Adapter) UpdateCachedWebhookConfigs() error {
	return sa.cacheWebhookConfigs()
}

func (sa *Adapter) cacheWebhookConfigs() error {
	sa.logger.Info("cacheWebhookConfigs..")

	webhookConfigs, err := sa.loadWebhookConfigs()
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeWebhookConfig, nil, err)
	}

	sa.setCachedWebhookConfigs(webhookConfigs)

	return nil
}

// FindWebhookConfig finds webhook configs
func (sa *Adapter) FindWebhookConfig() (*model.WebhookConfig, error) {
	return sa.getCachedWebhookConfig()
}

func (sa *Adapter) setCachedWebhookConfigs(webhookConfigs *model.WebhookConfig) {
	if webhookConfigs == nil {
		return
	}

	sa.webhookConfigsLock.Lock()
	defer sa.webhookConfigsLock.Unlock()

	// sa.cachedWebhookConfigs = &syncmap.Map{}
	validate := validator.New()

	err := validate.Struct(webhookConfigs)
	if err != nil {
		sa.logger.Errorf("failed to validate and cache webhook config: %s", err.Error())
	} else {
		sa.cachedWebhookConfig = webhookConfigs
	}
}

func (sa *Adapter) getCachedWebhookConfig() (*model.WebhookConfig, error) {
	sa.webhookConfigsLock.Lock()
	defer sa.webhookConfigsLock.Unlock()

	return sa.cachedWebhookConfig, nil
}

func (sa *Adapter) loadWebhookConfigs() (*model.WebhookConfig, error) {
	contentString, _, err := sa.GetContents(sa.githubWebhookConfigPath)
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
func (sa *Adapter) GetContents(path string) (string, bool, error) {
	isWebhookConfigPath := false
	if path == sa.githubWebhookConfigPath {
		isWebhookConfigPath = true
	}

	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: sa.githubToken},
	)
	tc := oauth2.NewClient(ctx, ts)

	client := github.NewClient(tc)

	fileContent, _, _, err := client.Repositories.GetContents(ctx, sa.githubOrgnizationName, sa.githubRepoName, path, &github.RepositoryContentGetOptions{Ref: "develop"})
	if err != nil || fileContent == nil {
		return "", isWebhookConfigPath, errors.WrapErrorAction(logutils.ActionGet, model.TypeGithubContent, nil, err)
	}

	contentString, err := fileContent.GetContent()
	if err != nil {
		return "", isWebhookConfigPath, errors.WrapErrorAction(logutils.ActionDecode, model.TypeGithubContent, nil, err)
	}

	return contentString, isWebhookConfigPath, nil
}

//NewGitHubAdapter creates a new GitHub adapter instance
func NewGitHubAdapter(githubToken string, githubOrgnizationName string, githubRepoName string, githubWebhookConfigPath string, logger *logs.Logger) *Adapter {
	cachedWebhookConfigs := &model.WebhookConfig{}
	webhookConfigsLock := &sync.RWMutex{}

	return &Adapter{cachedWebhookConfig: cachedWebhookConfigs, webhookConfigsLock: webhookConfigsLock, githubToken: githubToken, githubOrgnizationName: githubOrgnizationName, githubRepoName: githubRepoName, githubWebhookConfigPath: githubWebhookConfigPath, logger: logger}
}
