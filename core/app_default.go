package core

import (
	"core-building-block/core/model"
	"core-building-block/utils"
	"encoding/json"
	"fmt"

	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
)

func (app *application) processGitHubAppConfigWebhook(commits []model.Commit, l *logs.Log) error {

	for _, commit := range commits {
		err := app.processGitHubWebhookFiles(commit.Added, false, l)
		if err != nil {
			l.LogError("error processing GitHub webhook added files", err)
		}
		err = app.processGitHubWebhookFiles(commit.Modified, false, l)
		if err != nil {
			l.LogError("error processing GitHub webhook changed files", err)
		}
		err = app.processGitHubWebhookFiles(commit.Removed, true, l)
		if err != nil {
			l.LogError("error processing GitHub webhook deleted files", err)
		}
	}

	return nil
}

func (app *application) processGitHubWebhookFiles(files []string, isDelete bool, l *logs.Log) error {
	if len(files) < 1 {
		return nil
	}
	for _, path := range files {
		contentString, isWebhookConfigPath, err := app.github.GetContents(path)
		if err != nil {
			// fmt.Printf("fileContent.GetContent returned error: %v", err)
			continue
		}

		if isWebhookConfigPath {
			err = app.github.UpdateCachedWebhookConfigs()
			if err != nil {
				if err != nil {
					l.LogError("error updating GitHub webhook config file cache", err)
				}
			}
		} else {
			// update appplication config files in db
			valid, appType, envString, orgName, appName, major, minor, patch := utils.ParseWebhookFilePath(path)
			if valid == true {
				versionNumber := model.VersionNumbers{Major: major, Minor: minor, Patch: patch}

				data := make(map[string]interface{})
				json.Unmarshal([]byte(contentString), &data)

				_, err = app.updateAppConfigFromWebhook(*envString, *orgName, *appName, appType, versionNumber, nil, isDelete, data)
				if err != nil {
					l.LogError(fmt.Sprintf("error updating file with path: %s", path), err)
				}
			}
		}
	}

	return nil
}

func (app *application) updateAppConfigFromWebhook(enviromentString string, orgName string, appName string, appType string, versionNumbers model.VersionNumbers, apiKey *string, isDelete bool, data map[string]interface{}) (*model.ApplicationConfig, error) {
	webhookConfig, err := app.github.FindWebhookConfig()
	if err != nil || webhookConfig == nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeWebhookConfig, logutils.StringArgs(orgName), err)
	}

	var orgID *string
	orgMap := webhookConfig.Organizations
	if _, ok := orgMap[orgName]; ok {
		t := orgMap[orgName]
		orgID = &t
	}
	if webhookConfig.Applications != nil {
		if appMap, ok := webhookConfig.Applications[appName]; ok {
			if appTypeIdentifier, ok := appMap[appType]; ok {
				applicationType, err := app.storage.FindApplicationType(appTypeIdentifier)
				if err != nil {
					return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationType, logutils.StringArgs(appTypeIdentifier), err)
				}
				if applicationType == nil {
					return nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationType, logutils.StringArgs(appTypeIdentifier))
				}

				appConfig, _ := app.serGetAppConfig(appTypeIdentifier, orgID, versionNumbers, apiKey)
				if appConfig == nil {
					if isDelete {
						return nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationConfig, logutils.StringArgs(appTypeIdentifier))
					}

					// create new appConfig from webhook request
					appConfig, err = app.sysCreateAppConfig(applicationType.ID, orgID, data, versionNumbers)
					if err != nil {
						return nil, err
					}

					return appConfig, nil
				}

				// appConfig not nil
				if isDelete {
					err = app.sysDeleteAppConfig(appConfig.ID)
					return nil, err
				}

				// update
				if appConfig.Version.VersionNumbers == versionNumbers {
					err = app.sysUpdateAppConfig(appConfig.ID, applicationType.ID, orgID, data, versionNumbers)
					if err != nil {
						return nil, err
					}

					return appConfig, nil
				}

				// return nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationConfig, logutils.StringArgs(appTypeIdentifier))
				// create appConfig with a new version from webhook request
				appConfig, err = app.sysCreateAppConfig(applicationType.ID, orgID, data, versionNumbers)
				if err != nil {
					return nil, err
				}

				return appConfig, nil
			}
		}
	}

	return nil, nil
}

func (app *application) updateCachedWebhookConfigs() error {
	return app.github.UpdateCachedWebhookConfigs()
}
