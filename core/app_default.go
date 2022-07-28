package core

import (
	"core-building-block/core/model"
	"core-building-block/utils"
	"encoding/json"

	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logutils"
)

func (app *application) processWebhookRequest(commits []model.Commit) error {

	for _, commit := range commits {
		addedFiles := commit.Added
		if len(addedFiles) > 0 {
			// return l.HttpResponseErrorData(logutils.StatusInvalid, model.TypeGithubCommitAdded, nil, nil, http.StatusBadRequest, false)
			for _, path := range addedFiles {
				contentString, isWebhookConfigPath, err := app.github.GetContents(path)
				if err != nil {
					// fmt.Printf("fileContent.GetContent returned error: %v", err)
					continue
				}

				if isWebhookConfigPath {
					err = app.github.UpdateCachedWebhookConfigs()
					if err != nil {
						// TODO: add logging
					}
				} else {
					// update appplication config files in db
					valid, appType, envString, orgName, appName, major, minor, patch := utils.ParseWebhookFilePath(path)
					if valid != nil && *valid == true {
						versionNumber := model.VersionNumbers{Major: major, Minor: minor, Patch: patch}

						data := make(map[string]interface{})
						json.Unmarshal([]byte(contentString), &data)

						_, err = app.updateAppConfigFromWebhook(*envString, *orgName, *appName, appType, versionNumber, nil, false, data)
						if err != nil {
							// TODO: error logging
						}
					}
				}
			}
		}

		modifiedFiles := commit.Modified
		if len(modifiedFiles) > 0 {
			for _, path := range modifiedFiles {
				contentString, isWebhookConfigPath, err := app.github.GetContents(path)
				if err != nil {
					continue
				}

				if isWebhookConfigPath {
					err = app.github.UpdateCachedWebhookConfigs()
					if err != nil {
						// TODO: handle error
					}
				} else {
					valid, appType, envString, orgName, appName, major, minor, patch := utils.ParseWebhookFilePath(path)
					if valid != nil && *valid == true {
						versionNumber := model.VersionNumbers{Major: major, Minor: minor, Patch: patch}

						data := make(map[string]interface{})
						json.Unmarshal([]byte(contentString), &data)
						_, _ = app.updateAppConfigFromWebhook(*envString, *orgName, *appName, appType, versionNumber, nil, false, data)
					}
				}
			}
		}

		removedFiles := commit.Removed
		if len(removedFiles) > 0 {
			for _, path := range removedFiles {
				_, isWebhookConfigPath, err := app.github.GetContents(path)
				if err != nil {

				}
				if isWebhookConfigPath {
					err = app.updateCachedWebhookConfigs()
					if err != nil {
					}
				} else {
					// remove appplication config files in db
					valid, appType, envString, orgName, appName, major, minor, patch := utils.ParseWebhookFilePath(path)
					if valid != nil && *valid == true {
						versionNumber := model.VersionNumbers{Major: major, Minor: minor, Patch: patch}

						_, _ = app.updateAppConfigFromWebhook(*envString, *orgName, *appName, appType, versionNumber, nil, true, make(map[string]interface{}))
					}
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

	var appID *string
	var appTypeIdentifier string
	var appTypeID string
	if webhookConfig.Applications != nil {
		if appMap, ok := webhookConfig.Applications[appName]; ok {
			if appMap.Types != nil {
				if appType != "" {
					if appTypeIdentifier, ok = appMap.Types[appType]; ok {
						applicationType, err := app.storage.FindApplicationType(appTypeIdentifier)
						if err != nil {
							return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationType, logutils.StringArgs(appTypeIdentifier), err)
						}
						if applicationType == nil {
							return nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationType, logutils.StringArgs(appTypeIdentifier))
						}
						appTypeID = applicationType.ID
					}
				} else {
					appID = &appMap.ID
				}

				appConfig, _ := app.serGetAppConfig(appTypeIdentifier, appID, orgID, versionNumbers, apiKey)
				if appConfig == nil {
					if isDelete {
						return nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationConfig, logutils.StringArgs(appTypeIdentifier))
					}

					// create new appConfig from webhook request
					appConfig, err = app.sysCreateAppConfig(appTypeID, appID, orgID, data, versionNumbers)
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
					err = app.sysUpdateAppConfig(appConfig.ID, appTypeID, appID, orgID, data, versionNumbers)
					if err != nil {
						return nil, err
					}

					return appConfig, nil
				}

				// return nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationConfig, logutils.StringArgs(appTypeIdentifier))
				// create appConfig with a new version from webhook request
				appConfig, err = app.sysCreateAppConfig(appTypeID, appID, orgID, data, versionNumbers)
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
