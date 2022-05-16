package core

import (
	"core-building-block/core/model"

	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logutils"
)

func (app *application) updateAppConfigFromWebhook(enviromentString string, orgName string, appName string, appType string, versionNumbers model.VersionNumbers, apiKey *string, isDelete bool, data map[string]interface{}) (*model.ApplicationConfig, error) {
	webhookConfig, err := app.storage.FindWebhookConfig()
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

				if isDelete {
					err = app.sysDeleteAppConfig(appConfig.ID)
					if err != nil {
						return nil, err
					}
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
	return app.storage.UpdateCachedWebhookConfigs()
}
