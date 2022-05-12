package core

import (
	"core-building-block/core/model"

	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logutils"
)

func (app *application) createAppConfigFromWebhook(enviromentString string, orgName string, appName string, appType string, versionNumbers model.VersionNumbers, apiKey *string, data map[string]interface{}) (*model.ApplicationConfig, error) {

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
				// TODO:
				appConfig, _ := app.serGetAppConfig(appTypeIdentifier, orgID, versionNumbers, apiKey)
				if appConfig == nil {
					// insert current new appConfig
					// appTypeIdentifier = "com.rokmetro.safercommunity"
					applicationType, err := app.storage.FindApplicationType(appTypeIdentifier)
					if err != nil {
						return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationType, logutils.StringArgs(appTypeIdentifier), err)
					}
					if applicationType == nil {
						return nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationType, logutils.StringArgs(appTypeIdentifier))
					}

					appConfig, err = app.sysCreateAppConfig(applicationType.ID, orgID, data, versionNumbers)
					if err != nil {
						return nil, err
					}
				}

				return appConfig, nil
			}
		}
	}

	return nil, nil
}
