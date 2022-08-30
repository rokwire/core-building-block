package core

import (
	"core-building-block/core/model"

	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
)

func (app *application) processVCSAppConfigWebhook(data []byte, l *logs.Log) error {
	commits, err := app.github.ProcessAppConfigWebhook(data, l)
	if err != nil {
		return errors.Wrap("error processing app config webhook", err)
	}

	for _, commit := range commits {
		if commit.Config != nil {
			err := app.updateCachedWebhookConfig(commit.Config)
			if err != nil {
				l.LogError("error updating webhook config file cache", err)
			}
		} else {
			app.updateWebhookAppConfigs(commit.Added, false, l)
			app.updateWebhookAppConfigs(commit.Modified, false, l)
			app.updateWebhookAppConfigs(commit.Removed, true, l)
		}
	}

	return nil
}

func (app *application) updateWebhookAppConfigs(configs []model.WebhookAppConfig, isDelete bool, l *logs.Log) {
	for _, config := range configs {
		_, err := app.updateAppConfigFromWebhook(config, isDelete)
		if err != nil {
			l.LogError("error updating webhook app config", err)
		}
	}
}

func (app *application) updateAppConfigFromWebhook(config model.WebhookAppConfig, isDelete bool) (*model.ApplicationConfig, error) {
	webhookConfig, err := app.FindWebhookConfig()
	if err != nil || webhookConfig == nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeWebhookConfig, logutils.StringArgs(config.OrgName), err)
	}

	var orgID *string
	orgMap := webhookConfig.Organizations
	if _, ok := orgMap[config.OrgName]; ok {
		t := orgMap[config.OrgName]
		orgID = &t
	}
	if webhookConfig.Applications != nil {
		if appMap, ok := webhookConfig.Applications[config.AppName]; ok {
			if appTypeIdentifier, ok := appMap[config.AppType]; ok {
				applicationType, err := app.storage.FindApplicationType(appTypeIdentifier)
				if err != nil {
					return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationType, logutils.StringArgs(appTypeIdentifier), err)
				}
				if applicationType == nil {
					return nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationType, logutils.StringArgs(appTypeIdentifier))
				}

				appConfig, _ := app.serGetAppConfig(appTypeIdentifier, orgID, config.VersionNumbers, config.APIKey)
				if appConfig == nil {
					if isDelete {
						return nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationConfig, logutils.StringArgs(appTypeIdentifier))
					}

					// create new appConfig from webhook request
					appConfig, err = app.sysCreateAppConfig(applicationType.ID, orgID, config.Data, config.VersionNumbers, true)
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
				if appConfig.Version.VersionNumbers == config.VersionNumbers {
					err = app.sysUpdateAppConfig(appConfig.ID, applicationType.ID, orgID, config.Data, config.VersionNumbers, true)
					if err != nil {
						return nil, err
					}

					return appConfig, nil
				}

				// return nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationConfig, logutils.StringArgs(appTypeIdentifier))
				// create appConfig with a new version from webhook request
				appConfig, err = app.sysCreateAppConfig(applicationType.ID, orgID, config.Data, config.VersionNumbers, true)
				if err != nil {
					return nil, err
				}

				return appConfig, nil
			}
		}
	}

	return nil, nil
}
