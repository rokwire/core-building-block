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
	webhookConfigFile := []string{}
	baseConfigFiles := []model.AppConfigFile{}
	patchConfigFiles := []model.AppConfigFile{}

	for _, commit := range commits {
		app.groupFiles(&webhookConfigFile, &baseConfigFiles, &patchConfigFiles, commit.Added, false)
		app.groupFiles(&webhookConfigFile, &baseConfigFiles, &patchConfigFiles, commit.Modified, false)
		app.groupFiles(&webhookConfigFile, &baseConfigFiles, &patchConfigFiles, commit.Removed, true)
	}

	if len(webhookConfigFile) > 1 {
		return errors.ErrorData(logutils.StatusInvalid, model.TypeGitHubWebhookConfigFile, logutils.StringArgs("Could not have more than one webhook config file"))
	}

	// process webhook config file first
	if len(webhookConfigFile) == 1 {
		err := app.github.UpdateCachedWebhookConfigs()
		if err != nil {
			if err != nil {
				l.LogError("error updating GitHub webhook config file cache", err)
			}
		}
	}

	// process base then patch appConfig files
	err := app.processGitHubWebhookFiles(baseConfigFiles, l)
	if err != nil {
		l.LogError("error processing GitHub webhook base appConfig files", err)
	}
	err = app.processGitHubWebhookFiles(patchConfigFiles, l)
	if err != nil {
		l.LogError("error processing GitHub webhook patch appConfig files", err)
	}

	return nil
}

func (app *application) groupFiles(webhookConfigFile *[]string, baseConfigFiles *[]model.AppConfigFile, patchConfigFiles *[]model.AppConfigFile, files []string, isDelete bool) {
	if webhookConfigFile == nil || baseConfigFiles == nil || patchConfigFiles == nil {
		return
	}

	for _, path := range files {
		if app.github.IsWebhookConfigPath(path) {
			*webhookConfigFile = append(*webhookConfigFile, path)
		} else {
			_, appType, _, _, _, _, _, _ := utils.ParseWebhookFilePath(path)
			if appType == "" {
				*baseConfigFiles = append(*baseConfigFiles, model.AppConfigFile{Name: path, IsDelete: isDelete})
			} else {
				*patchConfigFiles = append(*patchConfigFiles, model.AppConfigFile{Name: path, IsDelete: isDelete})
			}
		}
	}

	return
}

func (app *application) processGitHubWebhookFiles(files []model.AppConfigFile, l *logs.Log) error {
	if len(files) < 1 {
		return nil
	}

	for _, path := range files {
		fileContent, _, err := app.github.GetContents(path.Name)
		if err != nil {
			l.LogError("fileContent.GetContent returned error: %v", err)
			continue
		}
		contentString, err := fileContent.GetContent()
		if err != nil {
			return err
		}

		valid, appType, envString, orgName, appName, major, minor, patch := utils.ParseWebhookFilePath(path.Name)
		if valid == true {
			versionNumber := model.VersionNumbers{Major: major, Minor: minor, Patch: patch}

			data := make(map[string]interface{})
			json.Unmarshal([]byte(contentString), &data)

			_, err = app.updateAppConfigFromWebhook(*envString, *orgName, *appName, appType, versionNumber, nil, path.IsDelete, data)
			if err != nil {
				l.LogError(fmt.Sprintf("error updating file with path: %s", path.Name), err)
			}
		}
	}

	return nil
}

func (app *application) updateAppConfigFromWebhook(enviromentString string, orgName string, appName string, appType string, versionNumbers model.VersionNumbers, apiKey *string, isDelete bool, data map[string]interface{}) (*model.ApplicationConfig, error) {
	webhookConfig, err := app.github.FindWebhookConfig()
	if err != nil || webhookConfig == nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeGitHubWebhookConfigFile, logutils.StringArgs(orgName), err)
	}

	var orgID *string
	orgMap := webhookConfig.Organizations
	if _, ok := orgMap[orgName]; ok {
		t := orgMap[orgName]
		orgID = &t
	}

	if webhookConfig.Applications != nil {
		if appMap, ok := webhookConfig.Applications[appName]; ok {
			if appMap.Types != nil {
				if appType != "" {
					return app.updatePatchAppConfigFile(appType, appMap, enviromentString, orgName, orgID, appName, versionNumbers, isDelete, data)
				}

				return app.updateBaseAppConfigFile(appMap, enviromentString, orgName, orgID, appName, versionNumbers, isDelete, data)
			}
		}
	}

	return nil, nil
}

// update associated merged appConfig files in db and cache
func (app *application) updateBaseAppConfigFile(appMap model.ApplicationTypes, enviromentString string, orgName string, orgID *string, appName string, versionNumbers model.VersionNumbers, isDelete bool, baseFileData map[string]interface{}) (*model.ApplicationConfig, error) {
	var appID *string
	var appTypeID string
	if appMap.Types != nil {
		appID = &appMap.ID
		// 1 load all path files from git
		for appTypeName, appTypeIdentifier := range appMap.Types {
			patchFileDirectory := fmt.Sprintf("%s/%s/%s/%s", enviromentString, orgName, appName, appTypeName)
			_, patchFileList, err := app.github.GetContents(patchFileDirectory)
			if err != nil || patchFileList == nil || len(patchFileList) == 0 {
				continue
			}

			applicationType, err := app.storage.FindApplicationType(appTypeIdentifier)
			if err != nil {
				return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationType, logutils.StringArgs(appTypeIdentifier), err)
			}
			if applicationType == nil {
				return nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationType, logutils.StringArgs(appTypeIdentifier))
			}
			appTypeID = applicationType.ID

			// 2 merge base with 'best match version' patch file
			patchFileMap := make(map[model.VersionNumbers]map[string]interface{}, 0)
			for _, patchFile := range patchFileList {
				if patchFile == nil {
					continue
				}
				currentPath := *patchFile.Path
				major, minor, patch := utils.GetFileVersion(currentPath)
				patchFileVersion := model.VersionNumbers{Major: major, Minor: minor, Patch: patch}
				fileContent, _, err := app.github.GetContents(currentPath)
				if err != nil || fileContent == nil {
					continue
				}
				contentString, err := fileContent.GetContent()
				patchData := make(map[string]interface{})
				err = json.Unmarshal([]byte(contentString), &patchData)
				if err != nil {
					continue
				}
				patchFileMap[patchFileVersion] = patchData
			}

			var targetPatchData map[string]interface{}
			basePatchData, ok := patchFileMap[model.VersionNumbers{Major: 0, Minor: 0, Patch: 0}]
			if ok {
				targetPatchData = basePatchData
			}

			if patch, ok := patchFileMap[versionNumbers]; ok {
				targetPatchData = patch
			}

			for key, value := range targetPatchData {
				baseFileData[key] = value
			}

			_, err = app.updateMergedAppConfig(appTypeIdentifier, appTypeID, appID, orgID, versionNumbers, nil, isDelete, baseFileData)
			if err != nil {
				// l.LogError(fmt.Sprintf("error updating file with path: %s", path.Name), err)
			}
		}
	}

	return nil, nil
}

func (app *application) updatePatchAppConfigFile(appType string, appMap model.ApplicationTypes, enviromentString string, orgName string, orgID *string, appName string, versionNumbers model.VersionNumbers, isDelete bool, patchFileData map[string]interface{}) (*model.ApplicationConfig, error) {
	var appID *string

	appTypeIdentifier, ok := appMap.Types[appType]
	if !ok {
		return nil, nil
	}
	applicationType, err := app.storage.FindApplicationType(appTypeIdentifier)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationType, logutils.StringArgs(appTypeIdentifier), err)
	}
	if applicationType == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationType, logutils.StringArgs(appTypeIdentifier))
	}
	appTypeID := applicationType.ID

	baseFileDirectory := fmt.Sprintf("%s/%s/%s", enviromentString, orgName, appName)
	baseFileMap := app.buildDirectoryFileMap(baseFileDirectory)

	defaultVersion := model.VersionNumbers{Major: 0, Minor: 0, Patch: 0}
	if versionNumbers.LessThanOrEqualTo(&defaultVersion) {
		// a default patch file without a specific version
		patchFileDirectory := fmt.Sprintf("%s/%s/%s/%s", enviromentString, orgName, appName, appType)
		patchFileMap := app.buildDirectoryFileMap(patchFileDirectory)
		for baseFileVersion, baseFile := range baseFileMap {
			var matchedPatchFile *map[string]interface{}
			if !baseFileVersion.LessThanOrEqualTo(&defaultVersion) {
				// check for matched patch file for a version specific base config file
				if patchFile, ok := patchFileMap[baseFileVersion]; ok {
					matchedPatchFile = &patchFile
				}
			}
			if matchedPatchFile == nil {
				// current default patch file will be applied to all base files without a matched version specific patch file
				for key, value := range patchFileData {
					baseFile[key] = value
				}
				_, err = app.updateMergedAppConfig(appTypeIdentifier, appTypeID, appID, orgID, versionNumbers, nil, isDelete, baseFile)
			}
		}
	} else {
		if baseFileData, ok := baseFileMap[versionNumbers]; ok {
			for key, value := range patchFileData {
				baseFileData[key] = value
			}
			_, err = app.updateMergedAppConfig(appTypeIdentifier, appTypeID, appID, orgID, versionNumbers, nil, isDelete, baseFileData)
		}
	}

	return nil, nil
}

func (app *application) updateMergedAppConfig(appTypeIdentifier string, appTypeID string, appID *string, orgID *string, versionNumbers model.VersionNumbers, apiKey *string, isDelete bool, data map[string]interface{}) (*model.ApplicationConfig, error) {
	appConfig, _ := app.serGetAppConfig(appTypeIdentifier, appID, orgID, versionNumbers, apiKey)
	if appConfig == nil {
		if isDelete {
			return nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationConfig, logutils.StringArgs(appTypeIdentifier))
		}

		// create new appConfig from webhook request
		appConfig, err := app.sysCreateAppConfig(appTypeID, appID, orgID, data, versionNumbers)
		if err != nil {
			return nil, err
		}

		return appConfig, nil
	}

	// appConfig not nil
	if isDelete {
		err := app.sysDeleteAppConfig(appConfig.ID)
		return nil, err
	}

	if appConfig.Version.VersionNumbers == versionNumbers {
		err := app.sysUpdateAppConfig(appConfig.ID, appTypeID, appID, orgID, data, versionNumbers)
		if err != nil {
			return nil, err
		}

		return appConfig, nil
	}

	appConfig, err := app.sysCreateAppConfig(appTypeID, appID, orgID, data, versionNumbers)
	if err != nil {
		return nil, err
	}

	return appConfig, nil
}

func (app *application) buildDirectoryFileMap(directory string) map[model.VersionNumbers]map[string]interface{} {
	fileMap := make(map[model.VersionNumbers]map[string]interface{}, 0)

	_, fileList, err := app.github.GetContents(directory)
	if err != nil || fileList == nil || len(fileList) == 0 {
		return nil
	}

	for _, file := range fileList {
		if file == nil {
			continue
		}
		currentPath := *file.Path
		fileContent, _, err := app.github.GetContents(currentPath)
		if err != nil || fileContent == nil {
			continue
		}
		contentString, err := fileContent.GetContent()
		patchData := make(map[string]interface{})
		err = json.Unmarshal([]byte(contentString), &patchData)
		if err != nil {
			continue
		}

		major, minor, patch := utils.GetFileVersion(currentPath)
		fileVersion := model.VersionNumbers{Major: major, Minor: minor, Patch: patch}
		fileMap[fileVersion] = patchData
	}

	return fileMap
}

func (app *application) updateCachedWebhookConfigs() error {
	return app.github.UpdateCachedWebhookConfigs()
}
