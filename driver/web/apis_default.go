package web

import (
	"context"
	"core-building-block/core"
	"core-building-block/core/model"
	Def "core-building-block/driver/web/docs/gen"
	"core-building-block/utils"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/google/go-github/v44/github"
	"github.com/rokwire/core-auth-library-go/tokenauth"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
	"golang.org/x/oauth2"
)

//DefaultApisHandler handles default APIs implementation - version etc
type DefaultApisHandler struct {
	coreAPIs *core.APIs
}

//getVersion gives the service version
func (h DefaultApisHandler) getVersion(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	version := h.coreAPIs.GetVersion()

	return l.HttpResponseSuccessMessage(version)
}

//getOpenIDConfiguration gives the OpenID Connect Discovery page
func (h DefaultApisHandler) getOpenIDConfiguration(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	discovery := Def.OIDCDiscovery{Issuer: h.coreAPIs.Auth.GetHost(), JwksUri: h.coreAPIs.Auth.GetHost() + "/tps/auth-keys"}

	data, err := json.Marshal(discovery)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, "openid configs", nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(data)
}

func (h DefaultApisHandler) handleWebhookConfigChange(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData model.WebhookRequest
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypeApplicationConfigWebhook, nil, err, http.StatusBadRequest, true)
	}

	// h.coreAPIs.ProcessWebhookRequest(requestData)
	commits := requestData.Commits
	if len(commits) < 1 {
		return l.HttpResponseErrorData(logutils.StatusInvalid, model.TypeGithubCommit, nil, nil, http.StatusBadRequest, false)
	}

	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: h.coreAPIs.GithubWebhookToken},
	)
	tc := oauth2.NewClient(ctx, ts)

	client := github.NewClient(tc)

	for _, commit := range commits {

		// TODO: also need to handle commit.Modified/Deleted
		addedFiles := commit.Added
		if len(addedFiles) > 0 {
			// return l.HttpResponseErrorData(logutils.StatusInvalid, model.TypeGithubCommitAdded, nil, nil, http.StatusBadRequest, false)

			for _, path := range addedFiles {
				fileContent, _, _, err := client.Repositories.GetContents(ctx, h.coreAPIs.GithubWebhookOrgnizationName, h.coreAPIs.GithubWebhookRepoName, path, &github.RepositoryContentGetOptions{Ref: "develop"})
				if err != nil || fileContent == nil {
					fmt.Printf("Repositories.GetContents returned error: %v", err)
					continue
				}

				contentString, err := fileContent.GetContent()
				if err != nil {
					fmt.Printf("fileContent.GetContent returned error: %v", err)
				}

				if path == h.coreAPIs.GithubWebhookConfigPath {
					// update webhook configs
					err = h.coreAPIs.Default.UpdateCachedWebhookConfigs()
					if err != nil {
						// return l.HttpResponseErrorAction(logutils.ActionUpdate, model.TypeWebhookConfig, nil, err, http.StatusInternalServerError, true)
					}
				} else {
					// update actual app config files

					// If both s and sep are empty, Split returns an empty slice.
					valid, appType, envString, orgName, appName, major, minor, patch := utils.ParseWebhookFilePath(path)
					if valid != nil && *valid == true {
						versionNumber := model.VersionNumbers{Major: major, Minor: minor, Patch: patch}

						data := make(map[string]interface{})
						json.Unmarshal([]byte(contentString), &data)

						// TODO: error message will be logged in storage functions?
						_, _ = h.coreAPIs.Default.UpdateAppConfigFromWebhook(*envString, *orgName, *appName, appType, versionNumber, nil, false, data)
					}
				}
			}
		}

		modifiedFiles := commit.Modified
		if len(modifiedFiles) > 0 {
			for _, path := range modifiedFiles {
				fileContent, _, _, err := client.Repositories.GetContents(ctx, h.coreAPIs.GithubWebhookOrgnizationName, h.coreAPIs.GithubWebhookRepoName, path, &github.RepositoryContentGetOptions{Ref: "develop"})
				if err != nil || fileContent == nil {
					fmt.Printf("Repositories.GetContents returned error: %v", err)
					continue
				}

				contentString, err := fileContent.GetContent()
				if err != nil {
					fmt.Printf("fileContent.GetContent returned error: %v", err)
				}

				if path == h.coreAPIs.GithubWebhookConfigPath {
					// update webhook configs
					err = h.coreAPIs.Default.UpdateCachedWebhookConfigs()
					if err != nil {
						// TODO: add error message but not return http error
						// return l.HttpResponseErrorAction(logutils.ActionUpdate, model.TypeWebhookConfig, nil, err, http.StatusInternalServerError, true)
					}
				} else {
					// update actual app config files

					// If both s and sep are empty, Split returns an empty slice.
					valid, appType, envString, orgName, appName, major, minor, patch := utils.ParseWebhookFilePath(path)
					if valid != nil && *valid == true {
						versionNumber := model.VersionNumbers{Major: major, Minor: minor, Patch: patch}

						data := make(map[string]interface{})
						json.Unmarshal([]byte(contentString), &data)

						_, _ = h.coreAPIs.Default.UpdateAppConfigFromWebhook(*envString, *orgName, *appName, appType, versionNumber, nil, false, data)
					}
				}
			}
		}

		removedFiles := commit.Removed
		if len(removedFiles) > 0 {
			for _, path := range removedFiles {
				if path == h.coreAPIs.GithubWebhookConfigPath {
					// update webhook configs
					err = h.coreAPIs.Default.UpdateCachedWebhookConfigs()
					if err != nil {
						// return l.HttpResponseErrorAction(logutils.ActionUpdate, model.TypeWebhookConfig, nil, err, http.StatusInternalServerError, true)
					}
				} else {
					// remove actual app config files

					// If both s and sep are empty, Split returns an empty slice.
					valid, appType, envString, orgName, appName, major, minor, patch := utils.ParseWebhookFilePath(path)
					if valid != nil && *valid == true {
						versionNumber := model.VersionNumbers{Major: major, Minor: minor, Patch: patch}

						_, _ = h.coreAPIs.Default.UpdateAppConfigFromWebhook(*envString, *orgName, *appName, appType, versionNumber, nil, true, make(map[string]interface{}))
					}
				}
			}
		}

	}

	// TODO: when and what do we return if all update attempts failed
	return l.HttpResponseSuccess()
}

//NewDefaultApisHandler creates new rest services Handler instance
func NewDefaultApisHandler(coreAPIs *core.APIs) DefaultApisHandler {
	return DefaultApisHandler{coreAPIs: coreAPIs}
}
