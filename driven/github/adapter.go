package github

import (
	"bytes"
	"context"
	"core-building-block/core/model"
	"encoding/json"
	"mime"
	"strconv"
	"strings"

	"github.com/google/go-github/v44/github"
	"github.com/rokwire/core-auth-library-go/v2/sigauth"
	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
	"golang.org/x/oauth2"
)

// Adapter implements the GitHub interface
type Adapter struct {
	githubToken             string
	githubOrganizationName  string
	githubRepoName          string
	githubWebhookConfigPath string
	githubWebhookSecret     string
	githubAppConfigBranch   string

	logger *logs.Logger
}

// Start starts the github adapter
func (a *Adapter) Start() error {
	return nil
}

func (a *Adapter) checkConfigs() error {
	if a.githubToken == "" {
		return errors.ErrorData(logutils.StatusMissing, "config", logutils.StringArgs("github token"))
	}
	if a.githubOrganizationName == "" {
		return errors.ErrorData(logutils.StatusMissing, "config", logutils.StringArgs("github org name"))
	}
	if a.githubRepoName == "" {
		return errors.ErrorData(logutils.StatusMissing, "config", logutils.StringArgs("github repo name"))
	}
	if a.githubAppConfigBranch == "" {
		return errors.ErrorData(logutils.StatusMissing, "config", logutils.StringArgs("github branch"))
	}
	return nil
}

// GetContents get file content from GitHub
func (a *Adapter) GetContents(path string) (string, bool, error) {
	err := a.checkConfigs()
	if err != nil {
		return "", false, err
	}
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

// LoadWebhookConfig loads the webhook config from GitHub
func (a *Adapter) LoadWebhookConfig() (*model.WebhookConfig, error) {
	contentString, _, err := a.GetContents(a.githubWebhookConfigPath)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGet, "github content", logutils.StringArgs("webhook config"), err)
	}

	var webhookConfig model.WebhookConfig
	err = json.Unmarshal([]byte(contentString), &webhookConfig)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, model.TypeWebhookConfig, nil, err)
	}

	return &webhookConfig, nil
}

// ProcessAppConfigWebhook processes an incoming GitHub app config webhook request
func (a *Adapter) ProcessAppConfigWebhook(r *sigauth.Request, l *logs.Log) ([]model.WebhookAppConfigCommit, error) {
	err := a.validatePayload(r)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionValidate, model.TypeWebhookSecretToken, nil, err)
	}
	var requestData webhookRequest
	err = json.Unmarshal(r.Body, &requestData)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, model.TypeApplicationConfigWebhook, nil, err)
	}
	gitRefs := strings.Split(requestData.Ref, "/")
	if len(gitRefs) == 0 {
		return nil, errors.WrapErrorData(logutils.StatusMissing, logutils.MessageDataType("github webhook repository branch"), nil, nil)
	}
	branchName := gitRefs[len(gitRefs)-1]
	if branchName != a.githubAppConfigBranch {
		return nil, errors.WrapErrorData(logutils.StatusInvalid, logutils.MessageDataType("github webhook repository branch"), nil, nil)
	}
	commits := requestData.Commits
	if len(commits) < 1 {
		return nil, errors.WrapErrorData(logutils.StatusInvalid, model.TypeGithubCommit, nil, nil)
	}

	appConfigCommits := []model.WebhookAppConfigCommit{}
	for _, commit := range commits {
		webhookCommit := model.WebhookAppConfigCommit{}
		var config *model.WebhookConfig
		config, webhookCommit.Added = a.processGitHubWebhookFiles(commit.Added, l)
		if config != nil {
			webhookCommit.Config = config
		}
		config, webhookCommit.Modified = a.processGitHubWebhookFiles(commit.Modified, l)
		if config != nil {
			webhookCommit.Config = config
		}
		_, webhookCommit.Removed = a.processGitHubWebhookFiles(commit.Removed, l)
		appConfigCommits = append(appConfigCommits, webhookCommit)
	}

	return appConfigCommits, nil
}

func (a *Adapter) processGitHubWebhookFiles(files []string, l *logs.Log) (*model.WebhookConfig, []model.WebhookAppConfig) {
	if len(files) < 1 {
		return nil, nil
	}

	var webhookConfig *model.WebhookConfig
	appConfigs := []model.WebhookAppConfig{}
	for _, path := range files {
		contentString, isWebhookConfigPath, err := a.GetContents(path)
		if err != nil {
			// fmt.Printf("fileContent.GetContent returned error: %v", err)
			l.LogError("error getting GitHub contents", err)
			continue
		}

		if isWebhookConfigPath {
			var webhookConfigData model.WebhookConfig
			err = json.Unmarshal([]byte(contentString), &webhookConfigData)
			if err != nil {
				l.LogError("error unmarshalling webhook config GitHub contents", err)
				continue
			}
			webhookConfig = &webhookConfigData
		} else {
			// update appplication config files in db
			webhookAppConfig, err := a.parseWebhookAppConfig(path, contentString)
			if err != nil {
				l.LogError("error parsing webhook file path "+path, err)
			}
			appConfigs = append(appConfigs, *webhookAppConfig)
		}
	}

	return webhookConfig, appConfigs
}

// parseWebhookFilePath parses the committed file path in the webhook request
func (a *Adapter) parseWebhookAppConfig(path string, contentString string) (*model.WebhookAppConfig, error) {
	dirs := strings.Split(path, "/")

	webhookAppConfig := model.WebhookAppConfig{}
	// appType := ""
	if len(dirs) == 4 || len(dirs) == 5 {
		// "/env/org_name/applications_name/config.xxx.json"
		webhookAppConfig.EnvironmentString, webhookAppConfig.OrgName, webhookAppConfig.AppName = dirs[0], dirs[1], dirs[2]
		if len(dirs) == 5 {
			// "/env/org_name/applications_name/app_type/config.xxx.json"
			webhookAppConfig.AppType = dirs[3]
		}

		fileName := strings.Split(dirs[len(dirs)-1], ".")
		if len(fileName) == 5 {
			var versionNumbers model.VersionNumbers
			tmp, err := strconv.Atoi(fileName[1])
			if err != nil {
				return nil, errors.WrapErrorAction(logutils.ActionParse, logutils.TypeInt, logutils.StringArgs("major version"), err)
			}
			versionNumbers.Major = tmp

			tmp, err = strconv.Atoi(fileName[2])
			if err != nil {
				return nil, errors.WrapErrorAction(logutils.ActionParse, logutils.TypeInt, logutils.StringArgs("minor version"), err)
			}
			versionNumbers.Minor = tmp

			tmp, err = strconv.Atoi(fileName[3])
			if err != nil {
				return nil, errors.WrapErrorAction(logutils.ActionParse, logutils.TypeInt, logutils.StringArgs("patch version"), err)
			}
			versionNumbers.Patch = tmp
			webhookAppConfig.VersionNumbers = versionNumbers
		}
	}
	var data map[string]interface{}
	err := json.Unmarshal([]byte(contentString), &data)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, "content map", nil, err)
	}
	webhookAppConfig.Data = data
	return &webhookAppConfig, nil
}

func (a *Adapter) validatePayload(r *sigauth.Request) (err error) {
	if a.githubWebhookSecret == "" {
		return errors.ErrorData(logutils.StatusMissing, "config", logutils.StringArgs("github webhook secret"))
	}

	signature := r.GetHeader(github.SHA256SignatureHeader)
	if signature == "" {
		signature = r.GetHeader(github.SHA1SignatureHeader)
	}

	contentType, _, err := mime.ParseMediaType(r.GetHeader("Content-Type"))
	if err != nil {
		return err
	}

	body := bytes.NewReader(r.Body)

	_, err = github.ValidatePayloadFromBody(contentType, body, signature, []byte(a.githubWebhookSecret))

	return err
}

// NewGitHubAdapter creates a new GitHub adapter instance
func NewGitHubAdapter(githubToken string, githubOrganizationName string, githubRepoName string, githubWebhookConfigPath string,
	githubWebhookSecret string, githubAppConfigBranch string, logger *logs.Logger) *Adapter {
	return &Adapter{githubToken: githubToken, githubOrganizationName: githubOrganizationName, githubRepoName: githubRepoName,
		githubWebhookConfigPath: githubWebhookConfigPath, githubWebhookSecret: githubWebhookSecret, githubAppConfigBranch: githubAppConfigBranch, logger: logger}
}
