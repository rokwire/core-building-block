package web

import (
	"core-building-block/core"
	"core-building-block/core/model"
	Def "core-building-block/driver/web/docs/gen"
	"encoding/json"
	"net/http"

	"github.com/google/go-github/v44/github"
	"github.com/rokwire/core-auth-library-go/tokenauth"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
)

//DefaultApisHandler handles default APIs implementation - version etc
type DefaultApisHandler struct {
	coreAPIs                  *core.APIs
	githubWebhookRequestToken string
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
	// verify webhook request signature
	data, err := github.ValidatePayload(r, []byte(h.githubWebhookRequestToken))

	// if string(payload) != body {
	// err = fmt.Errorf("ValidatePayload = %q, want %q", payload, body)
	// }

	if err != nil {
		return l.HttpResponseErrorData(logutils.MessageDataStatus(logutils.ActionValidate), model.TypeWebhookSecretToken, nil, nil, http.StatusBadRequest, false)
	}

	var requestData model.WebhookRequest
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypeApplicationConfigWebhook, nil, err, http.StatusBadRequest, true)
	}

	commits := requestData.Commits
	if len(commits) < 1 {
		return l.HttpResponseErrorData(logutils.StatusInvalid, model.TypeGithubCommit, nil, nil, http.StatusBadRequest, false)
	}
	err = h.coreAPIs.Default.ProcessWebhookRequest(commits)

	// TODO: when and what do we return if all update attempts failed
	return l.HttpResponseSuccess()
}

//NewDefaultApisHandler creates new rest services Handler instance
func NewDefaultApisHandler(coreAPIs *core.APIs) DefaultApisHandler {
	return DefaultApisHandler{coreAPIs: coreAPIs}
}
