package web

import (
	"core-building-block/core/model"
	Def "core-building-block/driver/web/docs/gen"
	"encoding/json"
	"net/http"

	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
)

//Helper for authLogin and authLoginMFA
func authBuildLoginResponse(l *logs.Log, loginSession *model.LoginSession) logs.HttpResponse {
	//token
	accessToken := loginSession.AccessToken
	refreshToken := loginSession.CurrentRefreshToken()

	tokenType := Def.ResSharedRokwireTokenTokenTypeBearer
	rokwireToken := Def.ResSharedRokwireToken{AccessToken: &accessToken, RefreshToken: &refreshToken, TokenType: &tokenType}

	//account
	var accountData *Def.ResSharedAccount
	if !loginSession.Anonymous {
		account := loginSession.AccountAuthType.Account
		accountData = accountToDef(account)
	}

	//params
	var paramsRes interface{}
	if loginSession.Params != nil {
		paramsRes = loginSession.Params
	}

	responseData := &Def.ResSharedLogin{Token: &rokwireToken, Account: accountData, Params: &paramsRes}
	respData, err := json.Marshal(responseData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, logutils.MessageDataType("auth login response"), nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(respData)
}
