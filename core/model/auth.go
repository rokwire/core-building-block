// Copyright 2022 Board of Trustees of the University of Illinois.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package model

import (
	"core-building-block/utils"
	"fmt"
	"time"

	"github.com/rokwire/rokwire-building-block-sdk-go/services/core/auth"
	"github.com/rokwire/rokwire-building-block-sdk-go/services/core/auth/authorization"
	"github.com/rokwire/rokwire-building-block-sdk-go/utils/logging/logutils"
)

const (
	//TypeLoginSession login session type
	TypeLoginSession logutils.MessageDataType = "login session"
	//TypeAuthType auth type
	TypeAuthType logutils.MessageDataType = "auth type"
	//TypeIdentityProvider identity provider type
	TypeIdentityProvider logutils.MessageDataType = "identity provider"
	//TypeIdentityProviderConfig identity provider config type
	TypeIdentityProviderConfig logutils.MessageDataType = "identity provider config"
	//TypeIdentityProviderSetting identity provider setting type
	TypeIdentityProviderSetting logutils.MessageDataType = "identity provider setting"
	//TypeUserAuth user auth type
	TypeUserAuth logutils.MessageDataType = "user auth"
	//TypeAuthCred auth cred type
	TypeAuthCred logutils.MessageDataType = "auth cred"
	//TypeCredential credential type
	TypeCredential logutils.MessageDataType = "credential"
	//TypeAuthRefresh auth refresh type
	TypeAuthRefresh logutils.MessageDataType = "auth refresh"
	//TypeRefreshToken refresh token type
	TypeRefreshToken logutils.MessageDataType = "refresh token"
	//TypeServiceAccount service account type
	TypeServiceAccount logutils.MessageDataType = "service account"
	//TypeServiceAccountCredential service account type
	TypeServiceAccountCredential logutils.MessageDataType = "service account credential"
	//TypeAppOrgPair app org pair
	TypeAppOrgPair logutils.MessageDataType = "app org pair"
	//TypeServiceReg service reg type
	TypeServiceReg logutils.MessageDataType = "service reg"
	//TypeServiceScope service scope type
	TypeServiceScope logutils.MessageDataType = "service scope"
	//TypeServiceAuthorization service authorization type
	TypeServiceAuthorization logutils.MessageDataType = "service authorization"
	//TypeScope scope type
	TypeScope logutils.MessageDataType = "scope"
	//TypeJSONWebKey JWK type
	TypeJSONWebKey logutils.MessageDataType = "jwk"
	//TypeJSONWebKeySet JWKS type
	TypeJSONWebKeySet logutils.MessageDataType = "jwks"
	//TypePubKey pub key type
	TypePubKey logutils.MessageDataType = "pub key"
	//TypeAPIKey api key type
	TypeAPIKey logutils.MessageDataType = "api key"
	//TypeCreds cred type
	TypeCreds logutils.MessageDataType = "creds"
	//TypeIP auth type type
	TypeIP logutils.MessageDataType = "ip"

	// AdminScopePrefix is the prefix on scope resources used to indicate that the scope is intended for administration
	AdminScopePrefix string = "admin_"
	// UpdateScopesPermission is the permission that allows an admin to update account/role scopes
	UpdateScopesPermission string = "update_auth_scopes"
	//TokenTypeBearer bearer token type
	TokenTypeBearer string = "Bearer"
)

// LoginSession represents login session entity
type LoginSession struct {
	ID string

	AppOrg   ApplicationOrganization
	AuthType AuthType
	AppType  ApplicationType

	Anonymous bool

	Identifier      string //it is the account id(anonymous id for anonymous logins)
	ExternalIDs     map[string]string
	AccountAuthType *AccountAuthType //it may be nil for anonymous logins

	Device *Device

	IPAddress     string
	AccessToken   string
	RefreshTokens []string
	Params        map[string]interface{} //authType-specific set of parameters passed back to client

	State        string
	StateExpires *time.Time
	MfaAttempts  int

	DateRefreshed *time.Time

	DateUpdated *time.Time
	DateCreated time.Time
}

// IsExpired says if the sessions is expired
func (ls LoginSession) IsExpired() bool {
	loginsSessionsSetting := ls.AppOrg.LoginsSessionsSetting

	inactivityExpirePolicy := loginsSessionsSetting.InactivityExpirePolicy
	tslExpirePolicy := loginsSessionsSetting.TSLExpirePolicy
	yearlyExpirePolicy := loginsSessionsSetting.YearlyExpirePolicy

	inactivityActive := inactivityExpirePolicy.Active
	tslActive := tslExpirePolicy.Active
	yearlyActive := yearlyExpirePolicy.Active

	//we must have at least one active expiration policy
	if !inactivityActive && !tslActive && !yearlyActive {
		return true //expired
	}

	expired := true //expired by default

	if inactivityActive {
		//check if satisfy the policy
		expired = ls.isInactivityExpired(inactivityExpirePolicy)
		if expired {
			return true
		}
	}

	if tslActive {
		//check if satisfy the policy
		expired = ls.isTSLExpired(tslExpirePolicy)
		if expired {
			return true
		}
	}

	if yearlyActive {
		//check if satisfy the policy
		expired = ls.isYearlyExpired(yearlyExpirePolicy)
		if expired {
			return true
		}
	}

	return expired
}

func (ls LoginSession) isInactivityExpired(policy InactivityExpirePolicy) bool {
	lastRefreshedDate := ls.DateRefreshed
	if lastRefreshedDate == nil {
		lastRefreshedDate = &ls.DateCreated //not refreshed yet
	}

	expiresDate := lastRefreshedDate.Add(time.Duration(policy.InactivityPeriod) * time.Minute)
	now := time.Now()

	return expiresDate.Before(now)
}

func (ls LoginSession) isTSLExpired(policy TSLExpirePolicy) bool {
	loginDate := ls.DateCreated
	expiresDate := loginDate.Add(time.Duration(policy.TimeSinceLoginPeriod) * time.Minute)
	now := time.Now()

	return expiresDate.Before(now)
}

func (ls LoginSession) isYearlyExpired(policy YearlyExpirePolicy) bool {
	createdDate := ls.DateCreated

	now := time.Now().UTC()

	min := policy.Min
	hour := policy.Hour
	day := policy.Day
	month := policy.Month
	year, _, _ := now.Date()

	expiresDate := time.Date(year, time.Month(month), day, hour, min, 0, 0, time.UTC)

	return createdDate.Before(expiresDate) && expiresDate.Before(now)
}

// CurrentRefreshToken returns the current refresh token (last element of RefreshTokens)
func (ls LoginSession) CurrentRefreshToken() string {
	numTokens := len(ls.RefreshTokens)
	if numTokens <= 0 {
		return ""
	}
	return ls.RefreshTokens[numTokens-1]
}

// LogInfo gives the information appropriate to be logged for the session
func (ls LoginSession) LogInfo() string {
	identifier := utils.GetLogValue(ls.Identifier, 3)
	accessToken := utils.GetLogValue(ls.AccessToken, 10)

	refreshTokens := make([]string, len(ls.RefreshTokens))
	for i, rt := range ls.RefreshTokens {
		refreshTokens[i] = utils.GetLogValue(rt, 10)
	}

	state := utils.GetLogValue(ls.State, 5)

	return fmt.Sprintf("[id:%s, anonymous:%t, identifier:%s, at:%s, rts:%s, state:%s, "+
		"state expires:%s,mfa attempts:%d, date refreshed:%s, date updated:%s, date created:%s]",
		ls.ID, ls.Anonymous, identifier, accessToken, refreshTokens, state,
		ls.StateExpires, ls.MfaAttempts, ls.DateRefreshed, ls.DateUpdated, ls.DateCreated)
}

// APIKey represents an API key entity
type APIKey struct {
	ID    string `json:"id" bson:"_id"`
	AppID string `json:"app_id" bson:"app_id" validate:"required"`
	Key   string `json:"key" bson:"key"`
}

// AuthType represents authentication type entity
//
//	The system supports different authentication types - username, email, phone, identity providers ones etc
type AuthType struct {
	ID             string                 `bson:"_id"`
	Code           string                 `bson:"code"` //username or email or phone or illinois_oidc etc
	Description    string                 `bson:"description"`
	IsExternal     bool                   `bson:"is_external"`     //says if the users source is external - identity providers
	IsAnonymous    bool                   `bson:"is_anonymous"`    //says if the auth type results in anonymous users
	UseCredentials bool                   `bson:"use_credentials"` //says if the auth type uses credentials
	IgnoreMFA      bool                   `bson:"ignore_mfa"`      //says if login using this auth type may bypass account MFA
	Params         map[string]interface{} `bson:"params"`
}

// IdentityProvider represents identity provider entity
//
//	The system can integrate different identity providers - facebook, google, illinois etc
type IdentityProvider struct {
	ID   string `bson:"_id"`
	Name string `bson:"name"`
	Type string `bson:"type"`

	Configs []IdentityProviderConfig `bson:"configs"`
}

// IdentityProviderConfig represents identity provider config for an application type
type IdentityProviderConfig struct {
	AppTypeID string                 `bson:"app_type_id"`
	Config    map[string]interface{} `bson:"config"`
}

// UserAuth represents user auth entity
type UserAuth struct {
	UserID         string
	AccountID      string
	OrgID          string
	Sub            string
	FirstName      string
	LastName       string
	Email          string
	Phone          string
	Picture        []byte
	Exp            *int64
	Creds          *AuthCreds
	RefreshParams  map[string]interface{}
	OrgData        map[string]interface{}
	ResponseParams interface{}
	Anonymous      bool
}

// AuthCreds represents represents a set of credentials used by auth
type AuthCreds struct {
	ID        string                 `bson:"_id"`
	OrgID     string                 `bson:"org_id"`
	AppID     string                 `bson:"app_id"`
	AuthType  string                 `bson:"auth_type"`
	AccountID string                 `bson:"account_id"`
	Creds     map[string]interface{} `bson:"creds"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

// AuthRefresh represents refresh token info used by auth
// TODO remove
type AuthRefresh struct {
	PreviousToken string                 `bson:"previous_token"`
	CurrentToken  string                 `bson:"current_token" validate:"required"`
	Expires       *time.Time             `bson:"exp" validate:"required"`
	AppID         string                 `bson:"app_id" validate:"required"`
	OrgID         string                 `bson:"org_id" validate:"required"`
	CredsID       string                 `bson:"creds_id" validate:"required"`
	Params        map[string]interface{} `bson:"params"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

// ServiceRegistration represents a service registration entity
type ServiceRegistration struct {
	Registration auth.ServiceReg `json:"registration" bson:"registration"`
	CoreHost     string          `json:"core_host" bson:"core_host"`
	Name         string          `json:"name" bson:"name"`
	Description  string          `json:"description" bson:"description"`
	InfoURL      string          `json:"info_url" bson:"info_url"`
	LogoURL      string          `json:"logo_url" bson:"logo_url"`
	Scopes       []ServiceScope  `json:"scopes" bson:"scopes"`
	AuthEndpoint string          `json:"auth_endpoint" bson:"auth_endpoint"`
	FirstParty   bool            `json:"first_party" bson:"first_party"`
}

// ServiceScope represents a scope entity
type ServiceScope struct {
	Scope       *authorization.Scope `json:"scope" bson:"scope"`
	Required    bool                 `json:"required" bson:"required"`
	Explanation string               `json:"explanation,omitempty" bson:"explanation,omitempty"`
}

// ServiceAccount represents a service account entity
type ServiceAccount struct {
	AccountID string
	Name      string

	Application  *Application
	Organization *Organization

	Permissions []Permission
	Scopes      []authorization.Scope
	FirstParty  bool

	Credentials []ServiceAccountCredential

	DateCreated time.Time
	DateUpdated *time.Time
}

// GetPermissionNames returns all names of permissions granted to this account
func (s ServiceAccount) GetPermissionNames() []string {
	permissions := make([]string, len(s.Permissions))
	for i, permission := range s.Permissions {
		permissions[i] = permission.Name
	}
	return permissions
}

// GetScopeStrings returns all names of scopes granted to this account
func (s ServiceAccount) GetScopeStrings() []string {
	scopes := make([]string, len(s.Scopes))
	for i, scope := range s.Scopes {
		scopes[i] = scope.String()
	}
	return scopes
}

// AppOrgPair represents an appID, orgID pair entity
type AppOrgPair struct {
	AppID string
	OrgID string
}

// ServiceAccountCredential represents a service account credential entity
type ServiceAccountCredential struct {
	ID   string `bson:"id"`
	Name string `bson:"name"`
	Type string `bson:"type"`

	Params  map[string]interface{} `bson:"params,omitempty"`
	Secrets map[string]interface{} `bson:"secrets,omitempty"`

	DateCreated time.Time `bson:"date_created"`
}

// ServiceAccountTokenRequest represents a service account token request entity
type ServiceAccountTokenRequest struct {
	AccountID string  `json:"account_id"`
	AppID     *string `json:"app_id"`
	OrgID     *string `json:"org_id"`
	AuthType  string  `json:"auth_type"`

	Creds *interface{} `json:"creds,omitempty"`
}

// ServiceAuthorization represents service authorization entity
type ServiceAuthorization struct {
	UserID    string                `json:"user_id" bson:"user_id"`
	ServiceID string                `json:"service_id" bson:"service_id"`
	Scopes    []authorization.Scope `json:"scopes" bson:"scopes"`
}
