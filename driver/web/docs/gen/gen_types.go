// Package Def provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen version v1.8.1 DO NOT EDIT.
package Def

import (
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"
)

const (
	BearerAuthScopes = "bearerAuth.Scopes"
)

// Defines values for DeviceFieldsType.
const (
	DeviceFieldsTypeDesktop DeviceFieldsType = "desktop"

	DeviceFieldsTypeMobile DeviceFieldsType = "mobile"

	DeviceFieldsTypeOther DeviceFieldsType = "other"

	DeviceFieldsTypeWeb DeviceFieldsType = "web"
)

// Defines values for JWKAlg.
const (
	JWKAlgRS256 JWKAlg = "RS256"
)

// Defines values for JWKKty.
const (
	JWKKtyRSA JWKKty = "RSA"
)

// Defines values for JWKUse.
const (
	JWKUseSig JWKUse = "sig"
)

// Defines values for OrganizationFieldsType.
const (
	OrganizationFieldsTypeHuge OrganizationFieldsType = "huge"

	OrganizationFieldsTypeLarge OrganizationFieldsType = "large"

	OrganizationFieldsTypeMedium OrganizationFieldsType = "medium"

	OrganizationFieldsTypeMicro OrganizationFieldsType = "micro"

	OrganizationFieldsTypeSmall OrganizationFieldsType = "small"
)

// Defines values for ReqAccountExistsRequestAuthType.
const (
	ReqAccountExistsRequestAuthTypeAnonymous ReqAccountExistsRequestAuthType = "anonymous"

	ReqAccountExistsRequestAuthTypeEmail ReqAccountExistsRequestAuthType = "email"

	ReqAccountExistsRequestAuthTypeIllinoisOidc ReqAccountExistsRequestAuthType = "illinois_oidc"

	ReqAccountExistsRequestAuthTypeTwilioPhone ReqAccountExistsRequestAuthType = "twilio_phone"

	ReqAccountExistsRequestAuthTypeUsername ReqAccountExistsRequestAuthType = "username"
)

// Defines values for ReqCreateOrganizationRequestType.
const (
	ReqCreateOrganizationRequestTypeHuge ReqCreateOrganizationRequestType = "huge"

	ReqCreateOrganizationRequestTypeLarge ReqCreateOrganizationRequestType = "large"

	ReqCreateOrganizationRequestTypeMedium ReqCreateOrganizationRequestType = "medium"

	ReqCreateOrganizationRequestTypeMicro ReqCreateOrganizationRequestType = "micro"

	ReqCreateOrganizationRequestTypeSmall ReqCreateOrganizationRequestType = "small"
)

// Defines values for ReqSharedLoginAuthType.
const (
	ReqSharedLoginAuthTypeAnonymous ReqSharedLoginAuthType = "anonymous"

	ReqSharedLoginAuthTypeEmail ReqSharedLoginAuthType = "email"

	ReqSharedLoginAuthTypeIllinoisOidc ReqSharedLoginAuthType = "illinois_oidc"

	ReqSharedLoginAuthTypeTwilioPhone ReqSharedLoginAuthType = "twilio_phone"

	ReqSharedLoginAuthTypeUsername ReqSharedLoginAuthType = "username"
)

// Defines values for ReqSharedLoginUrlAuthType.
const (
	ReqSharedLoginUrlAuthTypeIllinoisOidc ReqSharedLoginUrlAuthType = "illinois_oidc"
)

// Defines values for ReqSharedLoginDeviceType.
const (
	ReqSharedLoginDeviceTypeDesktop ReqSharedLoginDeviceType = "desktop"

	ReqSharedLoginDeviceTypeMobile ReqSharedLoginDeviceType = "mobile"

	ReqSharedLoginDeviceTypeOther ReqSharedLoginDeviceType = "other"

	ReqSharedLoginDeviceTypeWeb ReqSharedLoginDeviceType = "web"
)

// Defines values for ReqUpdateOrganizationRequestType.
const (
	ReqUpdateOrganizationRequestTypeHuge ReqUpdateOrganizationRequestType = "huge"

	ReqUpdateOrganizationRequestTypeLarge ReqUpdateOrganizationRequestType = "large"

	ReqUpdateOrganizationRequestTypeMedium ReqUpdateOrganizationRequestType = "medium"

	ReqUpdateOrganizationRequestTypeMicro ReqUpdateOrganizationRequestType = "micro"

	ReqUpdateOrganizationRequestTypeSmall ReqUpdateOrganizationRequestType = "small"
)

// Defines values for ResAuthorizeServiceResponseTokenType.
const (
	ResAuthorizeServiceResponseTokenTypeBearer ResAuthorizeServiceResponseTokenType = "Bearer"
)

// Defines values for ResGetOrganizationsResponseType.
const (
	ResGetOrganizationsResponseTypeHuge ResGetOrganizationsResponseType = "huge"

	ResGetOrganizationsResponseTypeLarge ResGetOrganizationsResponseType = "large"

	ResGetOrganizationsResponseTypeMedium ResGetOrganizationsResponseType = "medium"

	ResGetOrganizationsResponseTypeMicro ResGetOrganizationsResponseType = "micro"

	ResGetOrganizationsResponseTypeSmall ResGetOrganizationsResponseType = "small"
)

// Defines values for ResSharedRokwireTokenTokenType.
const (
	ResSharedRokwireTokenTokenTypeBearer ResSharedRokwireTokenTokenType = "Bearer"
)

// API key record
type APIKey struct {
	AppId string  `json:"app_id"`
	Id    *string `json:"id,omitempty"`
	Key   string  `json:"key"`
}

// Account defines model for Account.
type Account struct {
	Application  *Application            `json:"application,omitempty"`
	AuthTypes    *[]AccountAuthType      `json:"auth_types,omitempty"`
	Devices      *[]Device               `json:"devices,omitempty"`
	Fields       *AccountFields          `json:"fields,omitempty"`
	Groups       *[]AppOrgGroup          `json:"groups,omitempty"`
	Organization *Organization           `json:"organization,omitempty"`
	Permissions  *[]Permission           `json:"permissions,omitempty"`
	Preferences  *map[string]interface{} `json:"preferences,omitempty"`
	Profile      *Profile                `json:"profile,omitempty"`
	Roles        *[]AppOrgRole           `json:"roles,omitempty"`
}

// AccountAuthType defines model for AccountAuthType.
type AccountAuthType struct {
	Account    *Account               `json:"account,omitempty"`
	AuthType   *AuthType              `json:"auth_type,omitempty"`
	Credential *Credential            `json:"credential,omitempty"`
	Fields     *AccountAuthTypeFields `json:"fields,omitempty"`
}

// AccountAuthTypeFields defines model for AccountAuthTypeFields.
type AccountAuthTypeFields struct {
	Active     *bool                         `json:"active,omitempty"`
	Active2fa  *bool                         `json:"active_2fa,omitempty"`
	Code       *string                       `json:"code,omitempty"`
	Id         *string                       `json:"id,omitempty"`
	Identifier *string                       `json:"identifier,omitempty"`
	Params     *AccountAuthTypeFields_Params `json:"params"`
}

// AccountAuthTypeFields_Params defines model for AccountAuthTypeFields.Params.
type AccountAuthTypeFields_Params struct {
	AdditionalProperties map[string]interface{} `json:"-"`
}

// AccountFields defines model for AccountFields.
type AccountFields struct {
	Id string `json:"id"`
}

// AppOrgGroup defines model for AppOrgGroup.
type AppOrgGroup struct {
	Application *Application       `json:"application,omitempty"`
	Fields      *AppOrgGroupFields `json:"fields,omitempty"`
	Permissions *[]Permission      `json:"permissions,omitempty"`
	Roles       *[]AppOrgRole      `json:"roles,omitempty"`
}

// AppOrgGroupFields defines model for AppOrgGroupFields.
type AppOrgGroupFields struct {
	Id   string `json:"id"`
	Name string `json:"name"`
}

// AppOrgRole defines model for AppOrgRole.
type AppOrgRole struct {
	Application *Application      `json:"application,omitempty"`
	Fields      *AppOrgRoleFields `json:"fields,omitempty"`
	Permissions *[]Permission     `json:"permissions,omitempty"`
}

// AppOrgRoleFields defines model for AppOrgRoleFields.
type AppOrgRoleFields struct {
	Id   string `json:"id"`
	Name string `json:"name"`
}

// Application defines model for Application.
type Application struct {
	Fields        *ApplicationFields         `json:"fields,omitempty"`
	Organizations *[]ApplicationOrganization `json:"organizations,omitempty"`
	Types         *[]ApplicationType         `json:"types,omitempty"`
}

// ApplicationFields defines model for ApplicationFields.
type ApplicationFields struct {
	Id               string `json:"id"`
	MultiTenant      *bool  `json:"multi_tenant,omitempty"`
	Name             string `json:"name"`
	RequiresOwnUsers *bool  `json:"requires_own_users,omitempty"`
}

// ApplicationOrganization defines model for ApplicationOrganization.
type ApplicationOrganization struct {
	TODO *string `json:"TODO,omitempty"`
	Id   *string `json:"id,omitempty"`
}

// ApplicationType defines model for ApplicationType.
type ApplicationType struct {
	Application *Application           `json:"application,omitempty"`
	Fields      *ApplicationTypeFields `json:"fields,omitempty"`
}

// ApplicationTypeFields defines model for ApplicationTypeFields.
type ApplicationTypeFields struct {
	Id         string    `json:"id"`
	Identifier string    `json:"identifier"`
	Name       *string   `json:"name,omitempty"`
	Versions   *[]string `json:"versions,omitempty"`
}

// Service registration record used for auth
type AuthServiceReg struct {
	Host      string  `json:"host"`
	PubKey    *PubKey `json:"pub_key,omitempty"`
	ServiceId string  `json:"service_id"`
}

// AuthType defines model for AuthType.
type AuthType struct {
	Fields *AuthTypeFields `json:"fields,omitempty"`
}

// AuthTypeFields defines model for AuthTypeFields.
type AuthTypeFields struct {
	Code        *string                `json:"code,omitempty"`
	Description *string                `json:"description,omitempty"`
	Id          *string                `json:"id,omitempty"`
	IsExternal  *bool                  `json:"is_external,omitempty"`
	Params      *AuthTypeFields_Params `json:"params,omitempty"`
}

// AuthTypeFields_Params defines model for AuthTypeFields.Params.
type AuthTypeFields_Params struct {
	AdditionalProperties map[string]interface{} `json:"-"`
}

// Credential defines model for Credential.
type Credential struct {
	AccountsAuthTypes *[]AccountAuthType `json:"accounts_auth_types,omitempty"`
	Fields            *CredentialFields  `json:"fields,omitempty"`
}

// CredentialFields defines model for CredentialFields.
type CredentialFields struct {
	Id    *string                 `json:"id,omitempty"`
	Value *map[string]interface{} `json:"value,omitempty"`
}

// Device defines model for Device.
type Device struct {
	Accounts *[]Account    `json:"accounts,omitempty"`
	Fields   *DeviceFields `json:"fields,omitempty"`
}

// DeviceFields defines model for DeviceFields.
type DeviceFields struct {
	Id   string           `json:"id"`
	Os   *string          `json:"os,omitempty"`
	Type DeviceFieldsType `json:"type"`
}

// DeviceFieldsType defines model for DeviceFields.Type.
type DeviceFieldsType string

// GlobalConfig defines model for GlobalConfig.
type GlobalConfig struct {
	Setting string `json:"setting"`
}

// JSON Web Key (JWK)
type JWK struct {

	// The "alg" (algorithm) parameter identifies the algorithm intended for use with the key
	Alg JWKAlg `json:"alg"`

	// The exponent of the key - Base64URL encoded
	E string `json:"e"`

	// The "kid" (key ID) parameter is used to match a specific key
	Kid string `json:"kid"`

	// The "kty" (key type) parameter identifies the cryptographic algorithm family used with the key
	Kty JWKKty `json:"kty"`

	// The modulus (2048 bit) of the key - Base64URL encoded.
	N string `json:"n"`

	// The "use" (public key use) parameter identifies the intended use of the public key
	Use JWKUse `json:"use"`
}

// The "alg" (algorithm) parameter identifies the algorithm intended for use with the key
type JWKAlg string

// The "kty" (key type) parameter identifies the cryptographic algorithm family used with the key
type JWKKty string

// The "use" (public key use) parameter identifies the intended use of the public key
type JWKUse string

// JSON Web Key Set (JWKS)
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// OpenID Connect Discovery Metadata
type OIDCDiscovery struct {
	Issuer  string `json:"issuer"`
	JwksUri string `json:"jwks_uri"`
}

// Organization defines model for Organization.
type Organization struct {
	Config *OrganizationConfig `json:"config,omitempty"`
	Fields *OrganizationFields `json:"fields,omitempty"`
}

// OrganizationConfig defines model for OrganizationConfig.
type OrganizationConfig struct {
	Fields *OrganizationConfigFields `json:"fields,omitempty"`
}

// OrganizationConfigFields defines model for OrganizationConfigFields.
type OrganizationConfigFields struct {

	// organization domains
	Domains *[]string `json:"domains,omitempty"`

	// organization config id
	Id *string `json:"id,omitempty"`
}

// OrganizationFields defines model for OrganizationFields.
type OrganizationFields struct {
	Id   string                 `json:"id"`
	Name string                 `json:"name"`
	Type OrganizationFieldsType `json:"type"`
}

// OrganizationFieldsType defines model for OrganizationFields.Type.
type OrganizationFieldsType string

// Permission defines model for Permission.
type Permission struct {
	Fields *PermissionFields `json:"fields,omitempty"`
}

// PermissionFields defines model for PermissionFields.
type PermissionFields struct {
	Assigners *[]string `json:"assigners,omitempty"`
	Id        string    `json:"id"`
	Name      string    `json:"name"`
	ServiceId *string   `json:"service_id,omitempty"`
}

// Profile defines model for Profile.
type Profile struct {
	Accounts *[]Account     `json:"accounts,omitempty"`
	Fields   *ProfileFields `json:"fields,omitempty"`
}

// ProfileFields defines model for ProfileFields.
type ProfileFields struct {
	Address   *string `json:"address"`
	BirthYear *int    `json:"birth_year"`
	Country   *string `json:"country"`
	Email     *string `json:"email"`
	FirstName *string `json:"first_name,omitempty"`
	Id        *string `json:"id,omitempty"`
	LastName  *string `json:"last_name,omitempty"`
	Phone     *string `json:"phone"`
	PhotoUrl  *string `json:"photo_url,omitempty"`
	State     *string `json:"state"`
	ZipCode   *string `json:"zip_code"`
}

// PubKey defines model for PubKey.
type PubKey struct {
	Alg    string `json:"alg"`
	KeyPem string `json:"key_pem"`
}

// Full service registration record
type ServiceReg struct {
	Description string          `json:"description"`
	FirstParty  bool            `json:"first_party"`
	Host        string          `json:"host"`
	InfoUrl     *string         `json:"info_url,omitempty"`
	LogoUrl     *string         `json:"logo_url,omitempty"`
	Name        string          `json:"name"`
	PubKey      *PubKey         `json:"pub_key,omitempty"`
	Scopes      *[]ServiceScope `json:"scopes"`
	ServiceId   string          `json:"service_id"`
}

// ServiceScope defines model for ServiceScope.
type ServiceScope struct {

	// Explanation displayed to users for why this scope is requested/required
	Explanation *string `json:"explanation,omitempty"`
	Required    bool    `json:"required"`
	Scope       string  `json:"scope"`
}

// ReqAccountExistsRequest defines model for _req_account-exists_Request.
type ReqAccountExistsRequest struct {
	ApiKey            string                          `json:"api_key"`
	AppTypeIdentifier string                          `json:"app_type_identifier"`
	AuthType          ReqAccountExistsRequestAuthType `json:"auth_type"`
	OrgId             string                          `json:"org_id"`
	UserIdentifier    string                          `json:"user_identifier"`
}

// ReqAccountExistsRequestAuthType defines model for ReqAccountExistsRequest.AuthType.
type ReqAccountExistsRequestAuthType string

// ReqAccountPermissionsRequest defines model for _req_account-permissions_Request.
type ReqAccountPermissionsRequest struct {
	AccountId   string   `json:"account_id"`
	AppId       string   `json:"app_id"`
	Permissions []string `json:"permissions"`
}

// ReqAccountRolesRequest defines model for _req_account-roles_Request.
type ReqAccountRolesRequest struct {
	AccountId string   `json:"account_id"`
	AppId     string   `json:"app_id"`
	RoleIds   []string `json:"role_ids"`
}

// ReqApplicationRolesRequest defines model for _req_application-roles_Request.
type ReqApplicationRolesRequest struct {
	AppId       string   `json:"app_id"`
	Description string   `json:"description"`
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
}

// ReqAuthorizeServiceRequest defines model for _req_authorize-service_Request.
type ReqAuthorizeServiceRequest struct {

	// Scopes to be granted to this service in this and future tokens. Replaces existing scopes if present.
	ApprovedScopes *[]string `json:"approved_scopes,omitempty"`
	ServiceId      string    `json:"service_id"`
}

// ReqCreateOrganizationRequest defines model for _req_create-Organization_Request.
type ReqCreateOrganizationRequest struct {
	Config *OrganizationConfigFields        `json:"config,omitempty"`
	Id     *string                          `json:"id,omitempty"`
	Name   string                           `json:"name"`
	Type   ReqCreateOrganizationRequestType `json:"type"`
}

// ReqCreateOrganizationRequestType defines model for ReqCreateOrganizationRequest.Type.
type ReqCreateOrganizationRequestType string

// ReqCreateApplicationRequest defines model for _req_create_Application_Request.
type ReqCreateApplicationRequest struct {
	ApplicationTypes *[]struct {
		Identifier string    `json:"identifier"`
		Name       *string   `json:"name,omitempty"`
		Versions   *[]string `json:"versions,omitempty"`
	} `json:"application_types,omitempty"`
	MultiTenant      bool   `json:"multi_tenant"`
	Name             string `json:"name"`
	RequiresOwnUsers bool   `json:"requires_own_users"`
}

// ReqGetApplicationRequest defines model for _req_get_Application_Request.
type ReqGetApplicationRequest string

// ReqGetOrganizationRequest defines model for _req_get_Organization_Request.
type ReqGetOrganizationRequest struct {
	Id string `json:"id"`
}

// ReqPermissionsRequest defines model for _req_permissions_Request.
type ReqPermissionsRequest struct {

	// permissions that could assign current permission to accounts
	Assigners *[]string `json:"assigners,omitempty"`
	Name      string    `json:"name"`
	ServiceId *string   `json:"service_id,omitempty"`
}

// ReqSharedLogin defines model for _req_shared_Login.
type ReqSharedLogin struct {
	ApiKey            string                 `json:"api_key"`
	AppTypeIdentifier string                 `json:"app_type_identifier"`
	AuthType          ReqSharedLoginAuthType `json:"auth_type"`
	Creds             *interface{}           `json:"creds,omitempty"`

	// Client device
	Device      ReqSharedLoginDevice      `json:"device"`
	OrgId       string                    `json:"org_id"`
	Params      *interface{}              `json:"params,omitempty"`
	Preferences *map[string]interface{}   `json:"preferences"`
	Profile     *ReqSharedProfileNullable `json:"profile"`
}

// ReqSharedLoginAuthType defines model for ReqSharedLogin.AuthType.
type ReqSharedLoginAuthType string

// ReqSharedLoginUrl defines model for _req_shared_LoginUrl.
type ReqSharedLoginUrl struct {
	ApiKey            string                    `json:"api_key"`
	AppTypeIdentifier string                    `json:"app_type_identifier"`
	AuthType          ReqSharedLoginUrlAuthType `json:"auth_type"`
	OrgId             string                    `json:"org_id"`
	RedirectUri       string                    `json:"redirect_uri"`
}

// ReqSharedLoginUrlAuthType defines model for ReqSharedLoginUrl.AuthType.
type ReqSharedLoginUrlAuthType string

// Auth login creds for auth_type="anonymous"
type ReqSharedLoginCredsAPIKey struct {
	AnonymousId *string `json:"anonymous_id,omitempty"`
}

// Auth login creds for auth_type="email"
type ReqSharedLoginCredsEmail struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Auth login creds for auth_type="oidc" (or variants)
//   - full redirect URI received from OIDC provider
type ReqSharedLoginCredsOIDC string

// Auth login creds for auth_type="twilio_phone"
type ReqSharedLoginCredsTwilioPhone struct {
	Code  *string `json:"code,omitempty"`
	Phone string  `json:"phone"`
}

// Client device
type ReqSharedLoginDevice struct {
	DeviceId *string                  `json:"device_id,omitempty"`
	Os       *string                  `json:"os,omitempty"`
	Type     ReqSharedLoginDeviceType `json:"type"`
}

// ReqSharedLoginDeviceType defines model for ReqSharedLoginDevice.Type.
type ReqSharedLoginDeviceType string

// Auth login params for auth_type="email"
type ReqSharedLoginParamsEmail struct {

	// This should match the `creds` password field when sign_up=true. This should be verified on the client side as well to reduce invalid requests.
	ConfirmPassword *string `json:"confirm_password,omitempty"`
	SignUp          *bool   `json:"sign_up,omitempty"`
}

// Auth login request params for unlisted auth_types (None)
type ReqSharedLoginParamsNone map[string]interface{}

// Auth login params for auth_type="oidc" (or variants)
type ReqSharedLoginParamsOIDC struct {
	PkceVerifier *string `json:"pkce_verifier,omitempty"`
	RedirectUri  *string `json:"redirect_uri,omitempty"`
}

// ReqSharedProfile defines model for _req_shared_Profile.
type ReqSharedProfile struct {
	Address   *string `json:"address"`
	BirthYear *int    `json:"birth_year"`
	Country   *string `json:"country"`
	Email     *string `json:"email"`
	FirstName *string `json:"first_name"`
	LastName  *string `json:"last_name"`
	Phone     *string `json:"phone"`
	PhotoUrl  *string `json:"photo_url"`
	State     *string `json:"state"`
	ZipCode   *string `json:"zip_code"`
}

// ReqSharedProfileNullable defines model for _req_shared_ProfileNullable.
type ReqSharedProfileNullable struct {
	Address   *string `json:"address"`
	BirthYear *int    `json:"birth_year"`
	Country   *string `json:"country"`
	Email     *string `json:"email"`
	FirstName *string `json:"first_name"`
	LastName  *string `json:"last_name"`
	Phone     *string `json:"phone"`
	PhotoUrl  *string `json:"photo_url"`
	State     *string `json:"state"`
	ZipCode   *string `json:"zip_code"`
}

// ReqSharedRefresh defines model for _req_shared_Refresh.
type ReqSharedRefresh struct {
	ApiKey       string `json:"api_key"`
	RefreshToken string `json:"refresh_token"`
}

// ReqUpdateOrganizationRequest defines model for _req_update_Organization_Request.
type ReqUpdateOrganizationRequest struct {
	Config *OrganizationConfigFields        `json:"config,omitempty"`
	Id     string                           `json:"id"`
	Name   string                           `json:"name"`
	Type   ReqUpdateOrganizationRequestType `json:"type"`
}

// ReqUpdateOrganizationRequestType defines model for ReqUpdateOrganizationRequest.Type.
type ReqUpdateOrganizationRequestType string

// ResAccountExistsResponse defines model for _res_account-exists_Response.
type ResAccountExistsResponse bool

// ResAuthorizeServiceResponse defines model for _res_authorize-service_Response.
type ResAuthorizeServiceResponse struct {
	AccessToken    *string   `json:"access_token,omitempty"`
	ApprovedScopes *[]string `json:"approved_scopes,omitempty"`

	// Full service registration record
	ServiceReg *ServiceReg `json:"service_reg,omitempty"`

	// The type of the provided tokens to be specified when they are sent in the "Authorization" header
	TokenType *ResAuthorizeServiceResponseTokenType `json:"token_type,omitempty"`
}

// The type of the provided tokens to be specified when they are sent in the "Authorization" header
type ResAuthorizeServiceResponseTokenType string

// ResGetApplicationsResponse defines model for _res_get_Applications_Response.
type ResGetApplicationsResponse struct {
	ApplicationTypes *ApplicationTypeFields `json:"application_types,omitempty"`
	Id               string                 `json:"id"`
	MultiTenant      bool                   `json:"multi_tenant"`
	Name             string                 `json:"name"`
	RequiresOwnUsers bool                   `json:"requires_own_users"`
}

// ResGetOrganizationsResponse defines model for _res_get_Organizations_Response.
type ResGetOrganizationsResponse struct {
	Config *[]OrganizationConfigFields     `json:"config,omitempty"`
	Id     string                          `json:"id"`
	Name   string                          `json:"name"`
	Type   ResGetOrganizationsResponseType `json:"type"`
}

// ResGetOrganizationsResponseType defines model for ResGetOrganizationsResponse.Type.
type ResGetOrganizationsResponseType string

// ResSharedLogin defines model for _res_shared_Login.
type ResSharedLogin struct {
	Account *ResSharedLoginAccount `json:"account,omitempty"`
	Message *string                `json:"message,omitempty"`
	Params  *interface{}           `json:"params"`
	Token   *ResSharedRokwireToken `json:"token,omitempty"`
}

// ResSharedLoginUrl defines model for _res_shared_LoginUrl.
type ResSharedLoginUrl struct {
	LoginUrl string `json:"login_url"`

	// Params to be submitted with 'login' request (if necessary)
	Params *map[string]interface{} `json:"params,omitempty"`
}

// ResSharedLoginAccount defines model for _res_shared_Login_Account.
type ResSharedLoginAccount struct {
	AuthTypes   *[]AccountAuthTypeFields `json:"auth_types,omitempty"`
	Groups      *[]AppOrgGroupFields     `json:"groups,omitempty"`
	Id          string                   `json:"id"`
	Permissions *[]PermissionFields      `json:"permissions,omitempty"`
	Preferences *map[string]interface{}  `json:"preferences"`
	Profile     *ProfileFields           `json:"profile,omitempty"`
	Roles       *[]AppOrgRoleFields      `json:"roles,omitempty"`
}

// ResSharedRefresh defines model for _res_shared_Refresh.
type ResSharedRefresh struct {
	Params *interface{}           `json:"params"`
	Token  *ResSharedRokwireToken `json:"token,omitempty"`
}

// ResSharedRokwireToken defines model for _res_shared_RokwireToken.
type ResSharedRokwireToken struct {

	// The user's access token to be provided to authorize access to ROKWIRE APIs
	AccessToken *string `json:"access_token,omitempty"`

	// A refresh token that can be used to get a new access token once the one provided expires
	RefreshToken *string `json:"refresh_token,omitempty"`

	// The type of the provided tokens to be specified when they are sent in the "Authorization" header
	TokenType *ResSharedRokwireTokenTokenType `json:"token_type,omitempty"`
}

// The type of the provided tokens to be specified when they are sent in the "Authorization" header
type ResSharedRokwireTokenTokenType string

// PostAdminAuthLoginJSONBody defines parameters for PostAdminAuthLogin.
type PostAdminAuthLoginJSONBody ReqSharedLogin

// PostAdminAuthLoginUrlJSONBody defines parameters for PostAdminAuthLoginUrl.
type PostAdminAuthLoginUrlJSONBody ReqSharedLoginUrl

// PostAdminAuthRefreshJSONBody defines parameters for PostAdminAuthRefresh.
type PostAdminAuthRefreshJSONBody ReqSharedRefresh

// GetBbsServiceRegsParams defines parameters for GetBbsServiceRegs.
type GetBbsServiceRegsParams struct {

	// A comma-separated list of service IDs to return registrations for
	Ids string `json:"ids"`
}

// PutServicesAccountPreferencesJSONBody defines parameters for PutServicesAccountPreferences.
type PutServicesAccountPreferencesJSONBody map[string]interface{}

// PutServicesAccountProfileJSONBody defines parameters for PutServicesAccountProfile.
type PutServicesAccountProfileJSONBody ReqSharedProfile

// PostServicesAuthAccountExistsJSONBody defines parameters for PostServicesAuthAccountExists.
type PostServicesAuthAccountExistsJSONBody ReqAccountExistsRequest

// PostServicesAuthAuthorizeServiceJSONBody defines parameters for PostServicesAuthAuthorizeService.
type PostServicesAuthAuthorizeServiceJSONBody ReqAuthorizeServiceRequest

// PostServicesAuthLoginJSONBody defines parameters for PostServicesAuthLogin.
type PostServicesAuthLoginJSONBody ReqSharedLogin

// PostServicesAuthLoginUrlJSONBody defines parameters for PostServicesAuthLoginUrl.
type PostServicesAuthLoginUrlJSONBody ReqSharedLoginUrl

// PostServicesAuthRefreshJSONBody defines parameters for PostServicesAuthRefresh.
type PostServicesAuthRefreshJSONBody ReqSharedRefresh

// GetServicesAuthServiceRegsParams defines parameters for GetServicesAuthServiceRegs.
type GetServicesAuthServiceRegsParams struct {

	// A comma-separated list of service IDs to return registrations for
	Ids string `json:"ids"`
}

// GetServicesAuthVerifyParams defines parameters for GetServicesAuthVerify.
type GetServicesAuthVerifyParams struct {

	// Credential ID
	Id string `json:"id"`

	// Verification code
	Code string `json:"code"`
}

// PutSystemAccountPermissionsJSONBody defines parameters for PutSystemAccountPermissions.
type PutSystemAccountPermissionsJSONBody ReqAccountPermissionsRequest

// PutSystemAccountRolesJSONBody defines parameters for PutSystemAccountRoles.
type PutSystemAccountRolesJSONBody ReqAccountRolesRequest

// DeleteSystemApiKeysParams defines parameters for DeleteSystemApiKeys.
type DeleteSystemApiKeysParams struct {

	// The ID of the API key to delete
	Id string `json:"id"`
}

// GetSystemApiKeysParams defines parameters for GetSystemApiKeys.
type GetSystemApiKeysParams struct {

	// The ID of the API key to return
	Id string `json:"id"`
}

// PostSystemApiKeysJSONBody defines parameters for PostSystemApiKeys.
type PostSystemApiKeysJSONBody APIKey

// PutSystemApiKeysJSONBody defines parameters for PutSystemApiKeys.
type PutSystemApiKeysJSONBody APIKey

// GetSystemApplicationApiKeysParams defines parameters for GetSystemApplicationApiKeys.
type GetSystemApplicationApiKeysParams struct {

	// The app ID of the API keys to return
	AppId string `json:"app_id"`
}

// PostSystemApplicationRolesJSONBody defines parameters for PostSystemApplicationRoles.
type PostSystemApplicationRolesJSONBody ReqApplicationRolesRequest

// PostSystemApplicationsJSONBody defines parameters for PostSystemApplications.
type PostSystemApplicationsJSONBody ReqCreateApplicationRequest

// PostSystemGlobalConfigJSONBody defines parameters for PostSystemGlobalConfig.
type PostSystemGlobalConfigJSONBody GlobalConfig

// PutSystemGlobalConfigJSONBody defines parameters for PutSystemGlobalConfig.
type PutSystemGlobalConfigJSONBody GlobalConfig

// PostSystemOrganizationsJSONBody defines parameters for PostSystemOrganizations.
type PostSystemOrganizationsJSONBody ReqCreateOrganizationRequest

// PutSystemOrganizationsIdJSONBody defines parameters for PutSystemOrganizationsId.
type PutSystemOrganizationsIdJSONBody ReqUpdateOrganizationRequest

// PostSystemPermissionsJSONBody defines parameters for PostSystemPermissions.
type PostSystemPermissionsJSONBody ReqPermissionsRequest

// PutSystemPermissionsJSONBody defines parameters for PutSystemPermissions.
type PutSystemPermissionsJSONBody ReqPermissionsRequest

// DeleteSystemServiceRegsParams defines parameters for DeleteSystemServiceRegs.
type DeleteSystemServiceRegsParams struct {

	// The service ID of the registration to delete
	Id string `json:"id"`
}

// GetSystemServiceRegsParams defines parameters for GetSystemServiceRegs.
type GetSystemServiceRegsParams struct {

	// A comma-separated list of service IDs to return registrations for
	Ids string `json:"ids"`
}

// PostSystemServiceRegsJSONBody defines parameters for PostSystemServiceRegs.
type PostSystemServiceRegsJSONBody ServiceReg

// PutSystemServiceRegsJSONBody defines parameters for PutSystemServiceRegs.
type PutSystemServiceRegsJSONBody ServiceReg

// GetTpsServiceRegsParams defines parameters for GetTpsServiceRegs.
type GetTpsServiceRegsParams struct {

	// A comma-separated list of service IDs to return registrations for
	Ids string `json:"ids"`
}

// PostAdminAuthLoginJSONRequestBody defines body for PostAdminAuthLogin for application/json ContentType.
type PostAdminAuthLoginJSONRequestBody PostAdminAuthLoginJSONBody

// PostAdminAuthLoginUrlJSONRequestBody defines body for PostAdminAuthLoginUrl for application/json ContentType.
type PostAdminAuthLoginUrlJSONRequestBody PostAdminAuthLoginUrlJSONBody

// PostAdminAuthRefreshJSONRequestBody defines body for PostAdminAuthRefresh for application/json ContentType.
type PostAdminAuthRefreshJSONRequestBody PostAdminAuthRefreshJSONBody

// PutServicesAccountPreferencesJSONRequestBody defines body for PutServicesAccountPreferences for application/json ContentType.
type PutServicesAccountPreferencesJSONRequestBody PutServicesAccountPreferencesJSONBody

// PutServicesAccountProfileJSONRequestBody defines body for PutServicesAccountProfile for application/json ContentType.
type PutServicesAccountProfileJSONRequestBody PutServicesAccountProfileJSONBody

// PostServicesAuthAccountExistsJSONRequestBody defines body for PostServicesAuthAccountExists for application/json ContentType.
type PostServicesAuthAccountExistsJSONRequestBody PostServicesAuthAccountExistsJSONBody

// PostServicesAuthAuthorizeServiceJSONRequestBody defines body for PostServicesAuthAuthorizeService for application/json ContentType.
type PostServicesAuthAuthorizeServiceJSONRequestBody PostServicesAuthAuthorizeServiceJSONBody

// PostServicesAuthLoginJSONRequestBody defines body for PostServicesAuthLogin for application/json ContentType.
type PostServicesAuthLoginJSONRequestBody PostServicesAuthLoginJSONBody

// PostServicesAuthLoginUrlJSONRequestBody defines body for PostServicesAuthLoginUrl for application/json ContentType.
type PostServicesAuthLoginUrlJSONRequestBody PostServicesAuthLoginUrlJSONBody

// PostServicesAuthRefreshJSONRequestBody defines body for PostServicesAuthRefresh for application/json ContentType.
type PostServicesAuthRefreshJSONRequestBody PostServicesAuthRefreshJSONBody

// PutSystemAccountPermissionsJSONRequestBody defines body for PutSystemAccountPermissions for application/json ContentType.
type PutSystemAccountPermissionsJSONRequestBody PutSystemAccountPermissionsJSONBody

// PutSystemAccountRolesJSONRequestBody defines body for PutSystemAccountRoles for application/json ContentType.
type PutSystemAccountRolesJSONRequestBody PutSystemAccountRolesJSONBody

// PostSystemApiKeysJSONRequestBody defines body for PostSystemApiKeys for application/json ContentType.
type PostSystemApiKeysJSONRequestBody PostSystemApiKeysJSONBody

// PutSystemApiKeysJSONRequestBody defines body for PutSystemApiKeys for application/json ContentType.
type PutSystemApiKeysJSONRequestBody PutSystemApiKeysJSONBody

// PostSystemApplicationRolesJSONRequestBody defines body for PostSystemApplicationRoles for application/json ContentType.
type PostSystemApplicationRolesJSONRequestBody PostSystemApplicationRolesJSONBody

// PostSystemApplicationsJSONRequestBody defines body for PostSystemApplications for application/json ContentType.
type PostSystemApplicationsJSONRequestBody PostSystemApplicationsJSONBody

// PostSystemGlobalConfigJSONRequestBody defines body for PostSystemGlobalConfig for application/json ContentType.
type PostSystemGlobalConfigJSONRequestBody PostSystemGlobalConfigJSONBody

// PutSystemGlobalConfigJSONRequestBody defines body for PutSystemGlobalConfig for application/json ContentType.
type PutSystemGlobalConfigJSONRequestBody PutSystemGlobalConfigJSONBody

// PostSystemOrganizationsJSONRequestBody defines body for PostSystemOrganizations for application/json ContentType.
type PostSystemOrganizationsJSONRequestBody PostSystemOrganizationsJSONBody

// PutSystemOrganizationsIdJSONRequestBody defines body for PutSystemOrganizationsId for application/json ContentType.
type PutSystemOrganizationsIdJSONRequestBody PutSystemOrganizationsIdJSONBody

// PostSystemPermissionsJSONRequestBody defines body for PostSystemPermissions for application/json ContentType.
type PostSystemPermissionsJSONRequestBody PostSystemPermissionsJSONBody

// PutSystemPermissionsJSONRequestBody defines body for PutSystemPermissions for application/json ContentType.
type PutSystemPermissionsJSONRequestBody PutSystemPermissionsJSONBody

// PostSystemServiceRegsJSONRequestBody defines body for PostSystemServiceRegs for application/json ContentType.
type PostSystemServiceRegsJSONRequestBody PostSystemServiceRegsJSONBody

// PutSystemServiceRegsJSONRequestBody defines body for PutSystemServiceRegs for application/json ContentType.
type PutSystemServiceRegsJSONRequestBody PutSystemServiceRegsJSONBody

// Getter for additional properties for AccountAuthTypeFields_Params. Returns the specified
// element and whether it was found
func (a AccountAuthTypeFields_Params) Get(fieldName string) (value interface{}, found bool) {
	if a.AdditionalProperties != nil {
		value, found = a.AdditionalProperties[fieldName]
	}
	return
}

// Setter for additional properties for AccountAuthTypeFields_Params
func (a *AccountAuthTypeFields_Params) Set(fieldName string, value interface{}) {
	if a.AdditionalProperties == nil {
		a.AdditionalProperties = make(map[string]interface{})
	}
	a.AdditionalProperties[fieldName] = value
}

// Override default JSON handling for AccountAuthTypeFields_Params to handle AdditionalProperties
func (a *AccountAuthTypeFields_Params) UnmarshalJSON(b []byte) error {
	object := make(map[string]json.RawMessage)
	err := json.Unmarshal(b, &object)
	if err != nil {
		return err
	}

	if len(object) != 0 {
		a.AdditionalProperties = make(map[string]interface{})
		for fieldName, fieldBuf := range object {
			var fieldVal interface{}
			err := json.Unmarshal(fieldBuf, &fieldVal)
			if err != nil {
				return errors.Wrap(err, fmt.Sprintf("error unmarshaling field %s", fieldName))
			}
			a.AdditionalProperties[fieldName] = fieldVal
		}
	}
	return nil
}

// Override default JSON handling for AccountAuthTypeFields_Params to handle AdditionalProperties
func (a AccountAuthTypeFields_Params) MarshalJSON() ([]byte, error) {
	var err error
	object := make(map[string]json.RawMessage)

	for fieldName, field := range a.AdditionalProperties {
		object[fieldName], err = json.Marshal(field)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("error marshaling '%s'", fieldName))
		}
	}
	return json.Marshal(object)
}

// Getter for additional properties for AuthTypeFields_Params. Returns the specified
// element and whether it was found
func (a AuthTypeFields_Params) Get(fieldName string) (value interface{}, found bool) {
	if a.AdditionalProperties != nil {
		value, found = a.AdditionalProperties[fieldName]
	}
	return
}

// Setter for additional properties for AuthTypeFields_Params
func (a *AuthTypeFields_Params) Set(fieldName string, value interface{}) {
	if a.AdditionalProperties == nil {
		a.AdditionalProperties = make(map[string]interface{})
	}
	a.AdditionalProperties[fieldName] = value
}

// Override default JSON handling for AuthTypeFields_Params to handle AdditionalProperties
func (a *AuthTypeFields_Params) UnmarshalJSON(b []byte) error {
	object := make(map[string]json.RawMessage)
	err := json.Unmarshal(b, &object)
	if err != nil {
		return err
	}

	if len(object) != 0 {
		a.AdditionalProperties = make(map[string]interface{})
		for fieldName, fieldBuf := range object {
			var fieldVal interface{}
			err := json.Unmarshal(fieldBuf, &fieldVal)
			if err != nil {
				return errors.Wrap(err, fmt.Sprintf("error unmarshaling field %s", fieldName))
			}
			a.AdditionalProperties[fieldName] = fieldVal
		}
	}
	return nil
}

// Override default JSON handling for AuthTypeFields_Params to handle AdditionalProperties
func (a AuthTypeFields_Params) MarshalJSON() ([]byte, error) {
	var err error
	object := make(map[string]json.RawMessage)

	for fieldName, field := range a.AdditionalProperties {
		object[fieldName], err = json.Marshal(field)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("error marshaling '%s'", fieldName))
		}
	}
	return json.Marshal(object)
}
