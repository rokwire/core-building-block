// Package Def provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen version v1.8.1 DO NOT EDIT.
package Def

import (
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"
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

// Defines values for ReqLoginUrlRequestAuthType.
const (
	ReqLoginUrlRequestAuthTypeIllinoisOidc ReqLoginUrlRequestAuthType = "illinois_oidc"
)

// Defines values for ReqLoginRequestAuthType.
const (
	ReqLoginRequestAuthTypeEmail ReqLoginRequestAuthType = "email"

	ReqLoginRequestAuthTypeIllinoisOidc ReqLoginRequestAuthType = "illinois_oidc"

	ReqLoginRequestAuthTypePhone ReqLoginRequestAuthType = "phone"

	ReqLoginRequestAuthTypeUsername ReqLoginRequestAuthType = "username"
)

// Defines values for ResAuthorizeServiceResponseTokenType.
const (
	ResAuthorizeServiceResponseTokenTypeBearer ResAuthorizeServiceResponseTokenType = "Bearer"
)

// Defines values for ResSharedRokwireTokenTokenType.
const (
	ResSharedRokwireTokenTokenTypeBearer ResSharedRokwireTokenTokenType = "Bearer"
)

// Account defines model for Account.
type Account struct {
	Application  *Application             `json:"application,omitempty"`
	AuthTypes    *[]AccountAuthType       `json:"auth_types,omitempty"`
	Devices      *[]Device                `json:"devices,omitempty"`
	Fields       *AccountFields           `json:"fields,omitempty"`
	Groups       *[]ApplicationGroup      `json:"groups,omitempty"`
	Organization *Organization            `json:"organization,omitempty"`
	Permissions  *[]ApplicationPermission `json:"permissions,omitempty"`
	Profile      *Profile                 `json:"profile,omitempty"`
	Roles        *[]ApplicationRole       `json:"roles,omitempty"`
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

// ApplicationGroup defines model for ApplicationGroup.
type ApplicationGroup struct {
	Application *Application             `json:"application,omitempty"`
	Fields      *ApplicationGroupFields  `json:"fields,omitempty"`
	Permissions *[]ApplicationPermission `json:"permissions,omitempty"`
	Roles       *[]ApplicationRole       `json:"roles,omitempty"`
}

// ApplicationGroupFields defines model for ApplicationGroupFields.
type ApplicationGroupFields struct {
	Id   string `json:"id"`
	Name string `json:"name"`
}

// ApplicationOrganization defines model for ApplicationOrganization.
type ApplicationOrganization struct {
	TODO *string `json:"TODO,omitempty"`
	Id   *string `json:"id,omitempty"`
}

// ApplicationPermission defines model for ApplicationPermission.
type ApplicationPermission struct {
	Application *Application                 `json:"application,omitempty"`
	Fields      *ApplicationPermissionFields `json:"fields,omitempty"`
}

// ApplicationPermissionFields defines model for ApplicationPermissionFields.
type ApplicationPermissionFields struct {
	Id   string `json:"id"`
	Name string `json:"name"`
}

// ApplicationRole defines model for ApplicationRole.
type ApplicationRole struct {
	Application *Application             `json:"application,omitempty"`
	Fields      *ApplicationRoleFields   `json:"fields,omitempty"`
	Permissions *[]ApplicationPermission `json:"permissions,omitempty"`
}

// ApplicationRoleFields defines model for ApplicationRoleFields.
type ApplicationRoleFields struct {
	Id   string `json:"id"`
	Name string `json:"name"`
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
	Id         string           `json:"id"`
	MacAddress *string          `json:"mac_address,omitempty"`
	Os         *string          `json:"os,omitempty"`
	Type       DeviceFieldsType `json:"type"`
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
type OidcDiscovery struct {
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

// Profile defines model for Profile.
type Profile struct {
	Accounts *[]Account     `json:"accounts,omitempty"`
	Fields   *ProfileFields `json:"fields,omitempty"`
}

// ProfileFields defines model for ProfileFields.
type ProfileFields struct {
	FirstName *string `json:"first_name,omitempty"`
	Id        *string `json:"id,omitempty"`
	LastName  *string `json:"last_name,omitempty"`
	PhotoUrl  *string `json:"photo_url,omitempty"`
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

// ReqAuthorizeServiceRequest defines model for _req_authorize-service_Request.
type ReqAuthorizeServiceRequest struct {

	// Scopes to be granted to this service in this and future tokens. Replaces existing scopes if present.
	ApprovedScopes *[]string `json:"approved_scopes,omitempty"`
	ServiceId      string    `json:"service_id"`
}

// ReqLoginUrlRequest defines model for _req_login-url_Request.
type ReqLoginUrlRequest struct {
	AppId       string                     `json:"app_id"`
	AuthType    ReqLoginUrlRequestAuthType `json:"auth_type"`
	OrgId       string                     `json:"org_id"`
	RedirectUri string                     `json:"redirect_uri"`
}

// ReqLoginUrlRequestAuthType defines model for ReqLoginUrlRequest.AuthType.
type ReqLoginUrlRequestAuthType string

// Auth login creds for auth_type="email"
type ReqLoginCredsEmail struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Auth login creds for auth_type="oidc"
//   - full redirect URI received from OIDC provider
type ReqLoginCredsOidc string

// Auth login creds for auth_type="phone"
type ReqLoginCredsPhone struct {
	Code  *string `json:"code,omitempty"`
	Phone string  `json:"phone"`
}

// Auth login params for auth_type="email"
type ReqLoginParamsEmail struct {
	NewUser *bool `json:"new_user,omitempty"`
}

// Auth login params for auth_type="oidc"
type ReqLoginParamsOidc struct {
	PkceVerifier *string `json:"pkce_verifier,omitempty"`
	RedirectUri  *string `json:"redirect_uri,omitempty"`
}

// Auth login params for auth_type="phone" (None)
type ReqLoginParamsPhone map[string]interface{}

// ReqLoginRequest defines model for _req_login_Request.
type ReqLoginRequest struct {
	AppId    string                  `json:"app_id"`
	AuthType ReqLoginRequestAuthType `json:"auth_type"`
	Creds    *interface{}            `json:"creds,omitempty"`
	OrgId    string                  `json:"org_id"`
	Params   *interface{}            `json:"params,omitempty"`
}

// ReqLoginRequestAuthType defines model for ReqLoginRequest.AuthType.
type ReqLoginRequestAuthType string

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

// ResLoginUrlResponse defines model for _res_login-url_Response.
type ResLoginUrlResponse struct {
	LoginUrl string `json:"login_url"`

	// Params to be submitted with 'login' request (if necessary)
	Params *map[string]interface{} `json:"params,omitempty"`
}

// ResLoginAccount defines model for _res_login_Account.
type ResLoginAccount struct {
	AuthTypes   *[]AccountAuthTypeFields       `json:"auth_types,omitempty"`
	Groups      *[]ApplicationGroupFields      `json:"groups,omitempty"`
	Id          string                         `json:"id"`
	Permissions *[]ApplicationPermissionFields `json:"permissions,omitempty"`
	Profile     *ProfileFields                 `json:"profile,omitempty"`
	Roles       *[]ApplicationRoleFields       `json:"roles,omitempty"`
}

// ResLoginResponse defines model for _res_login_Response.
type ResLoginResponse struct {
	Account *ResLoginAccount       `json:"account,omitempty"`
	Params  *interface{}           `json:"params"`
	Token   *ResSharedRokwireToken `json:"token,omitempty"`
}

// ResRefreshResponse defines model for _res_refresh_Response.
type ResRefreshResponse struct {
	Params *interface{}           `json:"params,omitempty"`
	Token  *ResSharedRokwireToken `json:"token,omitempty"`
}

// ResSharedParamsOidc defines model for _res_shared_ParamsOidc.
type ResSharedParamsOidc struct {
	OidcToken *struct {
		AccessToken *string `json:"access_token,omitempty"`
		IdToken     *string `json:"id_token,omitempty"`
		TokenType   *string `json:"token_type,omitempty"`
	} `json:"oidc_token,omitempty"`
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

// PostAdminApplicationsJSONBody defines parameters for PostAdminApplications.
type PostAdminApplicationsJSONBody Application

// PostAdminGlobalConfigJSONBody defines parameters for PostAdminGlobalConfig.
type PostAdminGlobalConfigJSONBody GlobalConfig

// PutAdminGlobalConfigJSONBody defines parameters for PutAdminGlobalConfig.
type PutAdminGlobalConfigJSONBody GlobalConfig

// PostAdminOrganizationsJSONBody defines parameters for PostAdminOrganizations.
type PostAdminOrganizationsJSONBody Organization

// PutAdminOrganizationsIdJSONBody defines parameters for PutAdminOrganizationsId.
type PutAdminOrganizationsIdJSONBody Organization

// DeleteAdminServiceRegsParams defines parameters for DeleteAdminServiceRegs.
type DeleteAdminServiceRegsParams struct {

	// The service ID of the registration to delete
	Id string `json:"id"`
}

// GetAdminServiceRegsParams defines parameters for GetAdminServiceRegs.
type GetAdminServiceRegsParams struct {

	// A comma-separated list of service IDs to return registrations for
	Ids string `json:"ids"`
}

// PostAdminServiceRegsJSONBody defines parameters for PostAdminServiceRegs.
type PostAdminServiceRegsJSONBody ServiceReg

// PutAdminServiceRegsJSONBody defines parameters for PutAdminServiceRegs.
type PutAdminServiceRegsJSONBody ServiceReg

// GetBbsServiceRegsParams defines parameters for GetBbsServiceRegs.
type GetBbsServiceRegsParams struct {

	// A comma-separated list of service IDs to return registrations for
	Ids string `json:"ids"`
}

// PostServicesAuthAuthorizeServiceJSONBody defines parameters for PostServicesAuthAuthorizeService.
type PostServicesAuthAuthorizeServiceJSONBody ReqAuthorizeServiceRequest

// PostServicesAuthLoginJSONBody defines parameters for PostServicesAuthLogin.
type PostServicesAuthLoginJSONBody ReqLoginRequest

// PostServicesAuthLoginUrlJSONBody defines parameters for PostServicesAuthLoginUrl.
type PostServicesAuthLoginUrlJSONBody ReqLoginUrlRequest

// GetServicesAuthServiceRegsParams defines parameters for GetServicesAuthServiceRegs.
type GetServicesAuthServiceRegsParams struct {

	// A comma-separated list of service IDs to return registrations for
	Ids string `json:"ids"`
}

// GetTpsServiceRegsParams defines parameters for GetTpsServiceRegs.
type GetTpsServiceRegsParams struct {

	// A comma-separated list of service IDs to return registrations for
	Ids string `json:"ids"`
}

// PostAdminApplicationsJSONRequestBody defines body for PostAdminApplications for application/json ContentType.
type PostAdminApplicationsJSONRequestBody PostAdminApplicationsJSONBody

// PostAdminGlobalConfigJSONRequestBody defines body for PostAdminGlobalConfig for application/json ContentType.
type PostAdminGlobalConfigJSONRequestBody PostAdminGlobalConfigJSONBody

// PutAdminGlobalConfigJSONRequestBody defines body for PutAdminGlobalConfig for application/json ContentType.
type PutAdminGlobalConfigJSONRequestBody PutAdminGlobalConfigJSONBody

// PostAdminOrganizationsJSONRequestBody defines body for PostAdminOrganizations for application/json ContentType.
type PostAdminOrganizationsJSONRequestBody PostAdminOrganizationsJSONBody

// PutAdminOrganizationsIdJSONRequestBody defines body for PutAdminOrganizationsId for application/json ContentType.
type PutAdminOrganizationsIdJSONRequestBody PutAdminOrganizationsIdJSONBody

// PostAdminServiceRegsJSONRequestBody defines body for PostAdminServiceRegs for application/json ContentType.
type PostAdminServiceRegsJSONRequestBody PostAdminServiceRegsJSONBody

// PutAdminServiceRegsJSONRequestBody defines body for PutAdminServiceRegs for application/json ContentType.
type PutAdminServiceRegsJSONRequestBody PutAdminServiceRegsJSONBody

// PostServicesAuthAuthorizeServiceJSONRequestBody defines body for PostServicesAuthAuthorizeService for application/json ContentType.
type PostServicesAuthAuthorizeServiceJSONRequestBody PostServicesAuthAuthorizeServiceJSONBody

// PostServicesAuthLoginJSONRequestBody defines body for PostServicesAuthLogin for application/json ContentType.
type PostServicesAuthLoginJSONRequestBody PostServicesAuthLoginJSONBody

// PostServicesAuthLoginUrlJSONRequestBody defines body for PostServicesAuthLoginUrl for application/json ContentType.
type PostServicesAuthLoginUrlJSONRequestBody PostServicesAuthLoginUrlJSONBody

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
