// Package Def provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen version v1.8.1 DO NOT EDIT.
package Def

// Defines values for AuthLoginRequestAuthType.
const (
	AuthLoginRequestAuthTypeEmail AuthLoginRequestAuthType = "email"

	AuthLoginRequestAuthTypeOidc AuthLoginRequestAuthType = "oidc"

	AuthLoginRequestAuthTypePhone AuthLoginRequestAuthType = "phone"
)

// Defines values for DeviceType.
const (
	DeviceTypeDesktop DeviceType = "desktop"

	DeviceTypeMobile DeviceType = "mobile"

	DeviceTypeOther DeviceType = "other"

	DeviceTypeWeb DeviceType = "web"
)

// Defines values for OrganizationType.
const (
	OrganizationTypeHuge OrganizationType = "huge"

	OrganizationTypeLarge OrganizationType = "large"

	OrganizationTypeMedium OrganizationType = "medium"

	OrganizationTypeMicro OrganizationType = "micro"

	OrganizationTypeSmall OrganizationType = "small"
)

// Auth login creds for auth_type="email"
type AuthLoginCredsEmail struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Auth login creds for auth_type="oidc"
//   - Initial login: authorization code
//   - Refresh: refresh token
type AuthLoginCredsOidc string

// Auth login creds for auth_type="phone"
type AuthLoginCredsPhone struct {
	Code  *string `json:"code,omitempty"`
	Phone string  `json:"phone"`
}

// Auth login params for auth_type="email"
type AuthLoginParamsEmail struct {
	NewUser *bool `json:"new_user,omitempty"`
}

// Auth login params for auth_type="oidc"
type AuthLoginParamsOidc struct {
	PkceChallenge *string `json:"pkce_challenge,omitempty"`
	RedirectUri   *string `json:"redirect_uri,omitempty"`
}

// Auth login params for auth_type="phone" (None)
type AuthLoginParamsPhone map[string]interface{}

// AuthLoginRequest defines model for AuthLoginRequest.
type AuthLoginRequest struct {
	AppId    string                   `json:"app_id"`
	AuthType AuthLoginRequestAuthType `json:"auth_type"`
	Creds    *interface{}             `json:"creds,omitempty"`
	OrgId    string                   `json:"org_id"`
	Params   *interface{}             `json:"params,omitempty"`
}

// AuthLoginRequestAuthType defines model for AuthLoginRequest.AuthType.
type AuthLoginRequestAuthType string

// AuthLoginResponse defines model for AuthLoginResponse.
type AuthLoginResponse struct {
	AccessToken *string `json:"access_token,omitempty"`

	// Login params to be submitted with subsequent requests (if necessary)
	Params       *map[string]interface{} `json:"params,omitempty"`
	RefreshToken *string                 `json:"refresh_token,omitempty"`
	User         *User                   `json:"user,omitempty"`
}

// AuthRefreshResponse defines model for AuthRefreshResponse.
type AuthRefreshResponse struct {
	AccessToken  *string `json:"access_token,omitempty"`
	RefreshToken *string `json:"refresh_token,omitempty"`
}

// Device defines model for Device.
type Device struct {
	Id         string     `json:"id"`
	MacAddress *string    `json:"mac_address,omitempty"`
	Os         *string    `json:"os,omitempty"`
	Type       DeviceType `json:"type"`
	UserIds    []string   `json:"user_ids"`
}

// DeviceType defines model for Device.Type.
type DeviceType string

// GlobalConfig defines model for GlobalConfig.
type GlobalConfig struct {
	Setting string `json:"setting"`
}

// GlobalGroup defines model for GlobalGroup.
type GlobalGroup struct {
	Id          string        `json:"id"`
	Name        string        `json:"name"`
	Permissions *[]string     `json:"permissions,omitempty"`
	Roles       *[]GlobalRole `json:"roles,omitempty"`
	Users       *[]User       `json:"users,omitempty"`
}

// GlobalRole defines model for GlobalRole.
type GlobalRole struct {
	Id          string    `json:"id"`
	Name        string    `json:"name"`
	Permissions *[]string `json:"permissions,omitempty"`
}

// Organization defines model for Organization.
type Organization struct {
	Config           *OrganizationConfig `json:"config,omitempty"`
	Id               string              `json:"id"`
	LoginTypes       *[]string           `json:"login_types"`
	Name             string              `json:"name"`
	RequiresOwnLogin *bool               `json:"requires_own_login,omitempty"`
	Type             OrganizationType    `json:"type"`
}

// OrganizationType defines model for Organization.Type.
type OrganizationType string

// OrganizationConfig defines model for OrganizationConfig.
type OrganizationConfig struct {

	// organization domains
	Domains *[]string `json:"domains,omitempty"`

	// organization config id
	Id *string `json:"id,omitempty"`
}

// OrganizationGroup defines model for OrganizationGroup.
type OrganizationGroup struct {
	Id             string                    `json:"id"`
	Name           string                    `json:"name"`
	OrgId          string                    `json:"org_id"`
	OrgMemberships *[]OrganizationMembership `json:"org_memberships,omitempty"`
	Permissions    *[]string                 `json:"permissions,omitempty"`
	Roles          *[]OrganizationRole       `json:"roles,omitempty"`
}

// OrganizationMembership defines model for OrganizationMembership.
type OrganizationMembership struct {
	Groups *[]OrganizationGroup `json:"groups,omitempty"`
	Id     string               `json:"id"`
	OrgId  *string              `json:"org_id,omitempty"`

	// map[string]object for arbitrary organization user data
	OrgUserData *map[string]interface{} `json:"org_user_data,omitempty"`
	Permissions *[]string               `json:"permissions,omitempty"`
	Roles       *[]OrganizationRole     `json:"roles,omitempty"`
	UserId      *string                 `json:"user_id,omitempty"`
}

// OrganizationRole defines model for OrganizationRole.
type OrganizationRole struct {
	Id          string    `json:"id"`
	Name        string    `json:"name"`
	OrgId       string    `json:"org_id"`
	Permissions *[]string `json:"permissions,omitempty"`
}

// PubKey defines model for PubKey.
type PubKey struct {
	Alg    string `json:"alg"`
	KeyPem string `json:"key_pem"`
}

// ServiceReg defines model for ServiceReg.
type ServiceReg struct {
	Host      string  `json:"host"`
	PubKey    *PubKey `json:"pub_key,omitempty"`
	ServiceId string  `json:"service_id"`
}

// User defines model for User.
type User struct {
	Account        *UserAccount              `json:"account,omitempty"`
	Devices        *[]Device                 `json:"devices,omitempty"`
	Groups         *[]GlobalGroup            `json:"groups,omitempty"`
	Id             string                    `json:"id"`
	OrgMemberships *[]OrganizationMembership `json:"org_memberships,omitempty"`
	Permissions    *[]string                 `json:"permissions,omitempty"`
	Profile        *UserProfile              `json:"profile,omitempty"`
	Roles          *[]GlobalRole             `json:"roles,omitempty"`
}

// UserAccount defines model for UserAccount.
type UserAccount struct {
	Email    *string `json:"email,omitempty"`
	Id       string  `json:"id"`
	Phone    *string `json:"phone,omitempty"`
	Username *string `json:"username,omitempty"`
}

// UserProfile defines model for UserProfile.
type UserProfile struct {
	FirstName *string `json:"first_name,omitempty"`
	Id        string  `json:"id"`
	LastName  *string `json:"last_name,omitempty"`
	PhotoUrl  *string `json:"photo_url,omitempty"`
}

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

// PostServicesAuthLoginJSONBody defines parameters for PostServicesAuthLogin.
type PostServicesAuthLoginJSONBody AuthLoginRequest

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

// PostServicesAuthLoginJSONRequestBody defines body for PostServicesAuthLogin for application/json ContentType.
type PostServicesAuthLoginJSONRequestBody PostServicesAuthLoginJSONBody
