# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
### Added
- Support following accounts [#667](https://github.com/rokwire/core-building-block/issues/667)
- WebAuthn authentication [#659](https://github.com/rokwire/core-building-block/issues/659)
- Decouple authentication and verification mechanisms [#665](https://github.com/rokwire/core-building-block/issues/665)
- Refactor account auth types [#674](https://github.com/rokwire/core-building-block/issues/674)

## [1.34.0] - 2023-07-06
### Added
- Enable CORS [#632](https://github.com/rokwire/core-building-block/issues/632)
- Move the app config management APIs to the /admin subrouter from /system [#652](https://github.com/rokwire/core-building-block/issues/652)

## [1.33.0] - 2023-05-02
### Added
- Username and password authentication [#658](https://github.com/rokwire/core-building-block/issues/658)

## [1.32.2] - 2023-04-20
### Changed
- Sync Identity BB for user data on authentication event [#650](https://github.com/rokwire/core-building-block/issues/650)

## [1.32.1] - 2023-04-10
### Fixed
- Handle admin scopes on refresh

## [1.32.0] - 2023-04-08
### Added:
- Admin scopes [#653](https://github.com/rokwire/core-building-block/issues/653)
- Admin APIs to get count and list of accounts matching query [#649](https://github.com/rokwire/core-building-block/issues/649)
- Sync Identity BB for user data on authentication event [#650](https://github.com/rokwire/core-building-block/issues/650)

## [1.31.2] - 2023-04-04
### Fixed
- Ignore readOnly fields during validation [#641](https://github.com/rokwire/core-building-block/issues/641)

## [1.31.1] - 2023-03-14
### Changed
- Upgrade to auth library v3 [#645](https://github.com/rokwire/core-building-block/issues/645)

## [1.31.0] - 2023-03-02
### Changed
- Prepare for deployment in OpenShift [#638](https://github.com/rokwire/core-building-block/issues/638)

## [1.30.0] - 2023-02-03
### Added
- Update role admin API [#516](https://github.com/rokwire/core-building-block/issues/516)
- Add admin application config endpoints [#633](https://github.com/rokwire/core-building-block/issues/633)
### Changed
- Upgrade dependencies [#624](https://github.com/rokwire/core-building-block/issues/624)
### Fixed
- Fix system account initialization [#594](https://github.com/rokwire/core-building-block/issues/594)

## [1.29.0] - 2022-11-16
### Added
- Create API to get count of accounts matching criteria [#619](https://github.com/rokwire/core-building-block/issues/619)
### Fixed
- Panic on anonymous refresh [#621](https://github.com/rokwire/core-building-block/issues/621)

## [1.28.0] - 2022-10-24
### Added
- Add unstructured additional properties to profile [#609](https://github.com/rokwire/core-building-block/issues/609)

## [1.27.0] - 2022-10-21
### Added
- BBs/TPS API to search accounts matching criteria [#606](https://github.com/rokwire/core-building-block/issues/606)
- Add scopes to service accounts [#605](https://github.com/rokwire/core-building-block/issues/605)
- Update application system API [#549](https://github.com/rokwire/core-building-block/issues/549)
- Update group admin API [#518](https://github.com/rokwire/core-building-block/issues/518)

## [1.26.0] - 2022-10-05
### Fixed
- Services crashes on anonymous login [#603](https://github.com/rokwire/core-building-block/issues/603)

### Security
- Fix code scanning alert - Log entries created from user input [#601](https://github.com/rokwire/core-building-block/issues/601)

## [1.25.0] - 2022-10-04
### Added
- Update app/org endpoint [#543](https://github.com/rokwire/core-building-block/issues/543)
- Create app/org endpoint [#544](https://github.com/rokwire/core-building-block/issues/544)
- Expose account external IDs [#582](https://github.com/rokwire/core-building-block/issues/582)
- Anonymous accounts [#559](https://github.com/rokwire/core-building-block/issues/559)
- Usernames [#574](https://github.com/rokwire/core-building-block/issues/574)
- Add release instructions to CONVENTIONS.md [#519](https://github.com/rokwire/core-building-block/issues/519)
- Set up system app org token endpoint [#493](https://github.com/rokwire/core-building-block/issues/493)
- Track usage info in accounts [#445](https://github.com/rokwire/core-building-block/issues/445)
- Use signature Key ID to check specific key for service account auth [#481](https://github.com/rokwire/core-building-block/issues/481)
- Allow overriding docs base URLs [#513](https://github.com/rokwire/core-building-block/issues/513)
- Include account ID in request logs [#562](https://github.com/rokwire/core-building-block/issues/562)
- Add system flag to login response [#552](https://github.com/rokwire/core-building-block/issues/552)
- Add default assigners permission [#477](https://github.com/rokwire/core-building-block/issues/477)

### Fixed
- Fix has_permissions for existing accounts [#531](https://github.com/rokwire/core-building-block/issues/531)
- Service registration error handling change [#468](https://github.com/rokwire/core-building-block/issues/468)
- Update account permission duplication [#545](https://github.com/rokwire/core-building-block/issues/545)
- Deleting application roles and groups uses bad accounts query [#536](https://github.com/rokwire/core-building-block/issues/536)

### Changed
- Update oapi-codegen usage [#597](https://github.com/rokwire/core-building-block/issues/597)
- BREAKING: Permission assigners should be OR instead of AND [#482](https://github.com/rokwire/core-building-block/issues/482)]
- Update profile when external user info changes [#589](https://github.com/rokwire/core-building-block/issues/589)

## [1.24.2] - 2022-08-08
### Added
- Allow passing nil context to WithContext storage functions [#494](https://github.com/rokwire/core-building-block/issues/494)
- Account system configs [#558](https://github.com/rokwire/core-building-block/issues/558)

### Fixed
- Authorization policy comments not working [#506](https://github.com/rokwire/core-building-block/issues/506)

## [1.24.1] - 2022-07-07
### Changed
- Expose full roles/groups in accounts [#528](https://github.com/rokwire/core-building-block/issues/528)

## [1.24.0] - 2022-07-07
### Added
- Admin update account authorizations API [#484](https://github.com/rokwire/core-building-block/issues/484)
- Set up admin create account endpoint [#365](https://github.com/rokwire/core-building-block/issues/365)
- Prepare the project to become open source [#129](https://github.com/rokwire/core-building-block/issues/129)
- Retrieve all service account tokens at once [#459](https://github.com/rokwire/core-building-block/issues/459)

### Fixed
- Fix admin authorization endpoints [#515](https://github.com/rokwire/core-building-block/issues/515)
- Clean up authorization policies [#499](https://github.com/rokwire/core-building-block/issues/499)
- Prevent admins from using service account management endpoints [#500](https://github.com/rokwire/core-building-block/issues/500)

### Changed
- Get all admin level accounts [#486](https://github.com/rokwire/core-building-block/issues/486)
- Update SECURITY.md [#504](https://github.com/rokwire/core-building-block/issues/504)

## [1.23.0] - 2022-04-26
### Added
- Email/phone registration should populate email/phone in profile [#431](https://github.com/rokwire/core-building-block/issues/431)
- Implement system accounts [#278](https://github.com/rokwire/core-building-block/issues/278)
- Service accounts [#306](https://github.com/rokwire/core-building-block/issues/306)

### Security
- Update http-swagger dependency [#465](https://github.com/rokwire/core-building-block/issues/465)

## [1.22.0] - 2022-04-02
### Added
- Expose revoke roles from account Admin API [#412](https://github.com/rokwire/core-building-block/issues/412)
- Expose revoke permissions from account Admin API [#411](https://github.com/rokwire/core-building-block/issues/411)
- Expose grant permissions to role Admin API [#415](https://github.com/rokwire/core-building-block/issues/415)
- Expose remove accounts from a group Admin API [#413](https://github.com/rokwire/core-building-block/issues/413)
- Expose add accounts to a group Admin API [#384](https://github.com/rokwire/core-building-block/issues/384)
- Handle external ID management [#364](https://github.com/rokwire/core-building-block/issues/364)

### Security
- Loading all roles and groups for empty query [#458](https://github.com/rokwire/core-building-block/issues/458)

## [1.21.1] - 2022-03-17
### Fixed
- Fix verify credential HTML template loading issues [#451](https://github.com/rokwire/core-building-block/issues/451)

## [1.21.0] - 2022-03-16
### Added
- Clean up verification email messaging and UI [#444](https://github.com/rokwire/core-building-block/issues/444)
- Implement logout for users accounts [#329](https://github.com/rokwire/core-building-block/issues/329)

## [1.20.1] - 2022-03-07
### Fixed
- Unable to login in the Admin app [#430](https://github.com/rokwire/core-building-block/issues/430)

## [1.20.0] - 2022-03-01
### Fixed
- Fix broken external login [#427](https://github.com/rokwire/core-building-block/issues/427)

## [1.19.0] - 2022-02-25
### Added
- Expose System APIs for auth types [#362](https://github.com/rokwire/core-building-block/issues/362)
- Expose grant roles to account Admin API [#383](https://github.com/rokwire/core-building-block/issues/383)
- Expose grant permissions to account Admin API [#382](https://github.com/rokwire/core-building-block/issues/382)
- Expose Admin API which gives an application account devices [#359](https://github.com/rokwire/core-building-block/issues/359)
- Expose Admin API which logouts an account session for specific application [#371](https://github.com/rokwire/core-building-block/issues/371)
- Unlink account auth types [#393](https://github.com/rokwire/core-building-block/issues/393)
- Expose delete app org role admin API [#313](https://github.com/rokwire/core-building-block/issues/313)
- Expose delete app org group admin API [#312](https://github.com/rokwire/core-building-block/issues/312)
- Expose Admin API with the currently logged in accounts [#355](https://github.com/rokwire/core-building-block/issues/355)
- Add app config endpoints [#261](https://github.com/rokwire/core-building-block/issues/261)

### Security
- Fix security vulnerability for roles and groups admin APIs [#414](https://github.com/rokwire/core-building-block/issues/414)

### Fixed
- Fix issues with account linking [#408](https://github.com/rokwire/core-building-block/issues/408)
- Fix creating application group admin API [#397](https://github.com/rokwire/core-building-block/issues/397)
- Fix create role and create group Admin APIs [#386](https://github.com/rokwire/core-building-block/issues/386)
- Fix broken app config API and CHANGELOG.md [#401](https://github.com/rokwire/core-building-block/issues/401)
- Fix shared profile feature [#405](https://github.com/rokwire/core-building-block/issues/405)

### Changed
- Update the filter capability for the get login sessions Admin API [#394](https://github.com/rokwire/core-building-block/issues/394)
- Limit the returned items for get application accounts admin API [#375](https://github.com/rokwire/core-building-block/issues/375)
- Return ordered list of account auth types on link account auth type [#376](https://github.com/rokwire/core-building-block/issues/376)

## [1.18.0] - 2022-01-25
### Added
- Expose create app org group admin API [#309](https://github.com/rokwire/core-building-block/issues/309)
- Apply external auth system user data to profile [#377](https://github.com/rokwire/core-building-block/issues/377)
- Expose create app org role admin API [#308](https://github.com/rokwire/core-building-block/issues/308)
- Expose Admin API which gives all applications for an organization [#324](https://github.com/rokwire/core-building-block/issues/324)
- Expose get application organization groups admin API [#302](https://github.com/rokwire/core-building-block/issues/302)
- Expose get application organization roles admin API [#301](https://github.com/rokwire/core-building-block/issues/301)
- Admin APIs authorization fix [#372](https://github.com/rokwire/core-building-block/issues/372)
- Fixed date login session expiration [#367](https://github.com/rokwire/core-building-block/issues/367)
- Expose get permissions list admin API [#296](https://github.com/rokwire/core-building-block/issues/296)
- Expose get accounts admin API [#283](https://github.com/rokwire/core-building-block/issues/283)
- Expose get account admin API [#270](https://github.com/rokwire/core-building-block/issues/270)

### Changed
- Clean up schemas index.yaml file [#387](https://github.com/rokwire/core-building-block/issues/387)

### Fixed
- Fix yaml files paths [#352](https://github.com/rokwire/core-building-block/issues/352)

## [1.17.0] - 2021-12-06
### Fixed
- Fix delete account API [#341](https://github.com/rokwire/core-building-block/issues/341)
- Upgrade logging library for error JSON fix [#347](https://github.com/rokwire/core-building-block/issues/347)

## [1.16.0] - 2021-12-02
### Fixed
- Panic on nil conversion during OIDC refresh [#344](https://github.com/rokwire/core-building-block/issues/344)
- Account exists endpoint documentation incorrect [#342](https://github.com/rokwire/core-building-block/issues/342)
- Admin APIs issue [#326](https://github.com/rokwire/core-building-block/issues/326)

## [1.15.0] - 2021-12-01
### Fixed
- Panic on nil dereference during anonymous login [#338](https://github.com/rokwire/core-building-block/issues/338)

## [1.14.0] - 2021-11-30
### Added
- Assign device to the account on login [#245](https://github.com/rokwire/core-building-block/issues/245)
- Add multi-factor authentication support [#19](https://github.com/rokwire/core-building-block/issues/19)
- Handle multiple authentication methods linking to one account [#64](https://github.com/rokwire/core-building-block/issues/64)

### Security
- Return verification status on account exists endpoint [#330](https://github.com/rokwire/core-building-block/issues/330)

### Fixed
- Fix the accounts collection index for app and org [#333](https://github.com/rokwire/core-building-block/issues/333)

## [1.13.0] - 2021-11-22
### Added
- Expose resend verification code services API [#287](https://github.com/rokwire/core-building-block/issues/287)
- Add password reset from client and reset links [#216](https://github.com/rokwire/core-building-block/issues/216)
- User PII in tokens [#169](https://github.com/rokwire/core-building-block/issues/169)
- Add authentication required auth wrapper [#250](https://github.com/rokwire/core-building-block/issues/250)

### Security
- Change string comparisons to constant time comparisons [#317](https://github.com/rokwire/core-building-block/issues/317)

### Fixed
- Auth types removed from wrong endpoint [#321](https://github.com/rokwire/core-building-block/issues/321)
- Profile request fails for email sign up [#320](https://github.com/rokwire/core-building-block/issues/320)

## [1.12.0] - 2021-11-10
### Added
- Login session duration policies [#258](https://github.com/rokwire/core-building-block/issues/258)
- Handle groups mappings from OIDC integration [#276](https://github.com/rokwire/core-building-block/issues/276)
- Expose get account services API [#217](https://github.com/rokwire/core-building-block/issues/217)
- Define unified responses for the APIs [#286](https://github.com/rokwire/core-building-block/issues/286)
- Add refresh token abuse detection to login sessions [#257](https://github.com/rokwire/core-building-block/issues/257)

### Changed
- Limit number of active login sessions per account [#256](https://github.com/rokwire/core-building-block/issues/256)
- Expose transaction interface on storage adapter [#285](https://github.com/rokwire/core-building-block/issues/285)

### Fixed
- 502 error on login when missing preferences [#299](https://github.com/rokwire/core-building-block/issues/299)

## [1.11.0] - 2021-11-04
### Added
- Set up permission groups [#25](https://github.com/rokwire/core-building-block/issues/25)

## [1.10.0] - 2021-11-03
### Added
- Merge client and Profile BB profiles and preferences [#228](https://github.com/rokwire/core-building-block/issues/228)

## [1.9.0] - 2021-11-01
### Added
- Disable email verification [#280](https://github.com/rokwire/core-building-block/issues/280)

### Changed
- Dissociate permissions from applications [#207](https://github.com/rokwire/core-building-block/issues/207)

## [1.8.0] - 2021-10-27
### Added
- Prepare Core for Admin app integration [#247](https://github.com/rokwire/core-building-block/issues/247)
- Expose does account exist services API [#255](https://github.com/rokwire/core-building-block/issues/255)

### Fixed
- MongoDB ChangeStream Watch() does not recover [#259](https://github.com/rokwire/core-building-block/issues/259)

## [1.7.0] - 2021-10-25
### Added
- Handle API key validation for non-anonymous users [#244](https://github.com/rokwire/core-building-block/issues/244)
- Implement logins sessions [#172](https://github.com/rokwire/core-building-block/issues/172) 

## [1.6.0] - 2021-10-19
### Added
- Implement logins sessions - almost completed [#172](https://github.com/rokwire/core-building-block/issues/172) 

## [1.5.0] - 2021-10-15
### Fixed
- Permission authorization failing on all endpoints in Docker [#239](https://github.com/rokwire/core-building-block/issues/239)

### Changed
- Switch to ROKWIRE open source libraries [#232](https://github.com/rokwire/core-building-block/issues/232)

## [1.4.0] - 2021-10-11
### Fixed
- Fix various issues [#215](https://github.com/rokwire/core-building-block/issues/215)

### Removed
- **REVERT:** Handle anonymous ID conversion [#204](https://github.com/rokwire/core-building-block/issues/204)

## [1.3.0] - 2021-10-08
### Added
- Expose get account preferences services API [#206](https://github.com/rokwire/core-building-block/issues/206) 

### Changed
- Improve how the system sends emails [#192](https://github.com/rokwire/core-building-block/issues/192)

## [1.2.0] - 2021-10-07
### Security
- Fix Mongo driver vulnerability [#123](https://github.com/rokwire/core-building-block/issues/123)

### Added
- Extract IP address from reques [#246](https://github.com/rokwire/core-building-block/issues/246)
- Populate profile data automatically from ROKWIRE 2.0 Profile BB [#185](https://github.com/rokwire/core-building-block/issues/185)
- Add phone authentication support [#24](https://github.com/rokwire/core-building-block/issues/24)
- Handle anonymous ID conversion [#204](https://github.com/rokwire/core-building-block/issues/204)
- Create a Security.md [#193](https://github.com/rokwire/core-building-block/issues/193)
- Set up authorization system [#45](https://github.com/rokwire/core-building-block/issues/45)
- Add permissions to tokens [#189](https://github.com/rokwire/core-building-block/issues/189)
- Set up anonymous tokens [#26](https://github.com/rokwire/core-building-block/issues/26)
- Add Email authentication and verification [#23](https://github.com/rokwire/core-building-block/issues/23)
- Set up delete account endpoint [#180](https://github.com/rokwire/core-building-block/issues/180)
- Anonymous profile(non-pii) endpoints [#135](https://github.com/rokwire/core-building-block/issues/135)
- User PII endpoints [#128](https://github.com/rokwire/core-building-block/issues/128)
- Handle refresh tokens across multiple devices/apps/orgs [#149](https://github.com/rokwire/core-building-block/issues/149)
- Expose admin API which gets applications list [#104](https://github.com/rokwire/core-building-block/issues/104)
- Restructure auth package to provide APIs interface [#161](https://github.com/rokwire/core-building-block/issues/161)
- Set up refresh tokens [#95](https://github.com/rokwire/core-building-block/issues/95)
- Set up OIDC compliant token validation endpoints [#51](https://github.com/rokwire/core-building-block/issues/51)
- Storage improvements [#144](https://github.com/rokwire/core-building-block/issues/144)
- Expose admin API which creates application [#82](https://github.com/rokwire/core-building-block/issues/82)
- Suppress logs from the AWS load balancer health checks [#141](https://github.com/rokwire/core-building-block/issues/141)
- Set up accounts [#18](https://github.com/rokwire/core-building-block/issues/18)
- Optional OIDC URL overrides [#139](https://github.com/rokwire/core-building-block/issues/139)
- Automate Docker deployment process on Dev [#10](https://github.com/rokwire/core-building-block/issues/10)
- Improve error wrapping [#83](https://github.com/rokwire/core-building-block/issues/83)
- Set up scoped tokens [#98](https://github.com/rokwire/core-building-block/issues/98)
- Expose admin API which gets application. [#103](https://github.com/rokwire/core-building-block/issues/103)
- Expose auth APIs [#81](https://github.com/rokwire/core-building-block/issues/81)
- Expose admin API which gives the organizations list [#61](https://github.com/rokwire/core-building-block/issues/61)
- Expose admin API which gets an organization [#60](https://github.com/rokwire/core-building-block/issues/60)
- Expose service registration handlers [#75](https://github.com/rokwire/core-building-block/issues/75)
- Split OpenAPI yaml file [#84](https://github.com/rokwire/core-building-block/issues/84)
- Standardize logging using logging library [#78](https://github.com/rokwire/core-building-block/issues/78)
- Set up API documentation [#8](https://github.com/rokwire/core-building-block/issues/8)
- Extend the storage adapter listener [#76](https://github.com/rokwire/core-building-block/issues/76)
- Add OIDC support [#17](https://github.com/rokwire/core-building-block/issues/17)
- Incorporate Application entity in the data model [#50](https://github.com/rokwire/core-building-block/issues/50)
- Expose admin API which updates an organization [#59](https://github.com/rokwire/core-building-block/issues/59)
- Set up unit tests environment [#7](https://github.com/rokwire/core-building-block/issues/7)
- Expose admin API which creates an organization [#58](https://github.com/rokwire/core-building-block/issues/58)
- Expose update global config admin API [#36](https://github.com/rokwire/core-building-block/issues/36)
- Expand the model to handle the user devices [#41](https://github.com/rokwire/core-building-block/issues/41)
- Expose get global config admin API [#35](https://github.com/rokwire/core-building-block/issues/35)
- Set up auth framework [#16](https://github.com/rokwire/core-building-block/issues/16)
- Expose version API [#13](https://github.com/rokwire/core-building-block/issues/13)
- Set up project skeleton [#1](https://github.com/rokwire/core-building-block/issues/1)
- Define data model [#2](https://github.com/rokwire/core-building-block/issues/2)
- Expose create global config admin API [#34](https://github.com/rokwire/core-building-block/issues/34)
- Set up logging [#6](https://github.com/rokwire/core-building-block/issues/6)

### Fixed
- Fix broken OIDC login [#211](https://github.com/rokwire/core-building-block/issues/211)
- Fix crash on phone login [#208](https://github.com/rokwire/core-building-block/issues/208)
- Fix email account verification [#198](https://github.com/rokwire/core-building-block/issues/198)
- Fix build failure [#196](https://github.com/rokwire/core-building-block/issues/196)
- Fix admin APIs after the model changes [#173](https://github.com/rokwire/core-building-block/issues/173)
- Fix login issues [#178](https://github.com/rokwire/core-building-block/issues/178)
- Fix base path validation issue [#174](https://github.com/rokwire/core-building-block/issues/174)
- Fix auth credentials search for multiple apps [#153](https://github.com/rokwire/core-building-block/issues/153)
- Fix GlobalPermission and OrganizationPermission in the doc APIs model [#151](https://github.com/rokwire/core-building-block/issues/151)
- OIDC auth bug fixes [#143](https://github.com/rokwire/core-building-block/issues/143)
- Fix APIs requests validation [#89](https://github.com/rokwire/core-building-block/issues/89)
- Fixing the Log and the Changelog for issues #35 and #36 [#54](https://github.com/rokwire/core-building-block/issues/54)

### Changed
- Login API issues [#182](https://github.com/rokwire/core-building-block/issues/182)
- Move temporary claims to auth library [#183](https://github.com/rokwire/core-building-block/issues/183)
- Prepare the service to be deployed into Rokwire infrastructure [#176](https://github.com/rokwire/core-building-block/issues/176)
- Users authentication polish [#155](https://github.com/rokwire/core-building-block/issues/155)
- Optimise the Mongo DB collections indexes usage [#146](https://github.com/rokwire/core-building-block/issues/146)

[Unreleased]: https://github.com/rokwire/core-building-block/compare/v1.34.0...HEAD
[1.34.0]: https://github.com/rokwire/core-building-block/compare/v1.33.0...v1.34.0
[1.33.0]: https://github.com/rokwire/core-building-block/compare/v1.32.2...v1.33.0
[1.32.2]: https://github.com/rokwire/core-building-block/compare/v1.32.1...v1.32.2
[1.32.1]: https://github.com/rokwire/core-building-block/compare/v1.32.0...v1.32.1
[1.32.0]: https://github.com/rokwire/core-building-block/compare/v1.31.2...v1.32.0
[1.31.2]: https://github.com/rokwire/core-building-block/compare/v1.31.1...v1.31.2
[1.31.1]: https://github.com/rokwire/core-building-block/compare/v1.31.0...v1.31.1
[1.31.0]: https://github.com/rokwire/core-building-block/compare/v1.30.0...v1.31.0
[1.30.0]: https://github.com/rokwire/core-building-block/compare/v1.29.0...v1.30.0
[1.29.0]: https://github.com/rokwire/core-building-block/compare/v1.28.0...v1.29.0
[1.28.0]: https://github.com/rokwire/core-building-block/compare/v1.27.0...v1.28.0
[1.27.0]: https://github.com/rokwire/core-building-block/compare/v1.26.0...v1.27.0
[1.26.0]: https://github.com/rokwire/core-building-block/compare/v1.25.0...v1.26.0
[1.25.0]: https://github.com/rokwire/core-building-block/compare/v1.24.2...v1.25.0
[1.24.2]: https://github.com/rokwire/core-building-block/compare/v1.24.1...v1.24.2
[1.24.1]: https://github.com/rokwire/core-building-block/compare/v1.24.0...v1.24.1
[1.24.0]: https://github.com/rokwire/core-building-block/compare/v1.23.0...v1.24.0
[1.23.0]: https://github.com/rokwire/core-building-block/compare/v1.22.0...v1.23.0
[1.22.0]: https://github.com/rokwire/core-building-block/compare/v1.21.1...v1.22.0
[1.21.1]: https://github.com/rokwire/core-building-block/compare/v1.21.0...v1.21.1
[1.21.0]: https://github.com/rokwire/core-building-block/compare/v1.20.1...v1.21.0
[1.20.1]: https://github.com/rokwire/core-building-block/compare/v1.20.0...v1.20.1
[1.20.0]: https://github.com/rokwire/core-building-block/compare/v1.19.0...v1.20.0
[1.19.0]: https://github.com/rokwire/core-building-block/compare/v1.18.0...v1.19.0
[1.18.0]: https://github.com/rokwire/core-building-block/compare/v1.17.0...v1.18.0
[1.17.0]: https://github.com/rokwire/core-building-block/compare/v1.16.0...v1.17.0
[1.16.0]: https://github.com/rokwire/core-building-block/compare/v1.15.0...v1.16.0
[1.15.0]: https://github.com/rokwire/core-building-block/compare/v1.14.0...v1.15.0
[1.14.0]: https://github.com/rokwire/core-building-block/compare/v1.13.0...v1.14.0
[1.13.0]: https://github.com/rokwire/core-building-block/compare/v1.12.0...v1.13.0
[1.12.0]: https://github.com/rokwire/core-building-block/compare/v1.11.0...v1.12.0
[1.11.0]: https://github.com/rokwire/core-building-block/compare/v1.10.0...v1.11.0
[1.10.0]: https://github.com/rokwire/core-building-block/compare/v1.9.0...v1.10.0
[1.9.0]: https://github.com/rokwire/core-building-block/compare/v1.8.0...v1.9.0
[1.8.0]: https://github.com/rokwire/core-building-block/compare/v1.7.0...v1.8.0
[1.7.0]: https://github.com/rokwire/core-building-block/compare/v1.6.0...v1.7.0
[1.6.0]: https://github.com/rokwire/core-building-block/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/rokwire/core-building-block/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/rokwire/core-building-block/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/rokwire/core-building-block/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/rokwire/core-building-block/compare/v1.1.0...v1.2.0
