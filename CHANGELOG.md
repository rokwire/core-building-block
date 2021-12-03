# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.16.0] - 2021-12-02
### Fixed
- Upgrade logging library for error JSON fix [#347](https://github.com/rokwire/core-building-block/issues/347)
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
- Expose get accounts admin API [#283] (https://github.com/rokwire/core-building-block/issues/283)
- Expose get account admin API [#270] (https://github.com/rokwire/core-building-block/issues/270)
- Expose does account exist admin API [#271](https://github.com/rokwire/core-building-block/issues/271)
- Extract IP address from request [#246](https://github.com/rokwire/core-building-block/issues/246)
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

[Unreleased]: https://github.com/rokwire/core-building-block/compare/v1.16.0...HEAD
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
