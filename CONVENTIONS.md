# Conventions
This document contains a description of the conventions which should be followed when contributing to this repository. They are not final and suggestions are welcome.

## Formatting
- Follow [Effective Go](https://go.dev/doc/effective_go) conventions.
- Use snake-case everywhere in the database and JSON objects.

## Changelog
We should keep the changelog up to date as this is part of the open source platform. Each issue should be added to the top of the appropriate [verb](https://keepachangelog.com/en/1.0.0/#how) in the `[Unreleased]` section of the changelog in the corresponding issue branch in the format `{issue name} [#{issue-ID}]({issue url})` (eg. [Unreleased] Added - Set up project skeleton [#1](https://github.com/rokwire/core-building-block/issues/1))

## API Documentation
When implementing an API:
- Define the OpenAPI 3.0 documentation for the API in the appropriate yaml files stored in `driver/web/docs` folder.
- Run `make oapi-gen-docs` to generate the `def.yaml` file stored in `driver/web/docs/gen` folder. To run this command, you will need to install [swagger-cli](https://github.com/APIDevTools/swagger-cli). This command will merge all OpenAPI files into the `def.yaml` file. Please do not change the `def.yaml` file manually.
- Run `make oapi-gen-types` to generate the Go types from the `def.yaml` file. To run this command, you will need to install [oapi-codegen](https://github.com/deepmap/oapi-codegen). This command will update the `driver/web/docs/gen/gen_types.go` file with the new generated types.
- Implement the API handler function using the generated Go structs in `driver/web/docs/gen/gen_types.go`
- Test you API via the documentation - Open http://localhost/core/doc/ui/ , choose "Local server" from the "Servers" combobox and run your API. This is an alternative to Postman. Make sure to set the correct value in the `ROKWIRE_CORE_HOST` environment variable (eg. http://localhost/core) before running the service to access the docs.

## Pull Requests
If your PR resolves the issue entirely, link it to the issue in the description with a [keyword](https://docs.github.com/en/issues/tracking-your-work-with-issues/creating-issues/linking-a-pull-request-to-an-issue#linking-a-pull-request-to-an-issue-using-a-keyword) (eg. `Resolves #{issue number}`).This will close the issue automatically when the PR is merged. 

If the PR does not resolve the issue, include a reference to the related issue in the PR description without a keyword (eg. `Progress on #{issue number}`).

## Unit Tests
The test coverage should be at least 80% of the new created code.

Whenever a new interface is created, a unit test should be created for each function it exposes. The purpose of these unit tests is primarily to ensure that the contract with consumers established by the interfaces are not unintentionally broken by future implementation changes. With this in mind, test cases should include all common usage, as well as any edge cases for which consistency is important. 

When updating or changing existing implementations, run the associated unit tests to ensure that they still pass. If they do not, the implementation changes likely changed the interface as well. If the change to the interface was intentional, update the unit tests as needed to make them pass and document the [Breaking Change](#breaking-changes). If the change was not intentional, rework your implementation changes to keep the interface consistent and ensure all tests pass.

## Breaking Changes
Breaking changes should be avoided when possible, but will sometimes be necessary. In the event that a breaking change does need to be made, this change should be documented clearly for developers relying on the functionality. This includes the following items:
* Create and apply a "breaking" label to the associated issue in GitHub
* Add a "BREAKING:" prefix to the associated line in the CHANGELOG
* Document upgrade instructions in the README in the `Upgrading > Migration steps > Unreleased > Breaking changes` section. These should explain the changes that were made, as well as all changes the developer will need to make to handle the breaking change. Examples should be provided where appropriate.

When a release including the breaking change is created, the following steps must be taken:
* Update the MAJOR version number to indicate that incompatible interface changes have occurred (see [Semantic Versioning](https://semver.org/))
* Update the `Upgrading > Migration steps > Unreleased` section in the README to the latest version (eg. `Upgrading > Migration steps > v1.1.0`)
* Add a "BREAKING" warning to the release notes
* Include a copy of the upgrade instructions from the README in the release notes

## Deprecations
In some cases when [Breaking Changes](#breaking-changes) need to be made, the existing functionality must be maintained to provide backwards compatibility. To do so, the new component (function, type, field, package...) should be created and the old component should be maintained and flagged as deprecated. This will give time for developers relying on the component to make the necessary updates before it becomes unavailable. In these cases, the following process should be followed:
* Add a "DEPRECATED:" prefix to the associated line in the CHANGELOG
* Add a "Deprecated:" comment to the component and provide information about the deprecation and replacement. See the [Godoc](https://go.dev/blog/godoc) documentation for more information.
* Document upgrade instructions in the README in the `Upgrading > Migration steps > Unreleased > Deprecations` section. These should explain the changes that were made, as well as all changes the developer will need to make to replace the deprecated component. Examples should be provided where appropriate. If known, include a timeline for when the deprecated components will be removed.

When a release including the deprecation is created, the following steps must be taken:
* Update the `Upgrading > Migration steps > Unreleased` section in the README to the latest version (eg. `Upgrading > Migration steps > v1.1.0`)
* Include a copy of the upgrade instructions from the README in the release notes

When the deprecated components are finally removed, follow the process to document this as a [Breaking Change](#breaking-changes). 

