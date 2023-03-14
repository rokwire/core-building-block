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
Pull requests should be linked to the associated issue with a [keyword](https://docs.github.com/en/issues/tracking-your-work-with-issues/creating-issues/linking-a-pull-request-to-an-issue#linking-a-pull-request-to-an-issue-using-a-keyword) in the description (eg. `Resolves #{issue number}`). This will close the issue automatically when the PR is merged. 

## Unit Tests
The test coverage should be at least 80% of the new created code.

Whenever a new interface is created, a unit test should be created for each function it exposes. The purpose of these unit tests is primarily to ensure that the contract with consumers established by the interfaces are not unintentionally broken by future implementation changes. With this in mind, test cases should include all common usage, as well as any edge cases for which consistency is important. 

When updating or changing existing implementations, run the associated unit tests to ensure that they still pass. If they do not, the implementation changes likely changed the interface as well. If the change to the interface was intentional, update the unit tests as needed to make them pass and document the [Breaking Change](#breaking-changes). If the change was not intentional, rework your implementation changes to keep the interface consistent and ensure all tests pass.

### Mocks
To test some components of the system in isolation, it may be necessary to mock some interfaces. Mocks should be automatically generated using the [Mockery](https://github.com/vektra/mockery) utility. Mockery can be installed by running `go install github.com/vektra/mockery/v2@latest`. One example of an interface that will need to be mocked is the `core.Storage` interface. To generate (or regenerate) the mocks for the storage interface using Mockery, `cd core` then run `mockery --name=Storage`. 

## Releases
Whenever a new release is made, the following process should be followed.

### Dev Releases
Changes to the `develop` branch will be continuously deployed into the dev environment to be tested. When several significant changes have been merged into the `develop` branch and have been tested, a new dev release should be made. 

To make a dev release:

1. Checkout the `develop` branch and `git pull` to ensure you have the latest updates locally.
2. Update the "Unreleased" version in the [CHANGELOG](CHANGELOG.md#unreleased) to `[X.X.X] - YYYY-MM-dd` (eg. `[1.1.7] - 2022-06-08`).
3. Update [SECURITY.md](SECURITY.md) to reflect the latest supported and unsupported versions.
4. Update the latest version in any docs or source code as needed. 
5. Make any changes needed to document [breaking changes](#breaking-changes) and [deprecations](#deprecations).
6. Commit all changes to the `develop` branch with the commit message `Release vX.X.X` (eg. `Release v1.1.7).
7. Create a new tag from the `develop` branch called `vX.X.X` (eg. `v1.1.7`).
8. Push changes to `develop` branch and create remote tag atomically using `git push --atomic origin develop vX.X.X` (eg. `git push --atomic origin develop v1.1.7`).
> **NOTE:** Pushing to `develop` will automatically trigger a deployment to the `dev` environment. Pushing and creating the new tag atomically will ensure that the deployment pipeline correctly uses the new tag to set the version on the build it generates.

### Production Releases
When you are ready to move a release to the production environment:

1. Make a pull request from `develop` into `main` named `Release vX.X.X` (eg. `Release v1.1.7`).
2. Review the changes included in the update to ensure they are all production ready.
3. Checkout the `main` branch and `git pull` to ensure you have the latest updates locally.
4. Run `git merge --ff-only origin/develop`. If this merge fails, merge any changes from `main` back into `develop` then restart from Step 3.
> **NOTE:** While this is slightly cumbersome, GitHub does not currently support fast-forward merge through the pull request user interface. We want to use fast-forward merging to preserve the linear history from develop without introducing a new merge commit (like `Create a merge commit`), or rebasing and changing commit hashes unnecessarily (like `Rebase and merge`). This will ensure that the exact same commit hash is used to build for staging and production that was used to build for develop.
5. Run `git push`.
6. **RECOMMENDED** - Publish a new [GitHub Release](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository#creating-a-release) from this tag with the title `vX.X.X` (eg. `v1.1.7`). Include the contents from the [CHANGELOG](CHANGELOG.md) for this latest version in the release notes, as well as a link to the whole [CHANGELOG](CHANGELOG.md) on the `main` branch. For libraries this is highly recommended.

Pushing to the `main` branch will automatically trigger a deployment to the `stage` environment. Once the release has been tested appropriately, the production pipeline can be manually triggered to deploy the same Docker image in the `stage` environment to the `prod` environment.

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