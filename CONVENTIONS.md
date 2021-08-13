# Conventions and Workflow
This document contains a description of the conventions and workflow process which should be followed when contributing to this repository. They are not final and suggestions are welcome.

## Conventions
- Variable naming should follow the camel-case convention in Go.
- Use snake-case everywhere in the database and JSON objects.

## Work Flow
This section describes the process that developers should follow when contributing to this repository.

### 1. Create issue
Create an issue for each new feature or bug. Issue names should describe the changes to be made starting with an action verb (eg. Set up project skeleton, Fix email login bug). Issues should contain a detailed description comment including any information about feature requirements or steps to reproduce bugs.

### 2. Create issue branch
All work should happen in an issue branch. The name of the branch should be `issues/ID-[issue number]`.

#### Update the CHANGELOG.md file
We should keep the changelog up to date as this is part of the open source platform. Each issue should be added to the top of the appropriate [verb](https://keepachangelog.com/en/1.0.0/#how) in the `[Unreleased]` section of the changelog in the corresponding issue branch in the format `{issue name} [#{issue-ID}]({issue url})` (eg. [Unreleased] Added - Set up project skeleton [#1](https://github.com/rokwire/core-building-block/issues/1))

#### Add code
Make as many commits as needed to complete the issue.

When implementing an API:
- Define the OpenAPI 3.0 documentation for the API in the appropriate yaml files stored in `driver/web/docs` folder.
- Run `make oapi-gen-docs` to generate the `def.yaml` file stored in `driver/web/docs/gen` folder. To run this command, you will need to install [swagger-cli](https://github.com/APIDevTools/swagger-cli). This command will merge all OpenAPI files into the `def.yaml` file. Please do not change the `def.yaml` file manually.
- Run `make oapi-gen-types` to generate the Go types from the `def.yaml` file. To run this command, you will need to install [oapi-codegen](https://github.com/deepmap/oapi-codegen). This command will update the `driver/web/docs/gen/gen_types.go` file with the new generated types.
- Implement the API handler function using the generated Go structs in `driver/web/docs/gen/gen_types.go`
- Test you API via the documentation - Open http://localhost/doc/ui/ , choose "Local server" from the "Servers" combobox and run your API. This is an alternative to Postman. Make sure to set the correct value in the `ROKWIRE_CORE_HOST` environment variable (eg. http://localhost) before running the service to access the docs.

#### Write unit tests for your code
The test coverage should be at least 80% of the new created code.

### 3. Open Pull Request to `develop` branch
When ready, open a pull request to merge your issue branch into the `develop` branch. The name of the pull request should be `[ID-{the issue number}] {the issue name}`.
At least one reviewer must approve the changes before they are merged. 

If your PR resolves the issue entirely, link it to the issue in the description with a [keyword](https://docs.github.com/en/issues/tracking-your-work-with-issues/creating-issues/linking-a-pull-request-to-an-issue#linking-a-pull-request-to-an-issue-using-a-keyword) (eg. `Resolves #{issue number}`).This will close the issue automatically when the PR is merged. If the PR does not resolve the issue, include a reference to the related issue in the PR description without a keyword (eg. `Progress on #{issue number}`).

### 4. Merge the Pull Request
Once the pull request is approved, merge it into `develop` using "Squash and Merge". "Squash and Merge" merges all changes into `develop` in one single commit. This means that you can make as many commits as needed in your issue branch without cluttering the commit history on `develop`. When performing the "Squash and Mergs" you can exlude any low-impact commits from the description and leave only the ones which provide meaningful information.

### 5. Delete the issue branch
Delete the issue branch from GitHub

### 6. Close the issue in GitHub
If you have resolved the issues, verify that the issue has been closed by a pull request, or close it manually if not.