# Conventions and Work Flow
Here are proposals which every develop should accept. They are not final and every suggestins is welcomed.

## Conventions
- Variable naming should follow the camel case in Go.
- Use snake case everywhere in the database.

## Work Flow
Here is the process every develop should follow when working on an issue.

### Create issue
Create an issue for each new feature or bug. Issue names should describe the changes to be made starting with an action verb (eg. Set up project skeleton, Fix email login bug). Issues should contain a detailed description comment including any information about feature requirements or steps to reproduce bugs.

### Create issue branch
All work should happen in an issue branch. The name of the branch should be `issues/ID-[issue number]`.

#### Update the CHANGELOG.md file
We should keep the changelog up to date as this is part of open source platform. Each issue should be added to the top of the appropriate [verb](https://keepachangelog.com/en/1.0.0/#how) in the `[Unreleased]` section of the changelog in the corresponding issue branch in the format `{issue name} [#{issue-ID}]({issue url})` (eg. [Unreleased] Added - Set up project skeleton [#1](https://github.com/rokwire/core-building-block/issues/1))

#### Add code
Make as many commits as needed to complete the issue.

When a developer needs to implement an API he/she should need to do this:
- Add the API in the yaml files stored in driver/web/docs folder.
- Run this command(make oapi-gen-docs) to generate the def.yaml file stored in driver/web/docs/gen folder. You will need to install on your mashine this tool - https://github.com/APIDevTools/swagger-cli. Once the command is run then all yaml files will be merged into the def.yaml file. Please do not change the def.yaml file manually.
- Run this command(make oapi-gen-types) to generate the Go types from the def.yaml file. You will need to install on your mashine this tool - https://github.com/deepmap/oapi-codegen. Once the command is run then the driver/web/docs gen_types.go file will be updated with the new generated types.
- Implement the API using the generated Go structs in driver/web/docs gen_types.go
- Test you API via the documentation - open http://localhost/core/doc/ui/ , choose Local server from the Servers combobox and run your API. This is an alternative of Postman.

#### Write unit tests to your code
The test coverage should be at least 80% of the new created code.

### Open Pull Request to develop branch
Once ready then open pull request to merge this into the develop branch. The name of the pull request should be `[ID-{the issue number}] {the issue name}`.
The merge requires at least one approval. If your PR resolves the issue entirely, link it to the issue in the description with a [keyword](https://docs.github.com/en/issues/tracking-your-work-with-issues/creating-issues/linking-a-pull-request-to-an-issue#linking-a-pull-request-to-an-issue-using-a-keyword) (eg. `Resolves #{issue number}`).This will close the issue automatically when the PR is merged. If the PR does not resolve the issue, include a reference to the related issue in the PR description without a keyword (eg. `Progress on #{issue number}`).

### Merge the Pull Request
Once the pull request is approved then merge it into develop using "Squash and Merge". "Squash and Merge" gets all your changes and put this into develop with one single commit. This means that in your issue branch you can do as many commits as you want not tending to be so clear in the commits comments. Once you merge then you can exlude not meaningful commits and leave only the ones which gives meaningful information.

### Delete the issue branch
Delete the issue branch from GitHub

### Close the issue in GitHub
If you have resolved the issues, verify that the issue has been closed by a PR, or close it manually if not.