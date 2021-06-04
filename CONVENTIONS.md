# Conventions and Work Flow
Here are proposals which every develop should accept. They are not final and every suggestins is welcomed.

## Conventions
- Variable naming should follow the camel case in Go.
- Use snake case everywhere in the database.

## Work Flow
Here is the process every develop should follow when working on an issue.

### Create issue branch
All work should happen in an issue branch. The name of the branch should be issues/ID-[issue number].

#### Update the CHANGELOG.md file
We should keep the changelog up to date as this is part of open source platform.

#### Add code
Make as many commits as needed to complete the issue.

#### Write unit tests to your code
The test coverage should be at least 80% of the new created code.

### Open Pull Request to develop branch
Once ready then open pull request to merge this into the develop branch. The name of the pull request should be [ID-{the issue number}] {the issue name}.
The merge requires at least one approval.

### Merge the Pull Request
Once the pull request is approved then merge it into develop using "Squash and Merge". "Sqiash and Merge" gets all your changes and put this into develop with one single commit. This means that in your issue branch you can do as many commits as you want not tending to be so clear in the commits comments. Once you merge then you can exlude not menaningul commits and leave only the ones which gives meaningful information.

### Delete the issue branch
Delete the issue branch from GitHub

### Close the issue in GitHub
Finally close the issue in GitHub. Alternativelly yopu can link your PR with your issue which will close the issue automatically when the PR is merged.