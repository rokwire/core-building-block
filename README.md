# Core Building Block
Building block which handles core functions for the Rokwire platform - users, accounts, profiles, organizations, authentication and authorization.

## Architecture
The service is based on clear hexagonal architecture. The hexagonal architecture divides the system into several loosely-coupled components, such as the application core and different adapters. We categorize the adapters in two categories - driver and driven.

### core
This is the core component of the service. It keeps the data model and the logic of the service. It communicates with the outer world via adapters.

### driver adapters
What the service provides - user interface, rest adapter, test agent etc.

### driven adapters
What the service depends on - database, mock database, integration with other services etc.
GitHub Adapter
- GITHUB_WEBHOOK_TOKEN: secret token that validates webhook requests are expected
- GITHUB_TOKEN: access token that authenticates with GitHub
- GITHUB_ORG_NAME: organization name of the target repository
- GITHUB_REPO_NAME: Target GitHub repository name
- GITHUB_WEBHOOK_CONFIG_PATH: webhook-config.json file path in the target repository