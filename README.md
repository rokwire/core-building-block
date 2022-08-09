# Core Building Block
The Core Building Block handles core functions for the Rokwire platform - users, accounts, profiles, applications, organizations, configurations, authentication, and authorization.

## Architecture
The service is based on clear hexagonal architecture. The hexagonal architecture divides the system into several loosely-coupled components, such as the application core and different adapters. We categorize the adapters in two categories - driver and driven.

### core
This is the core component of the service. It keeps the data model and the logic of the service. It communicates with the outer world via adapters.

### driver adapters
What the service provides - user interface, rest adapter, test agent etc.

### driven adapters
What the service depends on - database, mock database, integration with other services etc.

## Documentation
The functionality provided by this application is documented in the [Wiki](https://github.com/rokwire/core-building-block/wiki).

The API documentation is available here: https://api.rokwire.illinois.edu/core/doc/ui/index.html

## Set Up

### Prerequisites
MongoDB v4.2.2+

Go v1.16+

### Environment Variables
The following Environment variables are supported. The service will not start unless those marked as Required are supplied.

Name|Format|Required|Description
---|---|---|---
ROKWIRE_CORE_LOG_LEVEL | < string > | no | Logging level to be printed to the console. Options are Info, Debug, Warn, and Error. Defaults to Info.
ROKWIRE_CORE_ENVIRONMENT | < string > | yes | Environment in which this application is being run.
ROKWIRE_CORE_PORT | < int > | no | Port to be used by this application. Defaults to 80.
ROKWIRE_CORE_SERVICE_ID | < string > | yes | Service ID to be used by the Core BB eg. "core".
ROKWIRE_CORE_HOST | < string > | yes | Url where this application is being hosted.
ROKWIRE_CORE_MONGO_AUTH | <mongodb://USER:PASSWORD@HOST:PORT/DATABASE NAME> | yes | MongoDB authentication string. The user must have read/write privileges.
ROKWIRE_CORE_MONGO_DATABASE | < string > | yes | MongoDB database name.
ROKWIRE_CORE_MONGO_TIMEOUT | < int > | no | Timeout for connection attempts to MongoDB in milliseconds. Defaults to 500.
ROKWIRE_CORE_AUTH_TWILIO_ACCOUNT_SID | < string > | no | Twilio Account SID. Twilio phone authentication will not work without this variable.
ROKWIRE_CORE_AUTH_TWILIO_TOKEN | < string > | no | Secret token needed to access Twilio APIs. Twilio phone authentication will not work without this variable.
ROKWIRE_CORE_AUTH_TWILIO_SERVICE_SID | < string > | no | Twilio Service SID for the phone verification service. Twilio phone authentication will not work without this variable.
ROKWIRE_CORE_SMTP_HOST | < string > | no | Host address of the SMTP server. Email verification will not work without this variable.
ROKWIRE_CORE_SMTP_PORT | < int > | no | Port used to send emails through the SMTP server. Email verification will not work without this variable.
ROKWIRE_CORE_SMTP_USER | < string > | no | Username for the user on the SMTP server. Email verification will not work without this variable.
ROKWIRE_CORE_SMTP_PASSWORD | < string > | no | Password for the user on the SMTP server. Email verification will not work without this variable.
ROKWIRE_CORE_SMTP_EMAIL_FROM | < string > | no | "From" email address to be used when sending emails. Email verification will not work without this variable.
ROKWIRE_CORE_AUTH_PRIV_KEY | < string > | yes | PEM encoded private key for auth service RSA keypair. Not required if ROKWIRE_CORE_AUTH_PRIV_KEY_PATH is set.
ROKWIRE_CORE_AUTH_PRIV_KEY_PATH | < string > | yes | Path to file containing PEM encoded private key for auth service RSA keypair. Not required if ROKWIRE_CORE_AUTH_PRIV_KEY is set.
ROKWIRE_CORE_MIN_TOKEN_EXP | < int > | no | Minimum duration of access tokens to be allowed in minutes. Defaults to 5.
ROKWIRE_CORE_MAX_TOKEN_EXP | < int > | no | Maximum duration of access tokens to be allowed in minutes. Defaults to 60.
ROKWIRE_CORE_MIGRATE_PROFILES | < bool > | no | Boolean value indicating whether profiles should be migrated from the Profile Building Block. Defaults to false.
ROKWIRE_CORE_PROFILE_BB_HOST | < string > | no | Profile Building Block host url
ROKWIRE_CORE_PROFILE_BB_API_KEY | < string > | no | Internal API key for accessing the Profile Building Block
ROKWIRE_CORE_SYSTEM_APP_TYPE_IDENTIFIER | < string > | yes | Identifier for system admin application type. This should be the application or bundle identifier for Android/iOS respectively. Only required for first run.
ROKWIRE_CORE_SYSTEM_APP_TYPE_NAME | < string > | yes | Name for system admin application type. Only required for first run.
ROKWIRE_CORE_SYSTEM_API_KEY | < string > | yes | API key for system admin application. Only required for first run.
ROKWIRE_CORE_SYSTEM_ACCOUNT_EMAIL | < string > | yes | Email address for initial system admin account. Only required for first run.
ROKWIRE_CORE_SYSTEM_ACCOUNT_PASSWORD | < string > | yes | Password for initial system admin account. Only required for first run.
GITHUB_APP_CONFIG_WEBHOOK_REQUEST_TOKEN | < string > | no | Secret token in the webhook request header.
GITHUB_TOKEN | < string > | no | Access token that authenticates with GitHub.
GITHUB_APP_CONFIG_ORG_NAME | < string > | no | Organization name of the target repository.
GITHUB_APP_CONFIG_REPO_NAME | < string > | no | Target GitHub repository name.
GITHUB_APP_CONFIG_WEBHOOK_CONFIG_PATH | < string > | no | File path of webhook-config.json in the target repository.
GITHUB_APP_CONFIG_BRANCH | < string > | no | Branch name of the app config files repository.
### Run Application

#### Run locally without Docker

1. Clone the repo (outside GOPATH)

2. Open the terminal and go to the root folder
  
3. Make the project  
```
$ make
...
▶ building executable(s)… 1.9.0 2020-08-13T10:00:00+0300
```

4. Set environment variables

5. Run the executable
```
$ ./bin/health
```

#### Run locally as Docker container

1. Clone the repo (outside GOPATH)

2. Open the terminal and go to the root folder
  
3. Create Docker image  
```
docker build -t core .
```

4. Create [env.list](https://docs.docker.com/engine/reference/commandline/run/#set-environment-variables--e---env---env-file) file containing the environment variables

5. Run as Docker container
```
docker run --env-file env.list -p 80:80 core
```

#### Tools

##### Run tests
```
$ make tests
```

##### Run code coverage tests
```
$ make cover
```

##### Run golint
```
$ make lint
```

##### Run gofmt to check formatting on all source files
```
$ make checkfmt
```

##### Run gofmt to fix formatting on all source files
```
$ make fixfmt
```

##### Cleanup everything
```
$ make clean
```

##### Run help
```
$ make help
```

##### Generate Swagger docs
To run this command, you will need to install [swagger-cli](https://github.com/APIDevTools/swagger-cli)
```
$ make oapi-gen-docs
```


##### Generate models from Swagger docs
To run this command, you will need to install [oapi-codegen](https://github.com/deepmap/oapi-codegen)
```
$ make make oapi-gen-types
```

### Test Application APIs

Verify the service is running as calling the get version API.

#### Call get version API

curl -X GET -i http://localhost/core/version

Response
```
0.0.0
```

## Contributing
If you would like to contribute to this project, please be sure to read the [Contributing Guidelines](CONTRIBUTING.md), [Code of Conduct](CODE_OF_CONDUCT.md), and [Conventions](CONVENTIONS.md) before beginning.

### Secret Detection
This repository is configured with a [pre-commit](https://pre-commit.com/) hook that runs [Yelp's Detect Secrets](https://github.com/Yelp/detect-secrets). If you intend to contribute directly to this repository, you must install pre-commit on your local machine to ensure that no secrets are pushed accidentally.

```
# Install software 
$ git pull  # Pull in pre-commit configuration & baseline 
$ pip install pre-commit 
$ pre-commit install
```
