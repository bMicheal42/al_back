# Alerta Release 9.1

[![Slack chat](https://img.shields.io/badge/chat-on%20slack-blue?logo=slack)](https://slack.alerta.dev)
[![Coverage Status](https://coveralls.io/repos/github/alerta/alerta/badge.svg?branch=master)](https://coveralls.io/github/alerta/alerta?branch=master)
[![Docker Pulls](https://img.shields.io/docker/pulls/alerta/alerta-web.svg)](https://hub.docker.com/r/alerta/alerta-web)

## Content

- [Description of Alerta](#description-of-alerta)
  - [Requirements](#requirements)
- [Instructions for Local Backend Setup](#instructions-for-local-backend-setup)
  - [Prerequisites](#prerequisites)
  - [1. Create and activate Python virtual environment](#1-create-and-activate-python-virtual-environment)
  - [2. Install dependencies](#2-install-dependencies)
  - [3. Run PostgreSQL via Docker](#3-run-postgresql-via-docker)
  - [4. Configure environment variables and start the server](#4-configure-environment-variables-and-start-the-server)
  - [5. Create admin account](#5-create-admin-account)
  - [6. Install and configure CLI for testing](#6-install-and-configure-cli-for-testing)
  - [Troubleshooting](#troubleshooting)
- [Default Alerta instructions](#default-alerta-instructions)
  - [Installation](#installation)
  - [Docker](#docker)
  - [Configuration](#configuration)
  - [Documentation](#documentation)
  - [Development](#development)
  - [Troubleshooting](#troubleshooting-1)
  - [Tests](#tests)
  - [Cloud Deployment](#cloud-deployment)
  - [License](#license)

## Description of Alerta

The Alerta monitoring tool was developed with the following aims in mind:

- distributed and de-coupled so that it is **SCALABLE**
- minimal **CONFIGURATION** that easily accepts alerts from any source
- quick at-a-glance **VISUALISATION** with drill-down to detail

![webui](/docs/images/alerta-webui-v7.jpg?raw=true)

---

### Requirements

Release 9 only supports Python 3.9 or higher.

The only mandatory dependency is MongoDB or PostgreSQL. Everything else is optional.

- Postgres version 13 or better
- MongoDB version 6.0 or better

## Instructions for Local Backend Setup

Below are the steps to set up and run the Alerta backend on a local machine for development and testing.

#### Prerequisites:

- Python 3.9 or higher
- Docker for running PostgreSQL
- Git for cloning the repository (if applicable)

#### 1. Create and activate Python virtual environment

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# For Unix/MacOS:
source venv/bin/activate
# For Windows:
# venv\Scripts\activate
```

#### 2. Install dependencies

```bash
# Install main dependencies
pip install -r requirements.txt

# Install project in development mode (optional)
pip install -e .

# Install PostgreSQL driver
pip install psycopg2-binary
```

#### 3. Run PostgreSQL via Docker

```bash
# Start PostgreSQL container
docker run --name alerta-db \
  -e POSTGRES_DB=monitoring \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -p 5432:5432 \
  -d postgres

# Check container status
docker ps | grep alerta-db
```

> **Note**: If the container already exists but is stopped, start it with:
>
> ```bash
> docker start alerta-db
> ```

#### 4. Configure environment variables and start the server

```bash
# Set environment variables
export DATABASE_URL=postgres://postgres:postgres@localhost:5432/monitoring
export FLASK_APP=alerta
export FLASK_DEBUG=1

# Start development server
flask run --port 8080
```

> **Note**: After starting, the API will be available at http://localhost:8080/api

#### 5. Create admin account

```bash
# Create temporary configuration file
touch temp_config.py

# Create admin user
export ALERTA_SVR_CONF_FILE=$(pwd)/temp_config.py && alertad user --username admin2@example.com --password admin123 --name "Admin User 2"
```

#### 6. Install and configure CLI for testing

```bash
# Install CLI
pip install alerta
```

```bash
# Authenticate in CLI, for admin user - write email used above when create admin user
alerta login
```

```bash
# Send test alert
alerta send \
  --resource "test-resource" \
  --event "test-event" \
  --environment "Production" \
  --service "TestService" \
  --severity "minor" \
  --text "This is a test alert"
```

#### Troubleshooting

1. **Database connection errors**:

   - Make sure the PostgreSQL container is running: `docker ps`
   - Check container logs: `docker logs alerta-db`
   - Verify database accessibility: `psql -h localhost -U postgres -d monitoring`

2. **Flask startup errors**:
   - Verify all environment variables are set correctly
   - Make sure the virtual environment is activated
   - Check server logs for errors

## Default Alerta instructions

### Installation

To install MongoDB on Debian/Ubuntu run:

    $ sudo apt-get install -y mongodb-org
    $ mongod

To install MongoDB on CentOS/RHEL run:

    $ sudo yum install -y mongodb
    $ mongod

To install the Alerta server and client run:

    $ pip install alerta-server alerta
    $ alertad run

To install the web console run:

    $ wget https://github.com/alerta/alerta-webui/releases/latest/download/alerta-webui.tar.gz
    $ tar zxvf alerta-webui.tar.gz
    $ cd dist
    $ python3 -m http.server 8000

    >> browse to http://localhost:8000

#### Docker

Alerta and MongoDB can also run using Docker containers, see [alerta/docker-alerta](https://github.com/alerta/docker-alerta).

### Configuration

To configure the `alertad` server override the default settings in `/etc/alertad.conf`
or using `ALERTA_SVR_CONF_FILE` environment variable::

    $ ALERTA_SVR_CONF_FILE=~/.alertad.conf
    $ echo "DEBUG=True" > $ALERTA_SVR_CONF_FILE

### Documentation

More information on configuration and other aspects of alerta can be found
at <http://docs.alerta.io>

### Development

To run in development mode, listening on port 5000:

    $ export FLASK_APP=alerta FLASK_DEBUG=1
    $ pip install -e .
    $ flask run

To run in development mode, listening on port 8080, using Postgres and
reporting errors to [Sentry](https://sentry.io):

    $ export FLASK_APP=alerta FLASK_DEBUG=1
    $ export DATABASE_URL=postgres://localhost:5432/alerta5
    $ export SENTRY_DSN=https://8b56098250544fb78b9578d8af2a7e13:fa9d628da9c4459c922293db72a3203f@sentry.io/153768
    $ pip install -e .[postgres]
    $ flask run --debugger --port 8080 --with-threads --reload

### Troubleshooting

Enable debug log output by setting `DEBUG=True` in the API server
configuration:

```
DEBUG=True

LOG_HANDLERS = ['console','file']
LOG_FORMAT = 'verbose'
LOG_FILE = '$HOME/alertad.log'
```

It can also be helpful to check the web browser developer console for
JavaScript logging, network problems and API error responses.

### Tests

To run the _all_ the tests there must be a local Postgres
and MongoDB database running. Then run:

    $ TOXENV=ALL make test

To just run the Postgres or MongoDB tests run:

    $ TOXENV=postgres make test
    $ TOXENV=mongodb make test

To run a single test run something like:

    $ TOXENV="mongodb -- tests/test_search.py::QueryParserTestCase::test_boolean_operators" make test
    $ TOXENV="postgres -- tests/test_queryparser.py::PostgresQueryTestCase::test_boolean_operators" make test

### Cloud Deployment

Alerta can be deployed to the cloud easily using Heroku <https://github.com/alerta/heroku-api-alerta>,
AWS EC2 <https://github.com/alerta/alerta-cloudformation>, or Google Cloud Platform
<https://github.com/alerta/gcloud-api-alerta>

### License

    Alerta monitoring system and console
    Copyright 2012-2023 Nick Satterly

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
