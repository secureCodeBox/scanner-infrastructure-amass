![Build Status](https://travis-ci.com/secureCodeBox/scanner-infrastructure-nmap.svg?token=2Rsf2E9Bq3FduSxRf6tz&branch=develop)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

# About
This repository contains a self contained µService utilizing the Amass Subdomain Scanner for the secureCodeBox project.

Amass is a awesome tool to find subdomains of a domain using multiple techniques all at once.

Further Documentation:
* [Project Description][scb-project]
* [Developer Guide][scb-developer-guide]
* [User Guide][scb-user-guide]

## Configuration Options
To configure this service specify the following environment variables:

| Environment Variable       | Value Example         |
| -------------------------- | --------------------- |
| ENGINE_ADDRESS             | http://engine         |
| ENGINE_BASIC_AUTH_USER     | username              |
| ENGINE_BASIC_AUTH_PASSWORD | 123456                |

## Build with docker
To build the docker container run: `docker build -t CONTAINER_NAME:LABEL .`

[scb-project]:              https://github.com/secureCodeBox/secureCodeBox
[scb-developer-guide]:      https://github.com/secureCodeBox/secureCodeBox/blob/develop/docs/developer-guide/README.md
[scb-developer-guidelines]: https://github.com/secureCodeBox/secureCodeBox/blob/develop/docs/developer-guide/README.md#guidelines
[scb-user-guide]:           https://github.com/secureCodeBox/secureCodeBox/tree/develop/docs/user-guide
