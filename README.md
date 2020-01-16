---
title: "Amass"
path: "scanner/Amass"
category: "scanner"
usecase: "Subdomain Scanner"
release: "https://img.shields.io/github/release/secureCodeBox/scanner-infrastructure-amass.svg"

---

![owasp logo](https://www.owasp.org/images/thumb/f/fe/Owasp_logo.jpg/320px-Owasp_logo.jpg)

The OWASP Amass Project has developed a tool to help information security professionals perform network mapping of attack surfaces and perform external asset discovery using open source information gathering and active reconnaissance techniques.

<!-- end -->

# About

This repository contains a self contained µService utilizing the Amass Subdomain Scanner for the secureCodeBox project. To learn more about the Amass scanner itself visit [OWASP_Amass_Project] or [Amass GitHub].

## Amass parameters

To hand over supported parameters through api usage, you can set following attributes:

```json
[
  {
    "name": "amass",
    "context": "some Context",
    "target": {
      "name": "targetName",
      "location": "http://your-target.com/",
      "attributes": {
        "NO_DNS": "[true | false]"
      }
    }
  }
]
```

## Example

Example configuration:

```json
[
  {
    "name": "amass",
    "context": "Example Test",
    "target": {
      "name": "example.com",
      "location": "example.com",
      "attributes": {}
    }
  }
]
```

Example Output:

```json
{
    "findings": [
      {
        "id":"c834c9cb-c3a6-4983-41bd-70df4dd4e5a8",
        "name":"www.example.com",
        "description":"Found subdomain www.example.com",
        "category":"Subdomain",
        "osi_layer":"NETWORK",
        "severity":"INFORMATIONAL",
        "reference":{},
        "attributes":{
          "ADDRESSES":[],
          "DOMAIN":"https://www.example.com/",
          "NAME":"www.example.com",
          "SOURCE":"Google",
          "Tag":"scrape"
          },
        "location":"www.example.com",
        "false_positive":false
      },
      {
        "id":"33e8da26-f8cb-4a09-a90c-44823320b868",
        "name":"gitlab.example.com",
        "description":"Found subdomain gitlab.example.com",
        "category":"Subdomain",
        "osi_layer":"NETWORK",
        "severity":"INFORMATIONAL",
        "reference":{},
        "attributes":{
          "ADDRESSES":[],
          "DOMAIN":"https://gitlab.example.com/",
          "NAME":"gitlab.example.com",
          "SOURCE":"Google",
          "Tag":"scrape"
          },
        "location":"gitlab.example.com",
        "false_positive":false
      }
    ]
  }
```


## Development

### Configuration Options

To configure this service specify the following environment variables:

| Environment Variable       | Value Example |
| -------------------------- | ------------- |
| ENGINE_ADDRESS             | http://engine |
| ENGINE_BASIC_AUTH_USER     | username      |
| ENGINE_BASIC_AUTH_PASSWORD | 123456        |

## Local setup

1. Clone the repo into your $GOPATH
2. Install the go dependency manager "dep"
3. Run `dep ensure` inside your repo to load the dependencies
4. Run `go build main.go` to compile
5. Execute the compiled `./main` file

## Build with docker

To build the docker container run: `docker build -t IMAGE_NAME:LABEL .`

[![Build Status](https://travis-ci.com/secureCodeBox/scanner-infrastructure-amass.svg?branch=master)](https://travis-ci.com/secureCodeBox/scanner-infrastructure-amass)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![GitHub release](https://img.shields.io/github/release/secureCodeBox/scanner-infrastructure-amass.svg)](https://github.com/secureCodeBox/scanner-infrastructure-amass/releases/latest)


[OWASP_Amass_Project]: https://www.owasp.org/index.php/OWASP_Amass_Project
[Amass GitHub]: https://github.com/OWASP/Amass
