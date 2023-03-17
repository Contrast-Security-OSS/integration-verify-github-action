# Running the container

This integration is available as a Docker image published to GitHub container repository.

The package and available versions can be seen here: [integration-verify](https://github.com/Contrast-Security-OSS/integration-verify-github-action/pkgs/container/integration-verify)

## Inputs -> Environment Variables
Inputs documented in the GitHub Actions [README](README.md#inputs) are all supported, and may be passed via environment variables:

|Input Name|Environment Variable|Prefixed variant|
|------|------|------|
|`apiKey`|`API_KEY`|`CONTRAST_API_KEY`|
|`orgId`|`ORG_ID`|`CONTRAST_ORG_ID`|
|`apiUrl`|`API_URL`|`CONTRAST_API_URL`|
|`serviceKey`|`SERVICE_KEY`|`CONTRAST_SERVICE_KEY`|
|`authHeader`|`AUTH_HEADER`|`CONTRAST_AUTH_HEADER`|
|`userName`|`USER_NAME`|`CONTRAST_USER_NAME`|
|`appId`|`APP_ID`|`CONTRAST_APP_ID`|
|`appName`|`APP_NAME`|`CONTRAST_APP_NAME`|
|`buildNumber`|`BUILD_NUMBER`|`CONTRAST_BUILD_NUMBER`
|`failThreshold`|`FAIL_THRESHOLD`|`CONTRAST_FAIL_THRESHOLD`|
|`jobStartTime`|`JOB_START_TIME`|`CONTRAST_JOB_START_TIME`|
|`severities`|`SEVERITIES`|`CONTRAST_SEVERITIES`|

The `CONTRAST_` prefix is optional.

## Docker


```bash
docker run -e ORG_ID -e APP_NAME -e USERNAME -e API_URL -e API_KEY -e AUTH_HEADER \
ghcr.io/contrast-security-oss/integration-verify:latest
```


## GitLab example

```yaml
contrast_verify:
  image: ghcr.io/contrast-security-oss/integration-verify:latest
  stage: verify
  variables:
    API_KEY: $CONTRAST__API_KEY
    ORG_ID: $CONTRAST__ORG_ID
    API_URL: https://$CONTRAST_HOST
    AUTH_HEADER: $CONTRAST__AUTHORIZATION
    APP_NAME: $APP_NAME
    BUILD_NUMBER: $CI_COMMIT_SHORT_SHA
  script:
    - /usr/bin/env python3 /verify.py
```

## Logging

Debug log messages are only emitted when an environment variable named `DEBUG` is set.

## Proxy / Custom TLS Certificates

A HTTP or HTTPS proxy may be used, by setting the environment variables `HTTP_PROXY` and `HTTPS_PROXY` respectively. The value should be the full proxy URL, including authorization details if required.

If your environment requires custom certificate(s) to be trusted, these may be provided via the environment variable `CA_FILE`/`CONTRAST_CA_FILE` in pem format.
