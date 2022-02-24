# Contrast Verify Action
This action verifies an application that's onboarded to Contrast by determining whether the application violates a [Job Outcome Policy](https://docs.contrastsecurity.com/en/define-a-job-outcome-policy.html) or threshold of open vulnerabilities.

## Inputs
|Input Name|Description|Required|
|------|------|------|
|`apiKey`|Contrast User/Service Account API Key|Yes|
|`orgId`|Contrast Organization ID|Yes|
|`apiUrl`|URL of your Contrast Teamserver Instance (must begin with `https://` or `http://`)|No, defaults to `https://app.contrastsecurity.com`|
|`serviceKey`|Contrast User or Service Account service key|Yes, unless `authHeader` is passed|
|`authHeader`|Contrast User or Service Account authorization header|Yes, if `username` and `serviceKey` not passed|
|`userName`|Contrast User or Service Account username|Yes, if `authHeader` not passed|
|`appId`|ID of the application to verify against|Yes, if `appName` not passed|
|`appName`|Name of the application to verify against|Yes, if `appId` not passed|
|`buildNumber`|The build number or app version tag to filter vulnerabilities by|No|
|`failThreshold`|Number of vulnerabilities that are needed to fail the build (not used if there is a defined job outcome policy)|No, defaults to `0`|
|`jobStartTime`|Filter vulnerabilities first found after this timestamp (formatted **in milliseconds** since the epoch)|No, defaults to `0`|
|`severities`|Comma separated list of vulnerability severities to consider (not used if there is a defined job outcome policy)|No, defaults to `CRITICAL,HIGH`|


## Example usage

```yaml
name: Test and Verify
on:
  push:
    branches:
      - main
    pull_request:
jobs:
  test_and_verify:
    runs-on: ubuntu-latest
    steps:
        # check out project
      - uses: actions/checkout@v2
        # record start time so we can verify only newly found vulnerabilities
      - name: Define job start time
        run: |
          import time
          n = int(round(time.time() * 1000))
          print(f"::set-output name=jobStartTime::{n}")
        shell: python
        id: set-job-start-time
      # steps to build and run integration tests
      # - name: Run tests
      #
      - name: Contrast Verify
        uses: Contrast-Security-OSS/integration-verify-github-action@main
        with:
          apiKey: ${{ secrets.CONTRAST_API_KEY }}
          orgId: <organization id>
          apiUrl: https://app.contrastsecurity.com
          authHeader: ${{ secrets.CONTRAST_AUTH_HEADER }}
          appName: App_Name_Here
          #appId: or app_uuid_here if known
          jobStartTime: "${{ steps.set-job-start-time.outputs.jobStartTime }}"
```

### Job Start Time and Build Number

As shown above, the `jobStartTime` input value can be generated with a script step, running prior to your tests.
This approach is useful when you want to consider only new vulnerabilities found by this action run, for example in a pull request.

You may also pass a `buildNumber` input which will filter for vulnerabilities found in specific builds. The agent must be started with this same build number provided via the `CONTRAST__APPLICATION__VERSION` environment variable, or equivalent YAML/System Properties.

If both `jobStartTime` and `buildNumber` are provided, the step will consider only vulnerabilities found since the specified start time, **and** with the provided `buildNumber`.

## Use outside of GitHub Actions

This integration is available as a Docker image which allows it to be used in other environments outside of GitHub Actions, for example, in GitLab pipelines. For more details, see [Container Documentation](CONTAINER_DOCS.md).

## Logging

Debug log messages are only made visible when [GitHub Actions debug logging is enabled](https://docs.github.com/en/actions/monitoring-and-troubleshooting-workflows/enabling-debug-logging#enabling-step-debug-logging).

## Development Setup
1. Run `python -m venv venv` to setup a virtual environment
1. Run `. venv/bin/activate` to activate the virtual environment
1. Run `pip install -r requirements-dev.txt` to install development dependencies (will also include app dependencies)
1. Run `pre-commit install` to setup the pre-commit hook which handles formatting
