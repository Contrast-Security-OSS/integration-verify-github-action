# ContrastAssessVerifyAction

This action verifies an Assess application, applying a Job Outcome Policy or vulnerability threshold to fail the step if there are open vulnerabilities violating the policy/threshold.

## Inputs

## `apiKey`

**Required** Contrast User/Service Account API Key.

## `orgId`

**Required** Contrast Organization ID.

## `apiUrl`

URL of your Contrast Teamserver Instance (should begin with `https://` or `http://`).
Defaults to `https://app.contrastsecurity.com`
(`/Contrast/api/ng/` is used automatically if omitted)

## `serviceKey`

Contrast User/Service Account service key. Required if authorization not passed.

## `authHeader`

Contrast User/Service Account Authorization Header. **Required** if username and service key not passed.

## `userName`

Contrast User/Service Account username. Required if authorization not passed.

## `appId`

ID of the application to verify against. **Required** if app_name not passed.

## `appName`

Name of the application to verify against. **Required** if app_id not passed.

## `buildNumber`

The build number or app version tag to filter vulnerabilities by.

## `failThreshold`

Number of vulnerabilities that are needed to fail the build (not used if there is a defined job outcome policy).
Defaults to `0`

## `jobStartTime`

Filter vulnerabilities first found after this timestamp (formatted **in milliseconds** since the epoch)

## `severities`

Comma separated list of vulnerability severities to consider (not used if there is a defined job outcome policy).
Defaults to `CRITICAL,HIGH`


## Example usage

```yaml
uses: andersonshatch/ContrastAssessVerifyAction@main
with:
  apiKey: ${{ secrets.CONTRAST_API_KEY }}
  orgId: ${{ env.CONTRAST_ORG_ID }}
  apiUrl: app.contrastsecurity.com
  authHeader: ${{ secrets.CONTRAST_AUTH_HEADER }}
  appName: App_Name_Here
  #appId: app_uuid_here
```

## Development Setup
1. Run `python -m venv venv` to setup a virtual environment
1. Run `. venv/bin/activate` to activate the virtual environment
1. Run `pip install -r requirements-dev.txt` to install development dependencies (will also include app dependencies)
1. Run `pre-commit install` to setup the pre-commit hook which handles formatting
