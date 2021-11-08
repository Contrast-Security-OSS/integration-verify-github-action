# ContrastAssessVerifyAction

This action verifies an Assess application, applying a Job Outcome Policy or vulnerability threshold to fail the step if there are open vulnerabilities violating the policy/threshold.

## Inputs

## `build_number`

The build number or app version tag to filter vulnerabilities by.
Defaults to `$GITHUB_SHA`

## `contrast_api_key`

**Required** Contrast User/Service Account API Key.

## `contrast_authorization`

**Required** Contrast User/Service Account Authorization Header.

## `contrast_url`

URL of your Contrast Teamserver Instance (should begin with `https://` or `http://`).
Defaults to `https://app.contrastsecurity.com`
(`/Contrast/api/ng/` is used automatically)

## `contrast_org_id`

**Required** Contrast Organization ID.

## `app_name`

Name of the application to verify against. **Required** if app_id not passed.

## `app_id`

ID of the application to verify against. **Required** if app_name not passed.

## `severities`

Comma separated list of vulnerability severities to consider (not used if there is a defined job outcome policy).
Defaults to `CRITICAL,HIGH`

## `fail_threshold`

Number of vulnerabilities that are needed to fail the build (not used if there is a defined job outcome policy).
Defaults to `0`


## Example usage

```yaml
uses: andersonshatch/ContrastAssessVerifyAction@main
with:
  app_name: App_Name_Here
  #app_id: app_uuid_here
  contrast_host: app.contrastsecurity.com
  contrast_api_key: ${{ secrets.CONTRASTAPIKEY }}
  contrast_authorization: ${{ secrets.CONTRASTAUTHORIZATION }}
  contrast_org_id: ${{ secrets.CONTRASTORGID }}
```

## Development Setup
1. Run `python -m venv venv` to setup a virtual environment
1. Run `. venv/bin/activate` to activate the virtual environment
1. Run `pip install -r requirements-dev.txt` to install development dependencies (will also include app dependencies)
1. Run `pre-commit install` to setup the pre-commit hook which handles formatting
