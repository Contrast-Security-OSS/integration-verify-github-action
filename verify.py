#!/usr/bin/env python3
from os import getenv

import requests
from actions_toolkit import core as gh_action

REQUIRED_INPUTS = ["CONTRAST_API_KEY", "CONTRAST_AUTHORIZATION", "CONTRAST_ORG_ID"]
CONFIG = {}


def validate_inputs():
    """Populate configuration object or set step to failed if required inputs are not set."""
    errors = []
    for input in REQUIRED_INPUTS:
        val = gh_action.get_input(input)
        if val is None or val == "":
            errors.append(input)
        else:
            CONFIG[input] = val

    app_id = gh_action.get_input("APP_ID")
    app_name = gh_action.get_input("APP_NAME")
    if app_id and app_id != "":
        CONFIG["APP_ID"] = app_id
    elif app_name and app_name != "":
        CONFIG["APP_NAME"] = app_name
    else:
        errors.append("(APP_ID or APP_NAME)")

    if len(errors) != 0:
        gh_action.error(
            f'Missing required inputs: {", ".join(errors)}, please see documentation for correct usage.'
        )
        gh_action.set_failed("Missing required inputs")

    host = gh_action.get_input("CONTRAST_HOST") or "app.contrastsecurity.com"
    CONFIG["BASE_URL"] = f"https://{host}/Contrast/api/ng/{CONFIG['CONTRAST_ORG_ID']}/"
    gh_action.debug(f'Base URL: {CONFIG["BASE_URL"]}')

    severities = gh_action.get_input("SEVERITIES") or "CRITICAL,HIGH"
    CONFIG["SEVERITIES"] = severities.upper()

    fail_threshold = gh_action.get_input("FAIL_THRESHOLD") or 0
    CONFIG["FAIL_THRESHOLD"] = int(fail_threshold)

    CONFIG["BUILD_NUMBER"] = gh_action.get_input("BUILD_NUMBER") or getenv("GITHUB_SHA")


def teamserver_headers():
    """Generate common request headers for TeamServer."""
    return {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Api-Key": CONFIG["CONTRAST_API_KEY"],
        "Authorization": CONFIG["CONTRAST_AUTHORIZATION"],
    }


def get_request(path, parameters={}):
    """Send a GET request to TeamServer."""
    gh_action.debug(f"GET {path} {parameters}")
    response = requests.get(
        CONFIG["BASE_URL"] + path, params=parameters, headers=teamserver_headers()
    )
    response.raise_for_status()
    return response


def post_request(path, body):
    """Send a POST request to TeamServer."""
    gh_action.debug(f"POST {path}")
    response = requests.post(
        CONFIG["BASE_URL"] + path, json=body, headers=teamserver_headers()
    )
    response.raise_for_status()
    return response


def validate_connection():
    """Determine if we can successfully make an API call, else mark the step failed."""
    try:
        response = get_request("profile/")
        response.json()
    except Exception as e:
        gh_action.set_failed(str(e))


def determine_application_id():
    """Determine application ID from application name for config."""
    if "APP_ID" in CONFIG:
        gh_action.info(f'Using provided application ID {CONFIG["APP_ID"]}')
        return

    response = get_request(f'/applications/name?filterText={CONFIG["APP_NAME"]}')
    applications = response.json()["applications"]
    matching_named_apps = list(
        filter(lambda app: app["name"] == CONFIG["APP_NAME"], applications)
    )
    if len(matching_named_apps) != 1:
        gh_action.set_failed(
            f'Could not match one app with name "{CONFIG["APP_NAME"]}", found {len(matching_named_apps)}, consider using APP_ID input instead.'
        )
    else:
        CONFIG["APP_ID"] = matching_named_apps[0]["app_id"]
        gh_action.info(f'Application ID for {CONFIG["APP_NAME"]} is {CONFIG["APP_ID"]}')


def perform_security_check():
    """Call the security check endpoint and return job outcome policy data."""
    gh_action.info(f'Using app version tags: [{CONFIG["BUILD_NUMBER"]}]')
    response = post_request(
        "securityChecks",
        {
            "application_id": CONFIG["APP_ID"],
            "security_check_filter": {
                "query_by": "APP_VERSION_TAG",
                "app_version_tags": [CONFIG["BUILD_NUMBER"]],
            },
            "origin": "GitHub/Python",
        },
    )
    return response.json()


def fetch_vulnerability_count():
    """Call the vulnerability quick filter endpoint to return number of vulnerabilities."""
    response = get_request(
        f'traces/{CONFIG["APP_ID"]}/quick',
        {
            "severities": CONFIG["SEVERITIES"],
            "appVersionTags": [CONFIG["BUILD_NUMBER"]],
        },
    )
    return response.json()


validate_inputs()
validate_connection()
determine_application_id()

# First check for a configured job outcome policy defined in TeamServer
job_outcome_policy_result = perform_security_check()
gh_action.debug(job_outcome_policy_result)
security_check_result = job_outcome_policy_result["security_check"]["result"]
if security_check_result == False:
    jop_policy = job_outcome_policy_result["security_check"]["job_outcome_policy"]
    jop_outcome = jop_policy["outcome"]
    jop_name = jop_policy["name"]
    if jop_policy["opt_into_query"] == False:
        gh_action.info(
            f'Matching policy "{jop_name}" is not configured to apply the "query vulnerabilities by selection from the plugin when filtering vulnerabilities" option, this means all open vulnerabilities will be considered, not just those from the build_number input.'
        )

    gh_action.set_failed(
        f'Contrast verify gate fails with status {jop_outcome} - policy "{jop_name}"'
    )
elif security_check_result == True:
    gh_action.info("Step passes matching policy")
else:
    # At this point, there is no matching job outcome policy in TeamServer, so query the open vulnerability count instead
    gh_action.info(
        "No matching job outcome policy, checking vulnerabilities against threshold..."
    )
    response = fetch_vulnerability_count()
    gh_action.debug(response)
    open_vulnerabilities_data = next(
        filter(lambda filter: filter["filterType"] == "OPEN", response["filters"])
    )
    open_vulnerabilities = open_vulnerabilities_data["count"]
    if open_vulnerabilities > CONFIG["FAIL_THRESHOLD"]:
        gh_action.set_failed(
            f'The vulnerability count is {open_vulnerabilities} - Contrast verify gate fails as this is above threshold (threshold allows {CONFIG["FAIL_THRESHOLD"]})'
        )
    else:
        gh_action.info(
            f"The vulnerability count is {open_vulnerabilities} (below threshold)"
        )
