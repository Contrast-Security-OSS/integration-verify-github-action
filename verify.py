#!/usr/bin/env python3
from os import getenv

import requests
from actions_toolkit import core as gh_action
from requests.exceptions import RequestException

REQUIRED_INPUTS = ["CONTRAST_API_KEY", "CONTRAST_AUTHORIZATION", "CONTRAST_ORG_ID"]


def validate_inputs():
    """Populate configuration object or set step to failed if required inputs are not set."""
    errors = []
    config = {}
    for input in REQUIRED_INPUTS:
        val = gh_action.get_input(input)
        if val is None or val == "":
            errors.append(input)
        else:
            config[input] = val

    app_id = gh_action.get_input("APP_ID")
    app_name = gh_action.get_input("APP_NAME")
    if app_id and app_id != "":
        config["APP_ID"] = app_id
    elif app_name and app_name != "":
        config["APP_NAME"] = app_name
    else:
        errors.append("(APP_ID or APP_NAME)")

    if len(errors) != 0:
        gh_action.error(
            f'Missing required inputs: {", ".join(errors)}, please see documentation for correct usage.'
        )
        gh_action.set_failed("Missing required inputs")

    host = gh_action.get_input("CONTRAST_HOST") or "app.contrastsecurity.com"
    config["BASE_URL"] = f"https://{host}/Contrast/api/ng/{config['CONTRAST_ORG_ID']}/"
    gh_action.debug(f'Base URL: {config["BASE_URL"]}')

    severities = gh_action.get_input("SEVERITIES") or "CRITICAL,HIGH"
    config["SEVERITIES"] = severities.upper()

    fail_threshold = gh_action.get_input("FAIL_THRESHOLD") or 0
    config["FAIL_THRESHOLD"] = int(fail_threshold)

    config["BUILD_NUMBER"] = gh_action.get_input("BUILD_NUMBER") or getenv("GITHUB_SHA")

    return config


class ContrastVerifyAction:
    def __init__(self, config) -> None:
        self._app_id = config.get("APP_ID")
        self._app_name = config.get("APP_NAME")
        self._base_url = config["BASE_URL"]
        self._build_number = config["BUILD_NUMBER"]
        self._contrast_api_key = config["CONTRAST_API_KEY"]
        self._contrast_authorization = config["CONTRAST_AUTHORIZATION"]
        self._fail_threshold = config["FAIL_THRESHOLD"]
        self._severities = config["SEVERITIES"]
        self._headers = None
        self._app_id_verified = False

    @property
    def teamserver_headers(self):
        """Generate common request headers for TeamServer."""
        if not self._headers:
            self._headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Api-Key": self._contrast_api_key,
                "Authorization": self._contrast_authorization,
            }
        return self._headers

    @property
    def app_id(self):
        """Return the app ID if provided in config, else look it up based on app name and cache it."""
        if self._app_id and self._app_id_verified:
            return self._app_id

        self.determine_application_id()
        return self._app_id

    def get_request(self, path, parameters={}):
        """Send a GET request to TeamServer."""
        gh_action.debug(f"GET {path} {parameters}")
        response = requests.get(
            self._base_url + path, params=parameters, headers=self.teamserver_headers
        )
        response.raise_for_status()
        return response

    def post_request(self, path, body):
        """Send a POST request to TeamServer."""
        gh_action.debug(f"POST {path}")
        response = requests.post(
            self._base_url + path, json=body, headers=self.teamserver_headers
        )
        response.raise_for_status()
        return response

    def validate_connection(self):
        """Determine if we can successfully make an API call, else mark the step failed."""
        try:
            response = self.get_request("profile/")
            response.json()
        except Exception as e:
            gh_action.set_failed(
                f"Connection test failed, please verify credentials (agent credentials will not work) - {e}"
            )

    def determine_application_id(self):
        """Determine application ID from application name for config."""
        if self._app_id:
            if not self._app_id_verified:
                try:
                    self.get_request(f"applications/{self._app_id}")
                except RequestException as e:
                    gh_action.set_failed(
                        f"Unable to find application with ID {self._app_id} - check the ID and ensure the user account this action uses can access it - {e}"
                    )
                self._app_id_verified = True

            gh_action.info(f"Using provided application ID {self._app_id}")
            return

        response = self.get_request(f"applications/name?filterText={self._app_name}")
        applications = response.json()["applications"]
        matching_named_apps = list(
            filter(lambda app: app["name"] == self._app_name, applications)
        )
        if len(matching_named_apps) != 1:
            gh_action.set_failed(
                f'Could not match one app with name "{self._app_name}", found {len(matching_named_apps)}, consider using APP_ID input instead.'
            )
        else:
            self._app_id = matching_named_apps[0]["app_id"]
            gh_action.info(f'Application ID for "{self._app_name}" is {self._app_id}')

    def perform_security_check(self):
        """Call the security check endpoint and return job outcome policy data."""
        gh_action.info(f"Using app version tags: [{self._build_number}]")
        response = self.post_request(
            "securityChecks",
            {
                "application_id": self.app_id,
                "security_check_filter": {
                    "query_by": "APP_VERSION_TAG",
                    "app_version_tags": [self._build_number],
                },
                "origin": "GitHub/Python",
            },
        )
        return response.json()

    def fetch_vulnerability_count(self):
        """Call the vulnerability quick filter endpoint to return number of vulnerabilities."""
        response = self.get_request(
            f"traces/{self._app_id}/quick",
            {
                "severities": self._severities,
                "appVersionTags": [self._build_number],
            },
        )
        return response.json()

    def verify_application(self):
        # First check for a configured job outcome policy defined in TeamServer
        job_outcome_policy_result = self.perform_security_check()
        gh_action.debug(job_outcome_policy_result)
        security_check_result = job_outcome_policy_result["security_check"]["result"]
        if security_check_result == False:
            jop_policy = job_outcome_policy_result["security_check"][
                "job_outcome_policy"
            ]
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
            response = self.fetch_vulnerability_count()
            gh_action.debug(response)
            open_vulnerabilities_data = next(
                filter(
                    lambda filter: filter["filterType"] == "OPEN", response["filters"]
                )
            )
            open_vulnerabilities = open_vulnerabilities_data["count"]
            if open_vulnerabilities > self._fail_threshold:
                gh_action.set_failed(
                    f"The vulnerability count is {open_vulnerabilities} - Contrast verify gate fails as this is above threshold (threshold allows {self._fail_threshold})"
                )
            else:
                gh_action.info(
                    f"The vulnerability count is {open_vulnerabilities} (below threshold)"
                )


if __name__ == "__main__":
    config = validate_inputs()
    action = ContrastVerifyAction(config)
    action.validate_connection()
    action.determine_application_id()
    action.verify_application()
