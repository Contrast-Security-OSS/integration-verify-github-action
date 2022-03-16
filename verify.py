#!/usr/bin/env python3
from base64 import b64encode
from sys import version_info
from urllib.parse import urlparse

import requests
from requests.exceptions import RequestException
from requests.utils import default_user_agent as requests_default_user_agent

from input_output_helpers import InputHelper, OutputHelper
from version import __version__


def validate_inputs():
    """Populate configuration object or set step to failed if required inputs are not set."""
    errors = []
    config = {}

    apiKey = InputHelper.get_input("API_KEY")
    if apiKey and apiKey != "":
        config["API_KEY"] = apiKey
    else:
        errors.append("apiKey")

    orgId = InputHelper.get_input("ORG_ID")
    if orgId and orgId != "":
        config["ORG_ID"] = orgId
    else:
        errors.append("orgId")

    authorization = InputHelper.get_input("AUTH_HEADER")
    username = InputHelper.get_input("USER_NAME")
    service_key = InputHelper.get_input("SERVICE_KEY")

    if authorization and authorization != "":
        config["AUTHORIZATION"] = authorization
    elif (username and username != "") and (service_key and service_key != ""):
        config["AUTHORIZATION"] = str(
            b64encode(bytes(f"{username}:{service_key}", "UTF-8")), "UTF-8"
        )
    else:
        errors.append("authHeader or (userName and serviceKey)")

    app_id = InputHelper.get_input("APP_ID")
    app_name = InputHelper.get_input("APP_NAME")
    if app_id and app_id != "":
        config["APP_ID"] = app_id
    elif app_name and app_name != "":
        config["APP_NAME"] = app_name
    else:
        errors.append("appId or appName")

    url = (
        InputHelper.get_input("API_URL")
        or "https://app.contrastsecurity.com/Contrast/api/ng/"
    )
    if not url.startswith("https://") and not url.startswith("http://"):
        errors.append("apiUrl (must start with http:// or https://)")

    job_start_time = InputHelper.get_input("JOB_START_TIME")
    if job_start_time is not None and job_start_time != "":
        try:
            config["JOB_START_TIME"] = int(job_start_time)
        except ValueError:
            errors.append("jobStartTime (must be a number)")

    output_helper = OutputHelper()
    if len(errors) != 0:
        output_helper.error(
            f'Missing required inputs: {", ".join(errors)}, please see documentation for correct usage.'
        )
        output_helper.set_failed("Missing required inputs")

    url_parts = urlparse(url)
    if url_parts.path != "/Contrast/api/ng/":
        url = f"{url_parts.scheme}://{url_parts.netloc}/Contrast/api/ng/"
    config["BASE_URL"] = f"{url}{config['ORG_ID']}/"
    output_helper.debug(f'Base URL: {config["BASE_URL"]}')

    severities = InputHelper.get_input("SEVERITIES") or "CRITICAL,HIGH"
    config["SEVERITIES"] = severities.upper()

    fail_threshold = InputHelper.get_input("FAIL_THRESHOLD") or 0
    config["FAIL_THRESHOLD"] = int(fail_threshold)

    config["BUILD_NUMBER"] = InputHelper.get_input("BUILD_NUMBER")

    return config


class ContrastVerifyAction:
    def __init__(self, config) -> None:
        self._app_id = config.get("APP_ID")
        self._app_name = config.get("APP_NAME")
        self._base_url = config["BASE_URL"]
        self._build_number = config["BUILD_NUMBER"]
        self._contrast_api_key = config["API_KEY"]
        self._contrast_authorization = config["AUTHORIZATION"]
        self._fail_threshold = config["FAIL_THRESHOLD"]
        self._job_start_time = config.get("JOB_START_TIME", 0)
        self._severities = config["SEVERITIES"]
        self._headers = None
        self._user_agent = None
        self._app_id_verified = False
        self._job_start_time_provided = "JOB_START_TIME" in config
        self._output_helper = OutputHelper()

    @property
    def user_agent(self):
        """Generate the User-Agent header value."""
        if not self._user_agent:
            github_suffix = (
                "-github-action" if self._output_helper.is_github_actions() else ""
            )
            integration_version = f"integration-verify{github_suffix}/{__version__}"
            python_version = ".".join(map(str, version_info[:3]))

            self._user_agent = f"{integration_version} {requests_default_user_agent()} python/{python_version}"

        return self._user_agent

    @property
    def teamserver_headers(self):
        """Generate common request headers for TeamServer."""
        if not self._headers:
            self._headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Api-Key": self._contrast_api_key,
                "Authorization": self._contrast_authorization,
                "User-Agent": self.user_agent,
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
        self._output_helper.debug(f"GET {path} {parameters}")
        response = requests.get(
            self._base_url + path, params=parameters, headers=self.teamserver_headers
        )
        response.raise_for_status()
        return response

    def post_request(self, path, body):
        """Send a POST request to TeamServer."""
        self._output_helper.debug(f"POST {path}")
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
            self._output_helper.set_failed(
                f"Connection test failed, please verify credentials (agent credentials will not work) - {e}"
            )

    def validate_organization(self):
        """Determine if we can successfully see the specified organization, else mark the step failed."""
        try:
            response = self.get_request("organizations/")
            response.json()
        except Exception as e:
            self._output_helper.set_failed(
                f"Organization test failed, please verify organization ID and credentials (agent credentials will not work) - {e}"
            )

    def determine_application_id(self):
        """Determine application ID from application name for config."""
        if self._app_id:
            if not self._app_id_verified:
                try:
                    self.get_request(f"applications/{self._app_id}")
                except RequestException as e:
                    self._output_helper.set_failed(
                        f"Unable to find application with ID {self._app_id} - check the ID and ensure the user account this action uses can access it - {e}"
                    )
                self._app_id_verified = True

            self._output_helper.info(f"Using provided application ID {self._app_id}")
            return

        response = self.get_request(f"applications/name?filterText={self._app_name}")
        applications = response.json()["applications"]
        matching_named_apps = list(
            filter(lambda app: app["name"] == self._app_name, applications)
        )
        if len(matching_named_apps) != 1:
            self._output_helper.set_failed(
                f'Could not match one app with name "{self._app_name}", found {len(matching_named_apps)}, consider using APP_ID input instead.'
            )
        else:
            self._app_id = matching_named_apps[0]["app_id"]
            self._output_helper.info(
                f'Application ID for "{self._app_name}" is {self._app_id}'
            )

    def perform_security_check(self):
        """Call the security check endpoint and return job outcome policy data."""
        version_tags = []
        if self._build_number != "":
            # only add build_number to the array if it is not empty, preventing send of one element with empty string [""]
            self._output_helper.info(f"Using app version tags: [{self._build_number}]")
            version_tags.append(self._build_number)
        body = {
            "application_id": self.app_id,
            "job_start_time": self._job_start_time,
            "security_check_filter": {
                "query_by": "APP_VERSION_TAG",
                "app_version_tags": version_tags,
            },
            "origin": self.user_agent.split()[0],
        }
        response = self.post_request(
            "securityChecks",
            body,
        )
        return response.json()

    def fetch_vulnerability_count(self):
        """Call the vulnerability quick filter endpoint to return number of vulnerabilities."""
        response = self.get_request(
            f"traces/{self._app_id}/quick",
            {
                "severities": self._severities,
                "appVersionTags": [self._build_number],
                "startDate": self._job_start_time,
                "timestampFilter": "FIRST",
            },
        )
        return response.json()

    def verify_application(self):
        # First check for a configured job outcome policy defined in TeamServer
        job_outcome_policy_result = self.perform_security_check()
        self._output_helper.debug(job_outcome_policy_result)
        security_check_result = job_outcome_policy_result["security_check"]["result"]
        if security_check_result is False:
            jop_policy = job_outcome_policy_result["security_check"][
                "job_outcome_policy"
            ]
            jop_outcome = jop_policy["outcome"]
            jop_name = jop_policy["name"]
            if self._build_number and jop_policy["opt_into_query"] is False:
                self._output_helper.info(
                    f'Matching policy "{jop_name}" is not configured to apply the "query vulnerabilities by selection from the plugin when filtering vulnerabilities" option, this means all open vulnerabilities will be considered, not just those from the build_number input.'
                )
            if not self._job_start_time_provided and jop_policy["is_job_start_time"]:
                self._output_helper.info(
                    f'Matching policy "{jop_name}" has job start time configured, but no job start time was provided, so 0 was passed to consider all open vulnerabilities.'
                )

            self._output_helper.set_failed(
                f'Contrast verify gate fails with status {jop_outcome} - policy "{jop_name}"'
            )
        elif security_check_result is True:
            self._output_helper.info("Step passes matching policy")
        else:
            # At this point, there is no matching job outcome policy in TeamServer, so query the open vulnerability count instead
            self._output_helper.info(
                "No matching job outcome policy, checking vulnerabilities against threshold..."
            )
            response = self.fetch_vulnerability_count()
            self._output_helper.debug(response)
            open_vulnerabilities_data = next(
                filter(
                    lambda filter: filter["filterType"] == "OPEN", response["filters"]
                )
            )
            open_vulnerabilities = open_vulnerabilities_data["count"]
            if open_vulnerabilities > self._fail_threshold:
                self._output_helper.set_failed(
                    f"The vulnerability count is {open_vulnerabilities} - Contrast verify gate fails as this is above threshold (threshold allows {self._fail_threshold})"
                )
            else:
                self._output_helper.info(
                    f"The vulnerability count is {open_vulnerabilities} (below threshold)"
                )


if __name__ == "__main__":
    config = validate_inputs()
    action = ContrastVerifyAction(config)
    action.validate_connection()
    action.validate_organization()
    action.determine_application_id()
    action.verify_application()
