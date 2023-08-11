from pathlib import Path
from sys import version_info
from typing import Optional, Union

import requests
import urllib3
from requests.exceptions import RequestException
from requests.utils import default_user_agent as requests_default_user_agent

from version import __version__

from .helpers.input_output_helpers import OutputHelper


class ContrastVerifyAction:
    def __init__(
        self,
        app_id: Optional[str],
        app_name: Optional[str],
        base_url: str,
        build_number: str,
        contrast_api_key: str,
        contrast_authorization: str,
        fail_threshold: int,
        job_start_time: Optional[int],
        severities: list[str],
        output_helper: Optional[OutputHelper] = None,
        cert_file: Union[Path, bool, None] = None,
    ) -> None:
        self._app_id = app_id
        self._app_name = app_name
        self._base_url = base_url
        self._build_number = build_number
        self._contrast_api_key = contrast_api_key
        self._contrast_authorization = contrast_authorization
        self._fail_threshold = fail_threshold
        self._job_start_time = job_start_time or 0
        self._severities = severities
        self._output_helper = output_helper or OutputHelper()
        self._cert_file = str(cert_file) if cert_file else True

        self._headers = None
        self._user_agent = None
        self._app_id_verified = False
        self._job_start_time_provided = job_start_time is not None

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

        if self._cert_file is False:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # type: ignore

        response = requests.get(
            self._base_url + path,
            params=parameters,
            headers=self.teamserver_headers,
            verify=self._cert_file,
        )
        response.raise_for_status()
        return response

    def post_request(self, path, body):
        """Send a POST request to TeamServer."""
        self._output_helper.debug(f"POST {path}")
        response = requests.post(
            self._base_url + path,
            json=body,
            headers=self.teamserver_headers,
            verify=self._cert_file,
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
                "severities": ",".join(self._severities),
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
