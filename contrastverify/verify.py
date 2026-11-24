from pathlib import Path
from sys import version_info

import requests
from requests.exceptions import RequestException
from requests.utils import default_user_agent as requests_default_user_agent

from version import __version__

from .helpers.input_output_helpers import OutputHelper


class ContrastVerifyAction:
    def __init__(
        self,
        app_id: str | None,
        app_name: str | None,
        base_url: str,
        build_number: str,
        contrast_api_key: str,
        contrast_authorization: str,
        fail_threshold: int,
        job_start_time: int | None,
        severities: list[str],
        output_helper: OutputHelper | None = None,
        cert_file: Path | None = None,
        session_metadata: dict[str, str] | None = None,
        route_coverage_threshold: float | None = None,
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
        self._session_metadata = session_metadata or {}
        self._route_coverage_threshold = route_coverage_threshold

        self._headers = None
        self._user_agent = None
        self._app_id_verified = False
        self._job_start_time_provided = job_start_time is not None
        self._session_metadata_fields = None
        self._session_metadata_filters_resolved = False
        self._session_metadata_filters = None

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
            self._base_url + path,
            params=parameters,
            headers=self.teamserver_headers,
            verify=self._cert_file,
        )
        response.raise_for_status()
        return response

    def post_request(self, path, body, parameters={}):
        """Send a POST request to TeamServer."""
        self._output_helper.debug(f"POST {path} {parameters}")
        response = requests.post(
            self._base_url + path,
            params=parameters,
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
            self._app_id_verified = True
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

    @staticmethod
    def _normalize_metadata_key(key: str | None) -> str:
        """Normalize a metadata key/label so `branchName`, `Branch Name` and `branch_name` all match."""
        return "".join(filter(str.isalnum, key or "")).lower()

    def fetch_session_metadata_fields(self):
        """Fetch (and cache) the session metadata fields TeamServer knows about for this application."""
        if self._session_metadata_fields is None:
            response = self.get_request(f"metadata/session/{self.app_id}/filters")
            self._session_metadata_fields = response.json().get("filters") or []
            self._output_helper.debug(
                f"Session metadata fields: {self._session_metadata_fields}"
            )
        return self._session_metadata_fields

    def resolve_session_metadata(self):
        """
        Match each configured session metadata key to a TeamServer metadata field, by agent label or display label,
        where the field also has the configured value.
        :return: tuple of (list of (key, value, field) for matched pairs, list of unmatched keys)
        """
        fields = self.fetch_session_metadata_fields()
        resolved = []
        unresolved = []
        for key, value in self._session_metadata.items():
            normalized_key = self._normalize_metadata_key(key)
            field = next(
                (
                    field
                    for field in fields
                    if self._normalize_metadata_key(field.get("agentLabel"))
                    == normalized_key
                ),
                None,
            ) or next(
                (
                    field
                    for field in fields
                    if self._normalize_metadata_key(field.get("label"))
                    == normalized_key
                ),
                None,
            )
            field_values = {
                str(field_value.get("value"))
                for field_value in (field or {}).get("values") or []
            }
            if field and value in field_values:
                resolved.append((key, value, field))
            else:
                unresolved.append(key)
        return resolved, unresolved

    def session_metadata_filters(self):
        """
        Resolve (and cache) the configured session metadata for use as filters.
        If any key or value is not found in TeamServer, the session cannot be matched, so checks fall back to the whole application.
        :return: list of (key, value, field), or None if checks should consider the whole application
        """
        if not self._session_metadata_filters_resolved:
            self._session_metadata_filters_resolved = True
            if self._session_metadata:
                resolved, unresolved = self.resolve_session_metadata()
                if unresolved:
                    missing = ", ".join(
                        f"{key}={self._session_metadata[key]}" for key in unresolved
                    )
                    self._output_helper.warning(
                        f"Session metadata {missing} was not found for this application, checks will consider the whole application instead. Check the keys and values match the agent session_metadata configuration."
                    )
                else:
                    self._session_metadata_filters = resolved
        return self._session_metadata_filters

    @property
    def session_metadata_description(self):
        return ", ".join(
            f"{key}={value}" for key, value in self._session_metadata.items()
        )

    def fetch_session_metadata_vulnerability_count(self):
        """
        Count open vulnerabilities matching all configured session metadata (and other filters),
        or across the whole application if the session metadata could not be resolved.
        :return: number of matching open vulnerabilities
        """
        body = {
            "quickFilter": "OPEN",
            "severities": self._severities,
        }
        filters = self.session_metadata_filters()
        if filters is not None:
            body["metadataFilters"] = [
                {
                    "fieldID": (
                        int(field["id"]) if str(field["id"]).isdigit() else field["id"]
                    ),
                    "values": [value],
                }
                for _, value, field in filters
            ]
        if self._build_number:
            body["appVersionTags"] = [self._build_number]
        if self._job_start_time_provided:
            body["startDate"] = self._job_start_time
            body["timestampFilter"] = "FIRST"

        response = self.post_request(
            f"traces/{self.app_id}/filter",
            body,
            {"expand": "skip_links", "limit": 1},
        )
        result = response.json()
        self._output_helper.debug(result)
        return result["count"]

    def fetch_route_coverage(self):
        """
        Fetch route coverage for the application, filtered by session metadata if configured and resolved.
        :return: tuple of (exercised route count, total route count)
        """
        filters = self.session_metadata_filters()
        if filters is not None:
            body = {
                "metadata": [
                    {"label": field["label"], "values": [value]}
                    for _, value, field in filters
                ]
            }
            response = self.post_request(
                f"applications/{self.app_id}/route/filter",
                body,
                {"expand": "skip_links"},
            )
        else:
            response = self.get_request(
                f"applications/{self.app_id}/route", {"expand": "skip_links"}
            )

        result = response.json()
        self._output_helper.debug(result)
        routes = result.get("routes") or []
        total = result.get("count")
        if total is None:
            total = len(routes)
        exercised = result.get("exercisedCount", result.get("exercised_count"))
        if exercised is None:
            exercised = len(
                [
                    route
                    for route in routes
                    if route.get("status") == "EXERCISED" or route.get("exercised")
                ]
            )
        return exercised, total

    def verify_route_coverage(self):
        """
        Compare route coverage percentage against the configured minimum.
        :return: failure message, or None if the check passes
        """
        threshold = self._route_coverage_threshold
        if threshold is None:
            return None
        exercised, total = self.fetch_route_coverage()
        coverage = (exercised / total * 100) if total else 0.0
        scope = (
            f" for session metadata [{self.session_metadata_description}]"
            if self.session_metadata_filters() is not None
            else ""
        )
        summary = f"Route coverage{scope} is {coverage:.2f}% ({exercised} of {total} routes exercised)"
        if total == 0:
            self._output_helper.warning(
                "No routes were found, check that the application has been exercised with a Contrast agent."
            )
        if coverage < threshold:
            return f"{summary} - Contrast verify gate fails as this is below threshold (threshold requires {threshold:g}%)"
        self._output_helper.info(f"{summary} (meets threshold of {threshold:g}%)")
        return None

    def verify_session_metadata_vulnerabilities(self):
        """
        Compare the number of open vulnerabilities matching session metadata against the fail threshold.
        :return: failure message, or None if the check passes
        """
        self._output_helper.info(
            f"Session metadata provided [{self.session_metadata_description}], checking matching vulnerabilities against threshold (job outcome policies are not used)..."
        )
        open_vulnerabilities = self.fetch_session_metadata_vulnerability_count()
        if open_vulnerabilities > self._fail_threshold:
            return f"The vulnerability count is {open_vulnerabilities} - Contrast verify gate fails as this is above threshold (threshold allows {self._fail_threshold})"
        self._output_helper.info(
            f"The vulnerability count is {open_vulnerabilities} (below threshold)"
        )
        return None

    def verify_vulnerabilities(self):
        """
        Check the application against a matching job outcome policy, or the open vulnerability count if none match.
        :return: failure message, or None if the check passes
        """
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

            return f'Contrast verify gate fails with status {jop_outcome} - policy "{jop_name}"'
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
                return f"The vulnerability count is {open_vulnerabilities} - Contrast verify gate fails as this is above threshold (threshold allows {self._fail_threshold})"
            self._output_helper.info(
                f"The vulnerability count is {open_vulnerabilities} (below threshold)"
            )
        return None

    def verify_application(self):
        """Run all configured checks, marking the step failed if any of them fail."""
        if self._session_metadata:
            failures = [self.verify_session_metadata_vulnerabilities()]
        else:
            failures = [self.verify_vulnerabilities()]

        if self._route_coverage_threshold is not None:
            failures.append(self.verify_route_coverage())

        failures = [failure for failure in failures if failure]
        if len(failures) == 1:
            self._output_helper.set_failed(failures[0])
        elif failures:
            for failure in failures:
                self._output_helper.error(failure)
            self._output_helper.set_failed(
                f"Contrast verify gate fails - {len(failures)} checks failed"
            )
