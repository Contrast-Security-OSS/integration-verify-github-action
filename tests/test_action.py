import contextlib
import io
import os
import re
import unittest
from pathlib import Path

import responses
from responses import matchers

from contrastverify import ContrastVerifyAction
from version import __version__


class ActionTestCase(unittest.TestCase):
    def setUp(self):
        for key in ["CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE"]:
            if key in os.environ:
                del os.environ[key]

        os.environ["GITHUB_ACTIONS"] = "false"
        header_matcher = matchers.header_matcher(
            {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Api-Key": "An_Api_Key",
                "Authorization": "Base64Header",
            }
        )

        kwargs_matcher = matchers.request_kwargs_matcher({"verify": True})

        def user_agent_matcher(request):
            github_action_part = (
                "" if os.environ["GITHUB_ACTIONS"] == "false" else "-github-action"
            )  # user-agent should include github-action suffix when running in GitHub Actions environment, some tests will set this
            pattern = f"integration-verify{github_action_part}/{__version__} python-requests/.* python/.*"
            user_agent = request.headers.get("User-Agent")
            match = re.match(
                pattern,
                user_agent,
            )
            return [
                match,
                ""
                if match
                else f"User agent does not match '{pattern}', got '{user_agent}'",
            ]

        self._matchers = [header_matcher, kwargs_matcher, user_agent_matcher]
        self._origin = {"origin": f"integration-verify/{__version__}"}
        self._gh_origin = {"origin": f"integration-verify-github-action/{__version__}"}

        responses.add(
            responses.GET,
            "https://apptwo.contrastsecurity.com/api/ng/anOrgId/applications/name?filterText=VerifierTest",
            json={
                "applications": [
                    {"name": "VerifierTest", "app_id": "verifier_app_uuid"}
                ]
            },
        )

        responses.add(
            responses.POST,
            "https://apptwo.contrastsecurity.com/api/ng/anOrgId/traces/verifier_app_uuid/filter",
            json={
                "traces": [
                    {
                        "uuid": "1234-abcd",
                        "severity": "Critical",
                        "rule_name": "sqli",
                        "app_version_tags": [],
                    },
                    {
                        "uuid": "5678-efgh",
                        "severity": "High",
                        "rule_name": "xss",
                        "app_version_tags": [],
                    },
                    {
                        "uuid": "9012-ijkl",
                        "severity": "High",
                        "rule_name": "xss",
                        "app_version_tags": [],
                    },
                ],
                "count": 3,
            },
            match=[
                *self._matchers,
                matchers.query_param_matcher({"limit": 25, "offset": 0}),
                matchers.json_params_matcher(
                    {
                        "severities": ["HIGH", "CRITICAL"],
                        "appVersionTags": ["123"],
                        "timestampFilter": "FIRST",
                        "startDate": 0,
                        "quickFilter": "OPEN",
                    }
                ),
            ],
        )

        self._action = ContrastVerifyAction(
            app_id=None,
            app_name="VerifierTest",
            base_url="https://apptwo.contrastsecurity.com/api/ng/anOrgId/",
            baseline_build_number_regex=None,
            build_number="123",
            contrast_api_key="An_Api_Key",
            contrast_authorization="Base64Header",
            fail_threshold=0,
            job_start_time=None,
            severities=["HIGH", "CRITICAL"],
        )

    @responses.activate
    def test_validate_connection_valid(self):
        os.environ["GITHUB_ACTIONS"] = "true"
        responses.add(
            responses.GET,
            "https://apptwo.contrastsecurity.com/api/ng/anOrgId/profile/",
            json={},
            status=200,
            match=self._matchers,
        )

        # it should succeed
        self._action.validate_connection()

    @responses.activate
    def test_validate_connection_invalid(self):
        responses.add(
            responses.GET,
            "https://apptwo.contrastsecurity.com/api/ng/anOrgId/profile/",
            status=403,
            match=self._matchers,
        )

        out = io.StringIO()
        # it should quit
        with self.assertRaises(SystemExit) as cm:
            with contextlib.redirect_stdout(out):
                self._action.validate_connection()
        # it should exit non-zero
        self.assertEqual(cm.exception.code, 1)
        # it should log a useful message
        self.assertIn(
            "Connection test failed, please verify credentials (agent credentials will not work) -",
            out.getvalue(),
        )

    @responses.activate
    def test_validate_organization_valid(self):
        responses.add(
            responses.GET,
            "https://apptwo.contrastsecurity.com/api/ng/anOrgId/organizations/",
            json={},
            status=200,
            match=self._matchers,
        )

        # it should succeed
        self._action.validate_organization()

    @responses.activate
    def test_validate_organization_invalid(self):
        responses.add(
            responses.GET,
            "https://apptwo.contrastsecurity.com/api/ng/anOrgId/organizations/",
            status=403,
            match=self._matchers,
        )

        out = io.StringIO()
        # it should quit
        with self.assertRaises(SystemExit) as cm:
            with contextlib.redirect_stdout(out):
                self._action.validate_organization()
        # it should exit non-zero
        self.assertEqual(cm.exception.code, 1)
        # it should log a useful message
        self.assertIn(
            "Organization test failed, please verify organization ID and credentials (agent credentials will not work) -",
            out.getvalue(),
        )

    @responses.activate
    def test_determine_application_id_validate_exists(self):
        responses.add(
            responses.GET,
            "https://apptwo.contrastsecurity.com/api/ng/anOrgId/applications/an_app_uuid",
            json={},
            match=self._matchers,
        )

        self._action = ContrastVerifyAction(
            app_id="an_app_uuid",
            app_name=None,
            base_url="https://apptwo.contrastsecurity.com/api/ng/anOrgId/",
            baseline_build_number_regex=None,
            build_number="123",
            contrast_api_key="An_Api_Key",
            contrast_authorization="Base64Header",
            fail_threshold=0,
            job_start_time=None,
            severities=["HIGH", "CRITICAL"],
        )

        self._action.determine_application_id()

    @responses.activate
    def test_determine_application_id_validate_invalid(self):
        responses.add(
            responses.GET,
            "https://apptwo.contrastsecurity.com/api/ng/anOrgId/applications/an_app_uuid",
            status=403,
            match=self._matchers,
        )

        self._action = ContrastVerifyAction(
            app_id="an_app_uuid",
            app_name=None,
            base_url="https://apptwo.contrastsecurity.com/api/ng/anOrgId/",
            baseline_build_number_regex=None,
            build_number="123",
            contrast_api_key="An_Api_Key",
            contrast_authorization="Base64Header",
            fail_threshold=0,
            job_start_time=None,
            severities=["HIGH", "CRITICAL"],
        )

        out = io.StringIO()
        # it should quit
        with self.assertRaises(SystemExit) as cm:
            with contextlib.redirect_stdout(out):
                self._action.determine_application_id()
        # it should exit non-zero
        self.assertEqual(cm.exception.code, 1)
        # it should log a useful message
        self.assertIn(
            "Unable to find application with ID an_app_uuid - check the ID and ensure the user account this action uses can access it",
            out.getvalue(),
        )

    @responses.activate
    def test_determine_application_id_by_name_found(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self._action.determine_application_id()
        # it should log a useful message
        self.assertIn(
            'Application ID for "VerifierTest" is verifier_app_uuid',
            out.getvalue(),
        )

    @responses.activate
    def test_determine_application_id_by_name_not_found(self):
        responses.add(
            responses.GET,
            "https://apptwo.contrastsecurity.com/api/ng/anOrgId/applications/name?filterText=NonExistentApp",
            json={"applications": [{"name": "NonExactMatch", "app_id": "uuid"}]},
            match=self._matchers,
        )

        self._action = ContrastVerifyAction(
            app_id=None,
            app_name="NonExistentApp",
            base_url="https://apptwo.contrastsecurity.com/api/ng/anOrgId/",
            baseline_build_number_regex=None,
            build_number="123",
            contrast_api_key="An_Api_Key",
            contrast_authorization="Base64Header",
            fail_threshold=0,
            job_start_time=None,
            severities=["HIGH", "CRITICAL"],
        )

        out = io.StringIO()
        # it should quit
        with self.assertRaises(SystemExit) as cm:
            with contextlib.redirect_stdout(out):
                self._action.determine_application_id()
        # it should exit non-zero
        self.assertEqual(cm.exception.code, 1)
        # it should log a useful message
        self.assertIn(
            'Could not match one app with name "NonExistentApp", found 0, consider using APP_ID input instead.',
            out.getvalue(),
        )

    @responses.activate
    def test_verify_application_with_succeeding_job_outcome_policy(self):
        responses.add(
            responses.POST,
            "https://apptwo.contrastsecurity.com/api/ng/anOrgId/securityChecks",
            status=200,
            json={"security_check": {"result": True}},
            match=[
                *self._matchers,
                matchers.json_params_matcher(
                    {
                        "application_id": "verifier_app_uuid",
                        "job_start_time": 0,
                        "security_check_filter": {
                            "app_version_tags": ["123"],
                            "query_by": "APP_VERSION_TAG",
                        },
                        **self._origin,
                    }
                ),
            ],
        )

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self._action.verify_application()
        # it should log a useful message
        self.assertIn(
            "Step passes matching policy",
            out.getvalue(),
        )

    @responses.activate
    def test_verify_application_with_failing_job_outcome_policy(self):
        responses.add(
            responses.POST,
            "https://apptwo.contrastsecurity.com/api/ng/anOrgId/securityChecks",
            status=200,
            json={
                "security_check": {
                    "result": False,
                    "job_outcome_policy": {
                        "outcome": "FAILED",
                        "name": "Test Job Outcome Policy",
                        "opt_into_query": True,
                        "is_job_start_time": True,
                    },
                }
            },
            match=[
                *self._matchers,
                matchers.json_params_matcher(
                    {
                        "application_id": "verifier_app_uuid",
                        "job_start_time": 0,
                        "security_check_filter": {
                            "app_version_tags": ["123"],
                            "query_by": "APP_VERSION_TAG",
                        },
                        **self._origin,
                    }
                ),
            ],
        )

        out = io.StringIO()
        # it should quit
        with self.assertRaises(SystemExit) as cm:
            with contextlib.redirect_stdout(out):
                self._action.verify_application()
        # it should exit non-zero
        self.assertEqual(cm.exception.code, 1)
        # it should log a useful message
        self.assertIn(
            'Contrast verify gate fails with status FAILED - policy "Test Job Outcome Policy"',
            out.getvalue(),
        )

    @responses.activate
    def test_verify_application_with_failing_job_outcome_policy_ignoring_build_version(
        self,
    ):
        responses.add(
            responses.POST,
            "https://apptwo.contrastsecurity.com/api/ng/anOrgId/securityChecks",
            status=200,
            json={
                "security_check": {
                    "result": False,
                    "job_outcome_policy": {
                        "outcome": "FAILED",
                        "name": "Test Job Outcome Policy",
                        "opt_into_query": False,
                        "is_job_start_time": True,
                    },
                }
            },
            match=[
                *self._matchers,
                matchers.json_params_matcher(
                    {
                        "application_id": "verifier_app_uuid",
                        "job_start_time": 0,
                        "security_check_filter": {
                            "app_version_tags": ["123"],
                            "query_by": "APP_VERSION_TAG",
                        },
                        **self._origin,
                    }
                ),
            ],
        )

        out = io.StringIO()
        # it should quit
        with self.assertRaises(SystemExit) as cm:
            with contextlib.redirect_stdout(out):
                self._action.verify_application()
        # it should exit non-zero
        self.assertEqual(cm.exception.code, 1)
        # it should warn that all vulnerabilities are being considered
        self.assertIn(
            'Matching policy "Test Job Outcome Policy" is not configured to apply the "query vulnerabilities by selection from the plugin when filtering vulnerabilities" option, this means all open vulnerabilities will be considered, not just those from the build_number input.',
            out.getvalue(),
        )
        self.assertIn(
            'Matching policy "Test Job Outcome Policy" has job start time configured, but no job start time was provided, so 0 was passed to consider all open vulnerabilities.',
            out.getvalue(),
        )
        # it should log a useful message
        self.assertIn(
            'Contrast verify gate fails with status FAILED - policy "Test Job Outcome Policy"',
            out.getvalue(),
        )

    @responses.activate
    def test_verify_application_with_blank_build_number_succeeding_job_outcome_policy(
        self,
    ):
        # Mainly want to verify that if build_number is blank, an empty array is sent rather than [""]
        responses.add(
            responses.POST,
            "https://apptwo.contrastsecurity.com/api/ng/anOrgId/securityChecks",
            status=200,
            json={"security_check": {"result": True}},
            match=[
                *self._matchers,
                matchers.json_params_matcher(
                    {
                        "application_id": "verifier_app_uuid",
                        "job_start_time": 0,
                        "security_check_filter": {
                            "app_version_tags": [],
                            "query_by": "APP_VERSION_TAG",
                        },
                        **self._origin,
                    }
                ),
            ],
        )

        responses.replace(
            responses.POST,
            "https://apptwo.contrastsecurity.com/api/ng/anOrgId/traces/verifier_app_uuid/filter",
            json={
                "traces": [
                    {
                        "uuid": "1234-abcd",
                        "severity": "Critical",
                        "rule_name": "sqli",
                        "app_version_tags": [],
                    },
                    {
                        "uuid": "5678-efgh",
                        "severity": "High",
                        "rule_name": "xss",
                        "app_version_tags": [],
                    },
                    {
                        "uuid": "9012-ijkl",
                        "severity": "High",
                        "rule_name": "xss",
                        "app_version_tags": [],
                    },
                ],
                "count": 3,
            },
            match=[
                *self._matchers,
                matchers.query_param_matcher({"limit": 25, "offset": 0}),
                matchers.json_params_matcher(
                    {
                        "severities": ["HIGH", "CRITICAL"],
                        "timestampFilter": "FIRST",
                        "startDate": 0,
                        "quickFilter": "OPEN",
                    }
                ),
            ],
        )

        self._action = ContrastVerifyAction(
            app_id=None,
            app_name="VerifierTest",
            base_url="https://apptwo.contrastsecurity.com/api/ng/anOrgId/",
            baseline_build_number_regex=None,
            build_number="",
            contrast_api_key="An_Api_Key",
            contrast_authorization="Base64Header",
            fail_threshold=0,
            job_start_time=None,
            severities=["HIGH", "CRITICAL"],
        )

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self._action.verify_application()
        # it should log a useful message
        self.assertIn(
            "Step passes matching policy",
            out.getvalue(),
        )

    @responses.activate
    def test_verify_application_with_no_job_outcome_policy_below_threshold(
        self,
    ):
        responses.add(
            responses.POST,
            "https://apptwo.contrastsecurity.com/api/ng/anOrgId/securityChecks",
            status=200,
            json={"security_check": {"result": None}},
            match=[
                *self._matchers,
                matchers.json_params_matcher(
                    {
                        "application_id": "verifier_app_uuid",
                        "job_start_time": 0,
                        "security_check_filter": {
                            "app_version_tags": ["123"],
                            "query_by": "APP_VERSION_TAG",
                        },
                        **self._origin,
                    }
                ),
            ],
        )

        responses.replace(
            responses.POST,
            "https://apptwo.contrastsecurity.com/api/ng/anOrgId/traces/verifier_app_uuid/filter",
            json={
                "traces": [],
                "count": 0,
            },
            match=[
                *self._matchers,
                matchers.query_param_matcher({"limit": 25, "offset": 0}),
                matchers.json_params_matcher(
                    {
                        "severities": ["HIGH", "CRITICAL"],
                        "appVersionTags": ["123"],
                        "timestampFilter": "FIRST",
                        "startDate": 0,
                        "quickFilter": "OPEN",
                    }
                ),
            ],
        )

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self._action.verify_application()
        # it should log useful messages
        self.assertIn(
            "No matching job outcome policy, checking vulnerabilities against threshold...",
            out.getvalue(),
        )
        self.assertIn("The vulnerability count is 0 (below threshold)", out.getvalue())

    @responses.activate
    def test_verify_application_with_no_job_outcome_policy_above_threshold(
        self,
    ):
        os.environ["GITHUB_ACTIONS"] = "true"
        responses.add(
            responses.POST,
            "https://apptwo.contrastsecurity.com/api/ng/anOrgId/securityChecks",
            status=200,
            json={"security_check": {"result": None}},
            match=[
                *self._matchers,
                matchers.json_params_matcher(
                    {
                        "application_id": "verifier_app_uuid",
                        "job_start_time": 0,
                        "security_check_filter": {
                            "app_version_tags": ["123"],
                            "query_by": "APP_VERSION_TAG",
                        },
                        **self._gh_origin,
                    }
                ),
            ],
        )

        out = io.StringIO()
        # it should quit
        with self.assertRaises(SystemExit) as cm:
            with contextlib.redirect_stdout(out):
                self._action.verify_application()
        # it should exit non-zero
        self.assertEqual(cm.exception.code, 1)
        # it should log useful messages
        self.assertIn(
            "No matching job outcome policy, checking vulnerabilities against threshold...",
            out.getvalue(),
        )
        self.assertIn(
            "The vulnerability count is 3 - Contrast verify gate fails as this is above threshold (threshold allows 0)",
            out.getvalue(),
        )

    @responses.activate
    def test_custom_ca_certificate_verification(
        self,
    ):
        cert_path = "/path/to/user_provided_ca_cert.pem"
        self._action = ContrastVerifyAction(
            app_id=None,
            app_name="CustomCertTest",
            baseline_build_number_regex=None,
            base_url="https://apptwo.contrastsecurity.com/api/ng/anOrgId/",
            build_number="123",
            contrast_api_key="An_Api_Key",
            contrast_authorization="Base64Header",
            fail_threshold=0,
            job_start_time=None,
            severities=["HIGH", "CRITICAL"],
            cert_file=Path(cert_path),
        )

        self._matchers[1] = matchers.request_kwargs_matcher({"verify": cert_path})

        responses.add(
            responses.GET,
            "https://apptwo.contrastsecurity.com/api/ng/anOrgId/applications/name?filterText=CustomCertTest",
            json={
                "applications": [
                    {"name": "CustomCertTest", "app_id": "verifier_app_uuid"}
                ]
            },
            match=self._matchers,
        )

        responses.add(
            responses.POST,
            "https://apptwo.contrastsecurity.com/api/ng/anOrgId/securityChecks",
            status=200,
            json={"security_check": {"result": None}},
            match=[
                *self._matchers,
                matchers.json_params_matcher(
                    {
                        "application_id": "verifier_app_uuid",
                        "job_start_time": 0,
                        "security_check_filter": {
                            "app_version_tags": ["123"],
                            "query_by": "APP_VERSION_TAG",
                        },
                        **self._origin,
                    }
                ),
            ],
        )

        responses.replace(
            responses.POST,
            "https://apptwo.contrastsecurity.com/api/ng/anOrgId/traces/verifier_app_uuid/filter",
            json={
                "traces": [
                    {
                        "uuid": "1234-abcd",
                        "severity": "Critical",
                        "rule_name": "sqli",
                        "app_version_tags": [],
                    },
                    {
                        "uuid": "5678-efgh",
                        "severity": "High",
                        "rule_name": "xss",
                        "app_version_tags": [],
                    },
                    {
                        "uuid": "9012-ijkl",
                        "severity": "High",
                        "rule_name": "xss",
                        "app_version_tags": [],
                    },
                ],
                "count": 3,
            },
            match=[
                *self._matchers,
                matchers.query_param_matcher({"limit": 25, "offset": 0}),
                matchers.json_params_matcher(
                    {
                        "severities": ["HIGH", "CRITICAL"],
                        "appVersionTags": ["123"],
                        "timestampFilter": "FIRST",
                        "startDate": 0,
                        "quickFilter": "OPEN",
                    }
                ),
            ],
        )

        out = io.StringIO()
        # it should quit
        with self.assertRaises(SystemExit) as cm:
            with contextlib.redirect_stdout(out):
                self._action.verify_application()
        # it should exit non-zero
        self.assertEqual(cm.exception.code, 1)
        # it should log useful messages
        self.assertIn(
            "No matching job outcome policy, checking vulnerabilities against threshold...",
            out.getvalue(),
        )
        self.assertIn(
            "The vulnerability count is 3 - Contrast verify gate fails as this is above threshold (threshold allows 0)",
            out.getvalue(),
        )


if __name__ == "__main__":
    unittest.main()
