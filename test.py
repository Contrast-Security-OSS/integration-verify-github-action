import contextlib
import io
import unittest

import responses
from responses import matchers

from verify import ContrastVerifyAction


class ActionTestCase(unittest.TestCase):
    def setUp(self):
        self._header_matcher = matchers.header_matcher(
            {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Api-Key": "An_Api_Key",
                "Authorization": "Base64Header",
            }
        )

        responses.add(
            responses.GET,
            "https://apptwo.contrastsecurity.com/api/ng/anOrgId/applications/name?filterText=VerifierTest",
            json={
                "applications": [
                    {"name": "VerifierTest", "app_id": "verifier_app_uuid"}
                ]
            },
        )

        self._action = ContrastVerifyAction(
            {
                "APP_NAME": "VerifierTest",
                "BASE_URL": "https://apptwo.contrastsecurity.com/api/ng/anOrgId/",
                "API_KEY": "An_Api_Key",
                "AUTHORIZATION": "Base64Header",
                "BUILD_NUMBER": "123",
                "FAIL_THRESHOLD": 0,
                "SEVERITIES": "HIGH,CRITICAL",
            }
        )

    @responses.activate
    def test_validate_connection_valid(self):
        responses.add(
            responses.GET,
            "https://apptwo.contrastsecurity.com/api/ng/anOrgId/profile/",
            json={},
            status=200,
            match=[self._header_matcher],
        )

        # it should succeed
        self._action.validate_connection()

    @responses.activate
    def test_validate_connection_invalid(self):
        responses.add(
            responses.GET,
            "https://apptwo.contrastsecurity.com/api/ng/anOrgId/profile/",
            status=403,
            match=[self._header_matcher],
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
    def test_determine_application_id_validate_exists(self):
        responses.add(
            responses.GET,
            "https://apptwo.contrastsecurity.com/api/ng/anOrgId/applications/an_app_uuid",
            json={},
            match=[self._header_matcher],
        )

        self._action = ContrastVerifyAction(
            {
                "APP_ID": "an_app_uuid",
                "BASE_URL": "https://apptwo.contrastsecurity.com/api/ng/anOrgId/",
                "API_KEY": "An_Api_Key",
                "AUTHORIZATION": "Base64Header",
                "BUILD_NUMBER": "123",
                "FAIL_THRESHOLD": 0,
                "SEVERITIES": "HIGH,CRITICAL",
            }
        )

        self._action.determine_application_id()

    @responses.activate
    def test_determine_application_id_validate_invalid(self):
        responses.add(
            responses.GET,
            "https://apptwo.contrastsecurity.com/api/ng/anOrgId/applications/an_app_uuid",
            status=403,
            match=[self._header_matcher],
        )

        self._action = ContrastVerifyAction(
            {
                "APP_ID": "an_app_uuid",
                "BASE_URL": "https://apptwo.contrastsecurity.com/api/ng/anOrgId/",
                "API_KEY": "An_Api_Key",
                "AUTHORIZATION": "Base64Header",
                "BUILD_NUMBER": "123",
                "FAIL_THRESHOLD": 0,
                "SEVERITIES": "HIGH,CRITICAL",
            }
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
            match=[self._header_matcher],
        )

        self._action = ContrastVerifyAction(
            {
                "APP_NAME": "NonExistentApp",
                "BASE_URL": "https://apptwo.contrastsecurity.com/api/ng/anOrgId/",
                "API_KEY": "An_Api_Key",
                "AUTHORIZATION": "Base64Header",
                "BUILD_NUMBER": "123",
                "FAIL_THRESHOLD": 0,
                "SEVERITIES": "HIGH,CRITICAL",
            }
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
                self._header_matcher,
                matchers.json_params_matcher(
                    {
                        "application_id": "verifier_app_uuid",
                        "security_check_filter": {
                            "app_version_tags": ["123"],
                            "query_by": "APP_VERSION_TAG",
                        },
                        "origin": "GitHub/Python",
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
                    },
                }
            },
            match=[
                self._header_matcher,
                matchers.json_params_matcher(
                    {
                        "application_id": "verifier_app_uuid",
                        "security_check_filter": {
                            "app_version_tags": ["123"],
                            "query_by": "APP_VERSION_TAG",
                        },
                        "origin": "GitHub/Python",
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
                    },
                }
            },
            match=[
                self._header_matcher,
                matchers.json_params_matcher(
                    {
                        "application_id": "verifier_app_uuid",
                        "security_check_filter": {
                            "app_version_tags": ["123"],
                            "query_by": "APP_VERSION_TAG",
                        },
                        "origin": "GitHub/Python",
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
        # it should log a useful message
        self.assertIn(
            'Contrast verify gate fails with status FAILED - policy "Test Job Outcome Policy"',
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
                self._header_matcher,
                matchers.json_params_matcher(
                    {
                        "application_id": "verifier_app_uuid",
                        "security_check_filter": {
                            "app_version_tags": ["123"],
                            "query_by": "APP_VERSION_TAG",
                        },
                        "origin": "GitHub/Python",
                    }
                ),
            ],
        )

        responses.add(
            responses.GET,
            "https://apptwo.contrastsecurity.com/api/ng/anOrgId/traces/verifier_app_uuid/quick",
            json={
                "filters": [
                    {"filterType": "ALL", "count": 12},
                    {"filterType": "OPEN", "count": 0},
                ]
            },
            match=[
                self._header_matcher,
                matchers.query_param_matcher(
                    {"severities": "HIGH,CRITICAL", "appVersionTags": "123"}
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
        responses.add(
            responses.POST,
            "https://apptwo.contrastsecurity.com/api/ng/anOrgId/securityChecks",
            status=200,
            json={"security_check": {"result": None}},
            match=[
                self._header_matcher,
                matchers.json_params_matcher(
                    {
                        "application_id": "verifier_app_uuid",
                        "security_check_filter": {
                            "app_version_tags": ["123"],
                            "query_by": "APP_VERSION_TAG",
                        },
                        "origin": "GitHub/Python",
                    }
                ),
            ],
        )

        responses.add(
            responses.GET,
            "https://apptwo.contrastsecurity.com/api/ng/anOrgId/traces/verifier_app_uuid/quick",
            json={
                "filters": [
                    {"filterType": "ALL", "count": 12},
                    {"filterType": "OPEN", "count": 7},
                ]
            },
            match=[
                self._header_matcher,
                matchers.query_param_matcher(
                    {"severities": "HIGH,CRITICAL", "appVersionTags": "123"}
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
            "The vulnerability count is 7 - Contrast verify gate fails as this is above threshold (threshold allows 0)",
            out.getvalue(),
        )


if __name__ == "__main__":
    unittest.main()
