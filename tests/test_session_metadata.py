import contextlib
import io
import os
import unittest

import responses
from responses import matchers

from contrastverify import ContrastVerifyAction

BASE_URL = "https://apptwo.contrastsecurity.com/api/ng/anOrgId/"
METADATA_FILTERS_URL = f"{BASE_URL}metadata/session/verifier_app_uuid/filters"
TRACES_FILTER_URL = f"{BASE_URL}traces/verifier_app_uuid/filter"
ROUTE_FILTER_URL = f"{BASE_URL}applications/verifier_app_uuid/route/filter"
ROUTE_URL = f"{BASE_URL}applications/verifier_app_uuid/route"
SECURITY_CHECKS_URL = f"{BASE_URL}securityChecks"


class SessionMetadataTestCase(unittest.TestCase):
    def setUp(self):
        os.environ["GITHUB_ACTIONS"] = "false"
        self._matchers = [
            matchers.header_matcher(
                {
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "Api-Key": "An_Api_Key",
                    "Authorization": "Base64Header",
                }
            ),
        ]

    def create_action(self, **kwargs):
        args = {
            "app_id": None,
            "app_name": "VerifierTest",
            "base_url": BASE_URL,
            "build_number": "",
            "contrast_api_key": "An_Api_Key",
            "contrast_authorization": "Base64Header",
            "fail_threshold": 0,
            "job_start_time": None,
            "severities": ["CRITICAL", "HIGH"],
            "session_metadata": {"branchName": "main", "commitHash": "abc123"},
        }
        args.update(kwargs)
        return ContrastVerifyAction(**args)

    def add_common_responses(self):
        responses.add(
            responses.GET,
            f"{BASE_URL}applications/name?filterText=VerifierTest",
            json={
                "applications": [
                    {"name": "VerifierTest", "app_id": "verifier_app_uuid"}
                ]
            },
        )
        responses.add(
            responses.GET,
            METADATA_FILTERS_URL,
            json={
                "success": True,
                "filters": [
                    {
                        "id": "11",
                        "label": "Branch Name",
                        "agentLabel": "branchName",
                        "values": [{"value": "main", "count": 3}],
                    },
                    # older TeamServer versions may not return agentLabel, so display label is matched
                    {
                        "id": "12",
                        "label": "Commit Hash",
                        "values": [{"value": "abc123", "count": 3}],
                    },
                ],
            },
            match=self._matchers,
        )

    def add_traces_filter_response(self, count, body):
        responses.add(
            responses.POST,
            TRACES_FILTER_URL,
            json={"success": True, "count": count, "traces": []},
            match=[
                *self._matchers,
                matchers.query_param_matcher({"expand": "skip_links", "limit": "1"}),
                matchers.json_params_matcher(body),
            ],
        )

    def run_verify(self, action):
        out = io.StringIO()
        exit_code = None
        with contextlib.redirect_stdout(out):
            try:
                action.verify_application()
            except SystemExit as e:
                exit_code = e.code
        return exit_code, out.getvalue()

    @responses.activate
    def test_session_metadata_vulnerabilities_below_threshold(self):
        self.add_common_responses()
        self.add_traces_filter_response(
            0,
            {
                "quickFilter": "OPEN",
                "severities": ["CRITICAL", "HIGH"],
                "metadataFilters": [
                    {"fieldID": 11, "values": ["main"]},
                    {"fieldID": 12, "values": ["abc123"]},
                ],
            },
        )

        exit_code, output = self.run_verify(self.create_action())

        self.assertIsNone(exit_code)
        self.assertIn(
            "Session metadata provided [branchName=main, commitHash=abc123]", output
        )
        self.assertIn("The vulnerability count is 0 (below threshold)", output)
        # job outcome policies must not be checked when session metadata is provided
        self.assertFalse(
            any(call.request.url == SECURITY_CHECKS_URL for call in responses.calls)
        )

    @responses.activate
    def test_session_metadata_vulnerabilities_above_threshold_with_filters(self):
        self.add_common_responses()
        self.add_traces_filter_response(
            5,
            {
                "quickFilter": "OPEN",
                "severities": ["CRITICAL"],
                "metadataFilters": [
                    {"fieldID": 11, "values": ["main"]},
                    {"fieldID": 12, "values": ["abc123"]},
                ],
                "appVersionTags": ["123"],
                "startDate": 1000,
                "timestampFilter": "FIRST",
            },
        )

        exit_code, output = self.run_verify(
            self.create_action(
                build_number="123",
                job_start_time=1000,
                severities=["CRITICAL"],
                fail_threshold=2,
            )
        )

        self.assertEqual(exit_code, 1)
        self.assertIn(
            "The vulnerability count is 5 - Contrast verify gate fails as this is above threshold (threshold allows 2)",
            output,
        )

    @responses.activate
    def test_session_metadata_unknown_field_checks_whole_application(self):
        self.add_common_responses()
        # no metadataFilters, so all open vulnerabilities in the application are counted
        self.add_traces_filter_response(
            3, {"quickFilter": "OPEN", "severities": ["CRITICAL", "HIGH"]}
        )

        exit_code, output = self.run_verify(
            self.create_action(session_metadata={"repository": "my-repo"})
        )

        self.assertEqual(exit_code, 1)
        self.assertIn(
            "Session metadata repository=my-repo was not found for this application, checks will consider the whole application instead",
            output,
        )
        self.assertIn(
            "The vulnerability count is 3 - Contrast verify gate fails as this is above threshold (threshold allows 0)",
            output,
        )

    @responses.activate
    def test_session_metadata_unknown_value_checks_whole_application(self):
        self.add_common_responses()
        self.add_traces_filter_response(
            0, {"quickFilter": "OPEN", "severities": ["CRITICAL", "HIGH"]}
        )

        exit_code, output = self.run_verify(
            self.create_action(
                session_metadata={"branchName": "feature-x", "commitHash": "abc123"}
            )
        )

        self.assertIsNone(exit_code)
        self.assertIn(
            "Session metadata branchName=feature-x was not found for this application, checks will consider the whole application instead",
            output,
        )
        self.assertIn("The vulnerability count is 0 (below threshold)", output)
        # job outcome policies are still not used when session metadata is provided
        self.assertFalse(
            any(call.request.url == SECURITY_CHECKS_URL for call in responses.calls)
        )

    @responses.activate
    def test_route_coverage_with_session_metadata_meets_threshold(self):
        self.add_common_responses()
        self.add_traces_filter_response(
            0,
            {
                "quickFilter": "OPEN",
                "severities": ["CRITICAL", "HIGH"],
                "metadataFilters": [
                    {"fieldID": 11, "values": ["main"]},
                    {"fieldID": 12, "values": ["abc123"]},
                ],
            },
        )
        responses.add(
            responses.POST,
            ROUTE_FILTER_URL,
            json={"success": True, "count": 4, "exercisedCount": 3, "routes": []},
            match=[
                *self._matchers,
                matchers.query_param_matcher({"expand": "skip_links"}),
                matchers.json_params_matcher(
                    {
                        "metadata": [
                            {"label": "Branch Name", "values": ["main"]},
                            {"label": "Commit Hash", "values": ["abc123"]},
                        ]
                    }
                ),
            ],
        )

        exit_code, output = self.run_verify(
            self.create_action(route_coverage_threshold=75)
        )

        self.assertIsNone(exit_code)
        self.assertIn(
            "Route coverage for session metadata [branchName=main, commitHash=abc123] is 75.00% (3 of 4 routes exercised) (meets threshold of 75%)",
            output,
        )

    @responses.activate
    def test_route_coverage_and_vulnerabilities_both_fail(self):
        self.add_common_responses()
        self.add_traces_filter_response(
            1,
            {
                "quickFilter": "OPEN",
                "severities": ["CRITICAL", "HIGH"],
                "metadataFilters": [{"fieldID": 11, "values": ["main"]}],
            },
        )
        responses.add(
            responses.POST,
            ROUTE_FILTER_URL,
            json={
                "success": True,
                "routes": [
                    {"status": "EXERCISED", "exercised": 1700000000000},
                    {"status": "DISCOVERED", "exercised": None},
                    {"status": "DISCOVERED", "exercised": None},
                ],
            },
            match=self._matchers,
        )

        exit_code, output = self.run_verify(
            self.create_action(
                session_metadata={"branchName": "main"},
                route_coverage_threshold=50,
            )
        )

        self.assertEqual(exit_code, 1)
        self.assertIn(
            "The vulnerability count is 1 - Contrast verify gate fails", output
        )
        self.assertIn(
            "Route coverage for session metadata [branchName=main] is 33.33% (1 of 3 routes exercised) - Contrast verify gate fails as this is below threshold (threshold requires 50%)",
            output,
        )
        self.assertIn("Contrast verify gate fails - 2 checks failed", output)

    @responses.activate
    def test_route_coverage_without_session_metadata(self):
        self.add_common_responses()
        responses.add(
            responses.POST,
            SECURITY_CHECKS_URL,
            json={"security_check": {"result": True}},
            match=self._matchers,
        )
        responses.add(
            responses.GET,
            ROUTE_URL,
            json={"success": True, "count": 0, "exercised_count": 0, "routes": []},
            match=[
                *self._matchers,
                matchers.query_param_matcher({"expand": "skip_links"}),
            ],
        )

        exit_code, output = self.run_verify(
            self.create_action(session_metadata=None, route_coverage_threshold=10)
        )

        self.assertEqual(exit_code, 1)
        self.assertIn("Step passes matching policy", output)
        self.assertIn("No routes were found", output)
        self.assertIn(
            "Route coverage is 0.00% (0 of 0 routes exercised) - Contrast verify gate fails as this is below threshold (threshold requires 10%)",
            output,
        )

    @responses.activate
    def test_route_coverage_unknown_metadata_value_checks_whole_application(self):
        self.add_common_responses()
        self.add_traces_filter_response(
            0, {"quickFilter": "OPEN", "severities": ["CRITICAL", "HIGH"]}
        )
        responses.add(
            responses.GET,
            ROUTE_URL,
            json={"success": True, "count": 4, "exercisedCount": 1},
            match=[
                *self._matchers,
                matchers.query_param_matcher({"expand": "skip_links"}),
            ],
        )

        exit_code, output = self.run_verify(
            self.create_action(
                session_metadata={"branchName": "feature-x"},
                route_coverage_threshold=20,
            )
        )

        self.assertIsNone(exit_code)
        # the warning is only logged once, even though both checks use session metadata
        self.assertEqual(
            output.count("Session metadata branchName=feature-x was not found"), 1
        )
        self.assertIn(
            "Route coverage is 25.00% (1 of 4 routes exercised) (meets threshold of 20%)",
            output,
        )
        self.assertFalse(
            any(
                (call.request.url or "").startswith(ROUTE_FILTER_URL)
                for call in responses.calls
            )
        )
