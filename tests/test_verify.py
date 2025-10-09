#!/usr/bin/env python3
import os
import unittest
from base64 import b64encode

import verify
from contrastverify.helpers.input_output_helpers import OutputHelper


class TestValidateInputs(unittest.TestCase):
    """Test cases for the validate_inputs function."""

    def setUp(self):
        """Set up test environment before each test."""
        # Clear environment variables
        env_vars_to_clear = [
            "API_KEY",
            "ORG_ID",
            "AUTH_HEADER",
            "USER_NAME",
            "SERVICE_KEY",
            "APP_ID",
            "APP_NAME",
            "API_URL",
            "JOB_START_TIME",
            "SEVERITIES",
            "FAIL_THRESHOLD",
            "BUILD_NUMBER",
            "CA_FILE",
            "INPUT_APIKEY",
            "INPUT_ORGID",
            "INPUT_AUTHHEADER",
            "INPUT_USERNAME",
            "INPUT_SERVICEKEY",
            "INPUT_APPID",
            "INPUT_APPNAME",
            "INPUT_APIURL",
            "INPUT_JOBSTARTTIME",
            "INPUT_SEVERITIES",
            "INPUT_FAILTHRESHOLD",
            "INPUT_BUILDNUMBER",
            "INPUT_CAFILE",
            "CONTRAST_API_KEY",
            "CONTRAST_ORG_ID",
            "CONTRAST_AUTH_HEADER",
            "CONTRAST_USER_NAME",
            "CONTRAST_SERVICE_KEY",
            "CONTRAST_APP_ID",
            "CONTRAST_APP_NAME",
            "CONTRAST_API_URL",
            "CONTRAST_JOB_START_TIME",
            "CONTRAST_SEVERITIES",
            "CONTRAST_FAIL_THRESHOLD",
            "CONTRAST_BUILD_NUMBER",
            "CONTRAST_CA_FILE",
        ]
        for var in env_vars_to_clear:
            if var in os.environ:
                del os.environ[var]

    def test_validate_inputs_all_required_params_provided(self):
        """Test validate_inputs with all required parameters provided."""
        os.environ["API_KEY"] = "test_api_key"
        os.environ["ORG_ID"] = "test_org_id"
        os.environ["AUTH_HEADER"] = "test_auth_header"
        os.environ["APP_ID"] = "test_app_id"

        output_helper = OutputHelper()
        config = verify.validate_inputs(output_helper)

        self.assertEqual(config["API_KEY"], "test_api_key")
        self.assertEqual(config["ORG_ID"], "test_org_id")
        self.assertEqual(config["AUTHORIZATION"], "test_auth_header")
        self.assertEqual(config["APP_ID"], "test_app_id")
        self.assertEqual(
            config["BASE_URL"],
            "https://app.contrastsecurity.com/Contrast/api/ng/test_org_id/",
        )
        self.assertEqual(config["SEVERITIES"], ["CRITICAL", "HIGH"])
        self.assertEqual(config["FAIL_THRESHOLD"], 0)

    def test_validate_inputs_with_username_and_service_key(self):
        """Test validate_inputs using username and service key instead of auth header."""
        os.environ["API_KEY"] = "test_api_key"
        os.environ["ORG_ID"] = "test_org_id"
        os.environ["USER_NAME"] = "test_user"
        os.environ["SERVICE_KEY"] = "test_service_key"
        os.environ["APP_NAME"] = "test_app_name"

        output_helper = OutputHelper()
        config = verify.validate_inputs(output_helper)

        expected_auth = str(
            b64encode(bytes("test_user:test_service_key", "UTF-8")), "UTF-8"
        )
        self.assertEqual(config["AUTHORIZATION"], expected_auth)
        self.assertEqual(config["APP_NAME"], "test_app_name")

    def test_validate_inputs_with_app_name_instead_of_app_id(self):
        """Test validate_inputs using app name instead of app ID."""
        os.environ["API_KEY"] = "test_api_key"
        os.environ["ORG_ID"] = "test_org_id"
        os.environ["AUTH_HEADER"] = "test_auth_header"
        os.environ["APP_NAME"] = "test_app_name"

        output_helper = OutputHelper()
        config = verify.validate_inputs(output_helper)

        self.assertEqual(config["APP_NAME"], "test_app_name")
        self.assertNotIn("APP_ID", config)

    def test_validate_inputs_with_custom_api_url(self):
        """Test validate_inputs with custom API URL."""
        os.environ["API_KEY"] = "test_api_key"
        os.environ["ORG_ID"] = "test_org_id"
        os.environ["AUTH_HEADER"] = "test_auth_header"
        os.environ["APP_ID"] = "test_app_id"
        os.environ["API_URL"] = "https://custom.contrastsecurity.com/Contrast/api/ng/"

        output_helper = OutputHelper()
        config = verify.validate_inputs(output_helper)

        self.assertEqual(
            config["BASE_URL"],
            "https://custom.contrastsecurity.com/Contrast/api/ng/test_org_id/",
        )

    def test_validate_inputs_with_custom_api_url_without_path(self):
        """Test validate_inputs with custom API URL that needs path correction."""
        os.environ["API_KEY"] = "test_api_key"
        os.environ["ORG_ID"] = "test_org_id"
        os.environ["AUTH_HEADER"] = "test_auth_header"
        os.environ["APP_ID"] = "test_app_id"
        os.environ["API_URL"] = "https://custom.contrastsecurity.com"

        output_helper = OutputHelper()
        config = verify.validate_inputs(output_helper)

        self.assertEqual(
            config["BASE_URL"],
            "https://custom.contrastsecurity.com/Contrast/api/ng/test_org_id/",
        )

    def test_validate_inputs_with_job_start_time(self):
        """Test validate_inputs with job start time."""
        os.environ["API_KEY"] = "test_api_key"
        os.environ["ORG_ID"] = "test_org_id"
        os.environ["AUTH_HEADER"] = "test_auth_header"
        os.environ["APP_ID"] = "test_app_id"
        os.environ["JOB_START_TIME"] = "1234567890"

        output_helper = OutputHelper()
        config = verify.validate_inputs(output_helper)

        self.assertEqual(config["JOB_START_TIME"], 1234567890)

    def test_validate_inputs_with_custom_severities(self):
        """Test validate_inputs with custom severities."""
        os.environ["API_KEY"] = "test_api_key"
        os.environ["ORG_ID"] = "test_org_id"
        os.environ["AUTH_HEADER"] = "test_auth_header"
        os.environ["APP_ID"] = "test_app_id"
        os.environ["SEVERITIES"] = "CRITICAL,HIGH,MEDIUM"

        output_helper = OutputHelper()
        config = verify.validate_inputs(output_helper)

        self.assertEqual(config["SEVERITIES"], ["CRITICAL", "HIGH", "MEDIUM"])

    def test_validate_inputs_with_custom_fail_threshold(self):
        """Test validate_inputs with custom fail threshold."""
        os.environ["API_KEY"] = "test_api_key"
        os.environ["ORG_ID"] = "test_org_id"
        os.environ["AUTH_HEADER"] = "test_auth_header"
        os.environ["APP_ID"] = "test_app_id"
        os.environ["FAIL_THRESHOLD"] = "5"

        output_helper = OutputHelper()
        config = verify.validate_inputs(output_helper)

        self.assertEqual(config["FAIL_THRESHOLD"], 5)

    def test_validate_inputs_with_build_number(self):
        """Test validate_inputs with build number."""
        os.environ["API_KEY"] = "test_api_key"
        os.environ["ORG_ID"] = "test_org_id"
        os.environ["AUTH_HEADER"] = "test_auth_header"
        os.environ["APP_ID"] = "test_app_id"
        os.environ["BUILD_NUMBER"] = "build-123"

        output_helper = OutputHelper()
        config = verify.validate_inputs(output_helper)

        self.assertEqual(config["BUILD_NUMBER"], "build-123")

    def test_validate_inputs_missing_api_key(self):
        """Test validate_inputs fails when API key is missing."""
        os.environ["ORG_ID"] = "test_org_id"
        os.environ["AUTH_HEADER"] = "test_auth_header"
        os.environ["APP_ID"] = "test_app_id"

        output_helper = OutputHelper()

        with self.assertRaises(SystemExit) as cm:
            verify.validate_inputs(output_helper)

        self.assertEqual(cm.exception.code, 1)

    def test_validate_inputs_missing_org_id(self):
        """Test validate_inputs fails when organization ID is missing."""
        os.environ["API_KEY"] = "test_api_key"
        os.environ["AUTH_HEADER"] = "test_auth_header"
        os.environ["APP_ID"] = "test_app_id"

        output_helper = OutputHelper()

        with self.assertRaises(SystemExit) as cm:
            verify.validate_inputs(output_helper)

        self.assertEqual(cm.exception.code, 1)

    def test_validate_inputs_missing_auth_credentials(self):
        """Test validate_inputs fails when neither auth header nor username/service key is provided."""
        os.environ["API_KEY"] = "test_api_key"
        os.environ["ORG_ID"] = "test_org_id"
        os.environ["APP_ID"] = "test_app_id"

        output_helper = OutputHelper()

        with self.assertRaises(SystemExit) as cm:
            verify.validate_inputs(output_helper)

        self.assertEqual(cm.exception.code, 1)

    def test_validate_inputs_missing_app_identifier(self):
        """Test validate_inputs fails when neither app ID nor app name is provided."""
        os.environ["API_KEY"] = "test_api_key"
        os.environ["ORG_ID"] = "test_org_id"
        os.environ["AUTH_HEADER"] = "test_auth_header"

        output_helper = OutputHelper()

        with self.assertRaises(SystemExit) as cm:
            verify.validate_inputs(output_helper)

        self.assertEqual(cm.exception.code, 1)

    def test_validate_inputs_invalid_api_url_protocol(self):
        """Test validate_inputs fails when API URL doesn't start with http(s)://."""
        os.environ["API_KEY"] = "test_api_key"
        os.environ["ORG_ID"] = "test_org_id"
        os.environ["AUTH_HEADER"] = "test_auth_header"
        os.environ["APP_ID"] = "test_app_id"
        os.environ["API_URL"] = "ftp://invalid.url.com"

        output_helper = OutputHelper()

        with self.assertRaises(SystemExit) as cm:
            verify.validate_inputs(output_helper)

        self.assertEqual(cm.exception.code, 1)

    def test_validate_inputs_invalid_job_start_time(self):
        """Test validate_inputs fails when job start time is not a valid number."""
        os.environ["API_KEY"] = "test_api_key"
        os.environ["ORG_ID"] = "test_org_id"
        os.environ["AUTH_HEADER"] = "test_auth_header"
        os.environ["APP_ID"] = "test_app_id"
        os.environ["JOB_START_TIME"] = "not_a_number"

        output_helper = OutputHelper()

        with self.assertRaises(SystemExit) as cm:
            verify.validate_inputs(output_helper)

        self.assertEqual(cm.exception.code, 1)

    def test_validate_inputs_empty_string_values(self):
        """Test validate_inputs handles empty string values correctly."""
        os.environ["API_KEY"] = ""
        os.environ["ORG_ID"] = "test_org_id"
        os.environ["AUTH_HEADER"] = "test_auth_header"
        os.environ["APP_ID"] = "test_app_id"

        output_helper = OutputHelper()

        with self.assertRaises(SystemExit) as cm:
            verify.validate_inputs(output_helper)

        self.assertEqual(cm.exception.code, 1)

    def test_validate_inputs_partial_username_service_key(self):
        """Test validate_inputs fails when only username or service key is provided."""
        os.environ["API_KEY"] = "test_api_key"
        os.environ["ORG_ID"] = "test_org_id"
        os.environ["USER_NAME"] = "test_user"
        # Missing SERVICE_KEY
        os.environ["APP_ID"] = "test_app_id"

        output_helper = OutputHelper()

        with self.assertRaises(SystemExit) as cm:
            verify.validate_inputs(output_helper)

        self.assertEqual(cm.exception.code, 1)

    def test_validate_inputs_multiple_errors(self):
        """Test validate_inputs reports multiple missing parameters."""
        # Missing multiple required parameters
        output_helper = OutputHelper()

        with self.assertRaises(SystemExit) as cm:
            verify.validate_inputs(output_helper)

        self.assertEqual(cm.exception.code, 1)

    def test_validate_inputs_github_actions_format(self):
        """Test validate_inputs works with GitHub Actions input format."""
        os.environ["INPUT_APIKEY"] = "test_api_key"
        os.environ["INPUT_ORGID"] = "test_org_id"
        os.environ["INPUT_AUTHHEADER"] = "test_auth_header"
        os.environ["INPUT_APPID"] = "test_app_id"

        output_helper = OutputHelper()
        config = verify.validate_inputs(output_helper)

        self.assertEqual(config["API_KEY"], "test_api_key")
        self.assertEqual(config["ORG_ID"], "test_org_id")
        self.assertEqual(config["AUTHORIZATION"], "test_auth_header")
        self.assertEqual(config["APP_ID"], "test_app_id")

    def test_validate_inputs_contrast_prefix_format(self):
        """Test validate_inputs works with CONTRAST_ prefixed environment variables."""
        os.environ["CONTRAST_API_KEY"] = "test_api_key"
        os.environ["CONTRAST_ORG_ID"] = "test_org_id"
        os.environ["CONTRAST_AUTH_HEADER"] = "test_auth_header"
        os.environ["CONTRAST_APP_ID"] = "test_app_id"

        output_helper = OutputHelper()
        config = verify.validate_inputs(output_helper)

        self.assertEqual(config["API_KEY"], "test_api_key")
        self.assertEqual(config["ORG_ID"], "test_org_id")
        self.assertEqual(config["AUTHORIZATION"], "test_auth_header")
        self.assertEqual(config["APP_ID"], "test_app_id")

    def test_validate_inputs_environment_variable_precedence(self):
        """Test that GitHub Actions format takes precedence over standard and CONTRAST_ format."""
        os.environ["INPUT_APIKEY"] = "github_api_key"
        os.environ["API_KEY"] = "standard_api_key"
        os.environ["CONTRAST_API_KEY"] = "contrast_api_key"
        os.environ["ORG_ID"] = "test_org_id"
        os.environ["AUTH_HEADER"] = "test_auth_header"
        os.environ["APP_ID"] = "test_app_id"

        output_helper = OutputHelper()
        config = verify.validate_inputs(output_helper)

        # Should use GitHub Actions format (INPUT_APIKEY)
        self.assertEqual(config["API_KEY"], "github_api_key")

    def test_validate_inputs_with_ca_file(self):
        """Test validate_inputs works when CA file is provided."""
        os.environ["API_KEY"] = "test_api_key"
        os.environ["ORG_ID"] = "test_org_id"
        os.environ["AUTH_HEADER"] = "test_auth_header"
        os.environ["APP_ID"] = "test_app_id"
        os.environ["CA_FILE"] = "some_cert_content"

        output_helper = OutputHelper()
        config = verify.validate_inputs(output_helper)

        self.assertEqual(config["API_KEY"], "test_api_key")
        # The CA_FILE is handled in the main execution, not in validate_inputs


if __name__ == "__main__":
    unittest.main()
