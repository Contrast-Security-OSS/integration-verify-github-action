import contextlib
import io
import os
import unittest
from pathlib import Path

from certifi import where as default_certs_path

from verify import InputHelper, OutputHelper


class InputHelperTestCase(unittest.TestCase):
    def setUp(self) -> None:
        os.environ["DEBUG"] = "true"
        self._fixtures_folder = Path(__file__).parent.absolute() / Path("fixtures")
        self._output_helper = OutputHelper()

    def test_severities_validation(self):
        self.assertEqual(InputHelper.get_included_severities(""), [])
        self.assertEqual(
            InputHelper.get_included_severities("CRITICAL,HIGH"), ["CRITICAL", "HIGH"]
        )
        self.assertEqual(
            InputHelper.get_included_severities("HIGH,CRITICAL"), ["CRITICAL", "HIGH"]
        )
        self.assertEqual(
            InputHelper.get_included_severities("MEDIUM,  note  ,, Crit"),
            ["MEDIUM", "NOTE"],
        )
        self.assertEqual(
            InputHelper.get_included_severities("low,med,high,critical"),
            ["CRITICAL", "HIGH", "LOW"],
        )
        self.assertEqual(
            InputHelper.get_included_severities(
                "CRITIcal, HIGH , LOW, HIGH, NOTE  , MEDIUM"
            ),
            ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NOTE"],
        )

    def test_load_empty_certs(self):
        del os.environ["CA_FILE"]
        # cert path should be none
        self.assertIsNone(InputHelper.load_certs(self._output_helper))

    def test_load_invalid_cert(self):
        os.environ["CA_FILE"] = "not a real certificate"

        out = io.StringIO()
        # cert path should not be none
        with contextlib.redirect_stdout(out):
            self.assertIsNotNone(InputHelper.load_certs(self._output_helper))
        # it should log a useful message
        self.assertIn(
            "Unable to load certificate(s) from CA_FILE input",
            out.getvalue(),
        )

    def test_load_non_ca_cert(self):
        os.environ["CA_FILE"] = (
            self._fixtures_folder / Path("selfsigned.pem")
        ).read_text()

        out = io.StringIO()
        # cert path should not be none
        with contextlib.redirect_stdout(out):
            self.assertIsNotNone(InputHelper.load_certs(self._output_helper))
        # it should log a useful message
        self.assertIn(
            "None of the provided certificates are CA certificates. Only CA certificates can be used for custom trust.",
            out.getvalue(),
        )

        # test we are getting cert debug logging
        self.assertIn(
            "Certificate[0]",
            out.getvalue(),
        )

        self.assertIn(
            "is_ca_cert: False",
            out.getvalue(),
        )

    def test_load_ca_certs(self):
        os.environ["CA_FILE"] = Path(default_certs_path()).read_text()

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertIsNotNone(InputHelper.load_certs(self._output_helper))
        # it should log a useful message

        # test we are getting cert debug logging
        self.assertIn(
            "Certificate[0]",
            out.getvalue(),
        )

        self.assertIn(
            "is_ca_cert: True",
            out.getvalue(),
        )

        # all certs should be ca certs, so there should be no warning
        self.assertNotIn(
            "None of the provided certificates are CA certificates. Only CA certificates can be used for custom trust.",
            out.getvalue(),
        )

    def test_certificate_without_basic_attributes(self):
        os.environ["CA_FILE"] = (
            self._fixtures_folder / Path("missingbasicattributes.pem")
        ).read_text()

        out = io.StringIO()
        # cert path should not be none
        with contextlib.redirect_stdout(out):
            self.assertIsNotNone(InputHelper.load_certs(self._output_helper))

        # it should assume this certificate is not a ca certificate
        self.assertIn(
            "has no basic constraints, assuming it is not a CA certificate",
            out.getvalue(),
        )

        # no other certs are ca certs, so expect this warning too
        self.assertIn(
            "None of the provided certificates are CA certificates. Only CA certificates can be used for custom trust.",
            out.getvalue(),
        )

        # test we are getting cert debug logging
        self.assertIn(
            "Certificate[0]",
            out.getvalue(),
        )

        self.assertIn(
            "is_ca_cert: False",
            out.getvalue(),
        )
