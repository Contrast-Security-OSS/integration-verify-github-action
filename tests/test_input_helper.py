import unittest

from verify import InputHelper


class InputHelperTestCase(unittest.TestCase):
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
