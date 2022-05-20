import atexit
import os
import sys
from typing import Callable

from actions_toolkit import core as gh_action


class InputHelper:
    """Helper class for getting inputs/environment variables"""

    ALL_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NOTE"]
    """All vulnerability severities, in descending severity order."""

    @staticmethod
    def get_input(name):
        """
        Check the environment for a named input or variable of supported formats.
        Name should be in the SCREAMING_SNAKE_CASE format.

        For example, given the name `AUTH_HEADER`, the following environment variables will be checked in order:
        - `INPUT_AUTHHEADER` (GitHub Actions format)
        - `AUTH_HEADER`
        - `CONTRAST_AUTH_HEADER`

        :param name: name of the input/environment variable to retrieve value for
        :return: value of the named input/environment variable, or None if no matches
        """
        gh_action_format = f'INPUT_{name.replace("_", "")}'
        if gh_action_format in os.environ:
            return os.getenv(gh_action_format)

        if name in os.environ:
            return os.getenv(name)

        contrast_prefix_format = f"CONTRAST_{name}"
        if contrast_prefix_format in os.environ:
            return os.getenv(contrast_prefix_format)

        return None

    @staticmethod
    def get_included_severities(severities_csv: str) -> list[str]:
        """
        Process a CSV list of severities returning an array of valid severities in descending severity order.
        Input will be split, trimmed and upper-cased.
        """
        input_severities = list(map(str.strip, severities_csv.upper().split(",")))

        return [
            severity
            for severity in InputHelper.ALL_SEVERITIES
            if severity in input_severities
        ]


class OutputHelper:
    """Helper class to format output for GitHub Actions or other CI/CD tools"""

    @staticmethod
    def is_github_actions():
        return "true" == os.getenv("GITHUB_ACTIONS")

    def __init__(self) -> None:
        if self.is_github_actions():
            self.debug = gh_action.debug
            self.error = gh_action.error
            self.info = gh_action.info
            self.notice = gh_action.notice
            self.warning = gh_action.warning
        else:
            if "DEBUG" in os.environ:
                self.debug = self.__print("DEBUG: ")
            else:
                self.debug = lambda input: None
            self.error = self.__print("ERROR: ")
            self.info = self.__print("INFO: ")
            self.notice = self.__print("NOTICE: ")
            self.warning = self.__print("WARNING: ")

        self.write_summary = self.setup_github_summary()

    def setup_github_summary(self) -> Callable[[str], None]:
        """
        Setup the `write_summary` function so messages can be written out to the GitHub Action summary file.
        If we are not running in GitHub Actions, are not given a path, or are unable to write to the specified file, the returned function will perform no operations.
        :return: function that can write lines to the GitHub Action summary file, safe to use even when not running in GitHub Actions
        """

        def noop_writer(message):
            pass

        if not self.is_github_actions():
            self.debug("Not running in GitHub Actions, so no summary will be written")
            return noop_writer

        path = os.getenv("GITHUB_STEP_SUMMARY")
        if not path:
            self.warning(
                "No path when configuring summary writer - no summary will be written"
            )
            return noop_writer
        try:
            self._summary_handle = open(path, "a")
            atexit.register(self._summary_handle.close)
            self.debug("Successfully configured summary writer handle")
        except OSError as e:
            self.warning(
                f"OSError configuring summary writer for {path} - no summary will be written - {e}"
            )
            return noop_writer
        else:
            self.debug("Successfully configured summary writer")
            return lambda message: print(message, file=self._summary_handle)

    def __print(self, prefix):
        """
        Generate a print function that prefixes output with the specified prefix
        :param prefix: prefix to print before supplied message
        :return: function that will print prefix+str(input)
        """
        return lambda input: print(prefix + str(input))

    def set_failed(self, message):
        """
        Exit due to a failure. Exit code will be 1.
        :param message: error message to print
        """
        self.error(message)
        sys.exit(1)
