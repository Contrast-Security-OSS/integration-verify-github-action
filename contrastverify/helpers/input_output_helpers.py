import os
import sys

from actions_toolkit import core as gh_action


class InputHelper:
    """Helper class for getting inputs/environment variables"""

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
