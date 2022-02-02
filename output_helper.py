import os
import sys

from actions_toolkit import core as gh_action


class OutputHelper:
    """Helper class to format output for GitHub Actions or other CI/CD tools"""

    def __init__(self) -> None:
        if "true" == os.getenv("GITHUB_ACTION"):
            self.debug = gh_action.debug
            self.error = gh_action.error
            self.info = gh_action.info
            self.notice = gh_action.notice
            self.warning = gh_action.warning
        else:
            self.debug = self.__print("DEBUG: ")
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
