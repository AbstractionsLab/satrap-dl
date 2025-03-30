"""Common exceptions, classes, and functions for SATRAP"""
import logging

from satrap.commons.log_utils import logger


class SatrapError(Exception):
    """Generic SATRAP error."""
    def __init__(self, message:str,log:logging.Logger|None=logger):
        if log is not None:
            log.exception(message)
        super().__init__(message)

    def __str__(self):
        return f"[{self.__class__.__name__}]: {super().__str__()}"

    
class SatrapWarning(SatrapError, Warning):
    """Generic SATRAP warning."""
    def __init__(self, message:str, log:logging.Logger|None=logger):
        if log is not None:
            log.warning(message)
        super().__init__(message)


class SatrapInfo(SatrapWarning):
    """Generic SATRAP info."""
    def __init__(self, message:str, log:logging.Logger|None=logger):
        if log is not None:
            log.info(message)
        super().__init__(message)
