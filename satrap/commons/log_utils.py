import logging
import os
from datetime import datetime

from satrap.settings import (
    DEBUG_LOG_FILE_NAME,
    INFO_LOG_FILE_NAME,
    ERROR_LOG_FILE_NAME,
    LOG_FILES_EXT,
    LOGS_PATH,
    TIMESTAMP_FILES,
    EXEC_ENVIRONMENT as etl_op_mode,
)

LOG_NEWLINE = "\n   "

# Create a logger
logger = logging.getLogger(__name__)


#--- Logging formats ---
DEFAULT_LOGGING_FORMAT = (
    "[%(levelname)s] (%(asctime)s) %(filename)s at %(funcName)s():"
    + LOG_NEWLINE
    + "%(message)s"
)
WARNING_LOGGING_FORMAT = "[%(levelname)s] (%(asctime)s) %(message)s"
SHORT_DATE_FORMAT = "%d-%m-%y %H:%M"


#--- Logging files ---
current_date = datetime.now().strftime("%Y-%m-%d")

DATED_LOGS_FOLDER = os.path.join(LOGS_PATH, current_date)
os.makedirs(DATED_LOGS_FOLDER, exist_ok=True)

ERROR_LOG_FILE = os.path.join(
    DATED_LOGS_FOLDER, f"{ERROR_LOG_FILE_NAME}{LOG_FILES_EXT}")
DEBUG_LOG_FILE = os.path.join(
    DATED_LOGS_FOLDER,
    f"{DEBUG_LOG_FILE_NAME}"
    f"{datetime.now().strftime('%Hh%M') if TIMESTAMP_FILES else ''}"
    f"{LOG_FILES_EXT}"
)

INFO_LOG_FILE = os.path.join(
    DATED_LOGS_FOLDER,
    f"{INFO_LOG_FILE_NAME}"
    f"{datetime.now().strftime('%Hh%M') if TIMESTAMP_FILES else ''}"
    f"{LOG_FILES_EXT}"
)

formatter = logging.Formatter(DEFAULT_LOGGING_FORMAT)
short_date_formatter = logging.Formatter(DEFAULT_LOGGING_FORMAT, datefmt=SHORT_DATE_FORMAT)
warning_formatter = logging.Formatter(WARNING_LOGGING_FORMAT, datefmt=SHORT_DATE_FORMAT)


#--- Console logger for errors ---
log_console_handler = logging.StreamHandler()
log_console_handler.setLevel(logging.ERROR)
log_console_handler.setFormatter(formatter)


#--- Console logger for testing messages ---
# Define a logging level for testing
TESTING_LEVEL = logging.INFO + 5
logging.addLevelName(TESTING_LEVEL, "TESTING")

def testing(self, message, *args, **kws):
    """
    Log the provided message if the logger is enabled for the 'TESTING_LEVEL' severity.

    :param self: The instance of the logger.
    :type self: object
    :param message: The message to be logged.
    :type message: str
    :param args: Additional positional arguments to be passed to the logger.
    :type args: tuple
    :param kws: Additional keyword arguments to be passed to the logger.
    :type kws: dict
    """
    if self.isEnabledFor(TESTING_LEVEL):
        self.log(TESTING_LEVEL, message, *args, **kws, stacklevel=2)

# Add the testing method to the Logger class
logging.Logger.testing = testing

# Create a console handler for testing level messages
log_testing_handler = logging.StreamHandler()
log_testing_handler.setLevel(TESTING_LEVEL)
log_testing_handler.setFormatter(short_date_formatter)


#--- Logger setup ---

ACTIVE_LOG_FILE = ""

# Add handlers to the logger
if etl_op_mode == "dev":
    logger.setLevel(logging.DEBUG)
    debug_file_handler = logging.FileHandler(
        DEBUG_LOG_FILE, encoding="utf-8"
    )
    debug_file_handler.setLevel(logging.DEBUG)
    debug_file_handler.setFormatter(formatter)
    logger.addHandler(debug_file_handler)
    logger.addHandler(log_console_handler)
    ACTIVE_LOG_FILE = DEBUG_LOG_FILE
elif etl_op_mode == "prod":
    logger.setLevel(logging.INFO)
    info_file_handler = logging.FileHandler(
        INFO_LOG_FILE, encoding="utf-8"
    )
    info_file_handler.setLevel(logging.INFO)
    info_file_handler.setFormatter(warning_formatter)
    logger.addHandler(info_file_handler)
    ACTIVE_LOG_FILE = INFO_LOG_FILE
elif etl_op_mode == "testing":
    logger.setLevel(TESTING_LEVEL)
    logger.addHandler(log_testing_handler)
else:
    logger.setLevel(logging.ERROR)
    # logger.addHandler(log_console_handler)
    err_file_handler = logging.FileHandler(
        ERROR_LOG_FILE, encoding="utf-8"
    )
    err_file_handler.setLevel(logging.ERROR)
    err_file_handler.setFormatter(short_date_formatter)
    logger.addHandler(err_file_handler)
    ACTIVE_LOG_FILE = ERROR_LOG_FILE
