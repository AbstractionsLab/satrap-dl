"""Common exceptions, classes, and functions for file handling."""

import os
import time
import json
import requests

from satrap import settings
from satrap.commons.log_utils import logger


def get_filename_from_url(url:str):
    if url is None or len(url)==0:
        raise ValueError(f"The URL '{url}' does not point to a file.")

    if '/' in url:
        name = url.split('/')[-1].replace(' ','')
        return name
    raise ValueError(f"Invalid URL: {url}")

def create_local_filename(folder:str,url:str):
    """The URL points to a JSON file
    """
    file = get_filename_from_url(url)
    if '.' in file:
        name, ext = file.split('.')
        filename = f"{name}_{time.strftime('%Y%m%d-%Hh%M')}.{ext}"
    else:
        filename = f"{file}_{time.strftime('%Y%m%d-%Hh%M')}.json"
    return os.path.join(folder,filename)


def validate_file_access(path: str, write=False, override=False):
    """Validates whether a file can be accessed with the selected options.
    
    :param path: The path to the file
    :type path: str
    :param write: True to write to the file
    :type write: bool, optional
    :param override: True to override the contents of the file
    :type override: bool, optional

    :raises ValueError: If the file cannot be accessed with the selected options 
    """
    if not isinstance(override, bool):
        override = False
    folder, _ = os.path.split(path)
    intro = "Destination file error:"

    if override and not write:
        raise ValueError(
            f"{intro} 'override' is set to True but 'write' is False."
        )

    if not os.path.exists(folder):
        if write:
            try:
                os.makedirs(folder, exist_ok=True)
                logger.debug("Destination folder %s created", folder)
            except OSError as e:
                raise ValueError(
                    f"{intro}: Failed to create folder '{folder}'."
                ) from e
        else:
            raise ValueError(f"{intro} the folder '{folder}' does not exist.")

    file_exists = os.path.exists(path)

    if not write:
        if not file_exists:
            raise ValueError(f"{intro} write is False and the file does not exist.")
    else:
        if not override and file_exists:
            raise ValueError(
                f"{intro} File '{path}' already exists and 'override' is set to False.")


def download_file(
        url: str, save_to: str, override: bool=False
    ):
    """Downloads and saves a single file.
    
    :param url: url of the source file
    :type url: str
    :param save_to: the file where the source file should be saved to
    :type save_to: str
    :param override: whether the target file should be overridden if 
        it already exists
    :type override: bool, optional
    
    :raises requests.exceptions.Timeout: if the connection to the server takes
        longer than 20 sec. or the reading takes longer than 30 sec.
    :raises HTTPError: if the response status code is not 200
    """
    # Check for whitespaces in url
    if not url == ''.join(url.split()):
        raise ValueError("URL contains whitespaces")

    validate_file_access(save_to, write=True, override=override)

    with requests.get(url, stream=True, timeout=(20,30)) as response:
        logger.debug("Requesting download from %s...", url)
        if response.status_code == requests.codes.ok:
            logger.debug("...Response status ok")
            with open(save_to, 'wb') as file:
                for chunk in response.iter_content(
                    settings.DOWNLOAD_CHUNK_SIZE
                ):
                    if chunk:
                        file.write(chunk)
            logger.debug("Written to %s", save_to)
        else:
            response.raise_for_status()


def read_json(file: str) -> dict:
    """Read and return the content of a .json file
    
    :param file: the file path of the json data
    :type file: str
    """
    with open(file, 'r', encoding="utf-8") as f:
        res = json.load(f)
    return res

def write_json(file_name: str, data: dict):
    validate_file_access(file_name, write=True, override=True)
    with open(file_name, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)

def create_file_and_write(filename,text):
    """Create a file with a given name and writes a given text in it

    :param filename: the path/name of the file
    :type filename: str
    :param text: the text to be written in the file
    :type text: string
    """
    # Open the file in write mode (creates the file if it doesn't exist)
    with open(filename, 'w', encoding="utf-8") as file:
        file.write(text)
