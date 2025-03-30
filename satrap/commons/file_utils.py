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


def validate_file(path: str, write=False, override=False):
    """Validates whether a file can be accessed in the described way.
    
    :param path: The path to the file
    :type path: str
    :param write: Whether one wants to write to the file
    :type write: bool, optional
    :param override: Whether one wants to override the contents of the 
        file
    :type override: bool, optional

    :raises ValueError: If the file cannot be accessed in the desired 
        way 
    """
    folder, file = os.path.split(path)

    if override and not write:
        raise ValueError(
            "To override a file, one must also want to write to it"
        )

    if not os.path.exists(folder):
        raise ValueError("Specified folder does not exist.")
    
    file_exists = os.path.exists(file)

    if not write:
        if not file_exists:
            raise ValueError("File does not exist")
    else:
        if not override:
            if file_exists:
                raise ValueError("Specified file already exists.")


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

    # validate the given file path
    #try:
    validate_file(save_to, write=True, override=override)
    # except ValueError as e:
    #     raise ValueError(e)

    # download
    with requests.get(url, stream=True, timeout=(20,30)) as response:
        logger.info("Requesting download from %s...", url)
        if response.status_code == requests.codes.ok:
            logger.debug("...Response status ok")
            with open(save_to, 'wb') as file:
                logger.info("Writing to %s", save_to)
                for chunk in response.iter_content(
                    settings.DOWNLOAD_CHUNK_SIZE
                ):
                    if chunk:
                        file.write(chunk)
        else:
            # logger.error(
            #     "Download cancelled. Response status %s.", response.status_code
            # )
            response.raise_for_status()


def read_json(file: str) -> dict:
    """Read and return the content of a .json file
    
    :param file: the file path of the json data
    :type file: str
    """
    with open(file, 'r', encoding="utf-8") as f:
        res = json.load(f)
    return res


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
