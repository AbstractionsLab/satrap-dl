import os
import time
import re
import argparse

import doorstop
from doorstop.common import DoorstopError

EXPORT_FOLDER_NAME = "export"
EXPORT_FOLDER = os.path.join(os.getcwd(), EXPORT_FOLDER_NAME)

DOCS_FOLDER_NAME = "docs"
PUBLISH_FOLDER_NAME = "publish"
ASSETS_FOLDER_NAME = "assets"
TRACEABILITY_FOLDER_NAME = "traceability"

PUBLISH_FOLDER_PATH = os.path.join(os.getcwd(), DOCS_FOLDER_NAME, PUBLISH_FOLDER_NAME)
TRACEABILITY_FOLDER_PATH = os.path.join(os.getcwd(), os.pardir, TRACEABILITY_FOLDER_NAME)

HTML_INDEX_FILENAME = "index.html"
DOORSTOP_FOLDER_NAME = "doorstop"
DOORSTOP_CSS_FILENAME = "sidebar.css"


def create_dirname(path):
    """Ensure a parent directory exists for a path."""
    dirpath = os.path.dirname(path)
    if dirpath and not os.path.isdir(dirpath):
        os.makedirs(dirpath)


def publish(prefix="all", path=None, format=None):
    """
    Publish the project specifications to a specified format and path.
    Args:
        prefix (str): The prefix of the document to publish. Defaults to "all".
        path (str): The path to save the published document. Defaults to None.
        format (str): The format of the published document. Defaults to None.
    """
    tree = doorstop.build()
    if format is None:
        format = ".md"
    
    if prefix != "all":
        # publish only a specific document (e.g., ARC, TST, ...)
        try:
            document = tree.find_document(prefix)
        except DoorstopError as err:
            print(f"Error finding specs with prefix '{prefix}'")
            print(err)
        
        current_time = time.strftime("%Y%m%d-%H%M%S")
        if path is None:
            path = "{}/{}-publish-{}{}".format(EXPORT_FOLDER, prefix, current_time, format)
        doorstop.publisher.publish(document, path, format)
    else:
        if path is None:
            path = PUBLISH_FOLDER_PATH
            create_dirname(path)
        doorstop.publisher.publish(tree, path, format)

        # Replace css refs in index.html
        if format == ".html":
            # update style of the table at the home page
            with open(os.path.join(path, HTML_INDEX_FILENAME), 'r') as source_file:
                try:
                    input = source_file.read()

                except Exception as e:
                    print(e)
                
                target = open(os.path.join(path, HTML_INDEX_FILENAME), "w")
                new_head = """<head>
                            <meta http-equiv="content-type" content="text/html; charset=UTF-8">
                            <link rel="stylesheet" href="assets/doorstop/bootstrap.min.css" />
                            <link rel="stylesheet" href="assets/doorstop/general.css" />
                            </head>"""
                new_content = re.sub(r'<head>.*?</head>', new_head, input, flags=re.DOTALL)
                new_content = re.sub(r'<table>', '<table class="table table-striped table-condensed">', new_content, flags=re.DOTALL)
                target.write(new_content)

            # enlarge width of the side table of contents for all specs
            with open(os.path.join(path, ASSETS_FOLDER_NAME, DOORSTOP_FOLDER_NAME, DOORSTOP_CSS_FILENAME), "a") as css_file:
                c5dec_css_fix = """
                                @media (min-width: 1200px) {
                                    .col-lg-2 {
                                    width: 26.66666667%;
                                    }
                                }
                                """
                css_file.write(c5dec_css_fix)

    print("Project specifications published to: {}".format(path))


def main(args=None, cwd=None):
    parser = argparse.ArgumentParser(description="Publish project specifications.")
    parser.add_argument("--trace", action="store_true", help=f"Publish in the '{DOCS_FOLDER_NAME}/{TRACEABILITY_FOLDER_NAME}' folder")
    args = parser.parse_args()

    if args.trace:
        publish(format=".html", path=TRACEABILITY_FOLDER_PATH)
    else:
        publish(format=".html", path=PUBLISH_FOLDER_PATH)
    #publish(format=".html", prefix="TRA")

if __name__ == "__main__":
    main()
