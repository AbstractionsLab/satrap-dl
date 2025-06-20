import argparse
import sys

from satrap.etl.extract import extract_constants as extract_ct
from satrap import __description__, PROJ_NAME
from satrap import settings as conf
from satrap.frontend import commands
from satrap.commons.log_utils import logger


def cli():
    """Command line management interface that allows setting up a fresh CTI SKB,
     running the ETL process and SATRAP analysis tools.
    """
    parser = argparse.ArgumentParser(prog="satrap", description=__description__)
    parser.add_argument("-V", "--version", action="version", version=PROJ_NAME)
    _add_db_args(parser)

    subparsers = parser.add_subparsers(
        dest="command", title="subcommands", description="Available subcommands"
    )

    # build parsers for etl subcommands
    _add_setup(subparsers)
    _add_etl(subparsers)
    _add_tl(subparsers)

    # build parsers for analysis subcommands
    _add_rules(subparsers)
    _add_stats(subparsers)
    _add_techniques_usage(subparsers)
    _add_attck_mitigations(subparsers)
    _add_search(subparsers)
    _add_info_mitre(subparsers)
    _add_mid(subparsers)

    # parse arguments
    args = parser.parse_args()
    # logger.debug(args)

    # run the selected command
    if args.command is None:
        parser.print_help()
    else:
        function = commands.as_function(args.command)
        try:
            function(args)
        except KeyboardInterrupt:
            logger.debug("Command cancelled")
            sys.exit(1)
        except Exception as exc:
            logger.error(exc)
            print(exc)
            sys.exit(1)


def _add_setup(subs):
    """Add submenu for the 'setup' command to a given parser

    :param subs: An object returned by the 'add_subparsers()' method
        of an ArgumentParser
    :type subs: Type of the output of the 'add_subparsers()' method
        of an ArgumentParser
    """
    info = "Create a fresh CTI semantic knowledge base for SATRAP."
    subparser = subs.add_parser("setup", description=info, help=info)

    subparser.add_argument(
        "-db",
        "--database",
        default=conf.DB_NAME,
        help="Database where data is to be inserted (default: %(default)s)",
    )
    subparser.add_argument(
        "-d",
        "--delete",
        action="store_true",
        help="If it exists, delete the database and recreate it",
    )
    subparser.add_argument(
        "-tm",
        "--testmode",
        action="store_true",
        help=('The setup uses the database "DB_NAME_TST" defined in settings; '
        'existing instances are overwritten')
    )


def _add_etl(subs):
    """Add submenu for the 'run' command to a given parser

    :param subs: An object returned by the 'add_subparsers()' method
        of an ArgumentParser
    :type subs: Type of the output of the 'add_subparsers()' method
        of an ArgumentParser
    """
    help_txt = "Ingest data from an external given source into the CTI SKB of SATRAP. "
    info = (
        help_txt
        + "Default parameters can be set in the configuration file 'satrap_params.yml'. "
        "Datasource file parameter: 'extract_src' in 'etl'."
    )
    subparser = subs.add_parser("etl", description=info, help=help_txt)

    subparser.add_argument(
        "-x",
        "--xmode",
        default=extract_ct.DOWNLOADER,
        help="""The extraction mode (default %(default)s):
            1 - download file from a URL; 
            2 - get events from a MISP instance""",
    )
    subparser.add_argument(
        "-src",
        default=conf.MITRE_ATTACK_SRC,
        help="The path or URI of a STIX-compliant datasource",
    )
    subparser.add_argument(
        "-db",
        "--database",
        default=conf.DB_NAME,
        help="Database where data is to be inserted (default: %(default)s)",
    )
    subparser.add_argument(
        "-k",
        "--apikey",
        help=("MISP API key to enable communication with the MISP instance. "
              " Required for extractor type 2")
    )
    subparser.add_argument(
        "-tm",
        "--test",
        action="store_true",
        help=f"Extract a sample STIX2.1 file and load in the test database '{conf.DB_NAME_TST}'",
    )


def _add_tl(subs):
    """Add submenu for the 'tl' command to a given parser

    :param subs: An object returned by the 'add_subparsers()' method
        of an ArgumentParser
    :type subs: Type of the output of the 'add_subparsers()' method
        of an ArgumentParser
    """
    help_txt = "Transform data from a given STIX 2.1 file and load it into the CTI SKB of SATRAP."
    info = (
        help_txt
        + " Default parameters can be set in the configuration file 'satrap_params.yml'. "
        "Datasource file parameter: 'transform_src' in 'tl'."
    )
    subparser = subs.add_parser("tl", description=info, help=help_txt)

    subparser.add_argument(
        "-f",
        "--file",
        default=conf.TRANSFORM_SRC_CLI,
        help="The path of a STIX2.1 file to be transformed and loaded (default: %(default)s)",
    )
    subparser.add_argument(
        "-db",
        "--database",
        default=conf.DB_NAME,
        help="Database where data is to be inserted (default: %(default)s)",
    )


def _add_db_args(parser):
    parser.add_argument(
        "-ep",
        "--server",
        default=conf.TYPEDB_SERVER_ADDRESS,
        help="Address (host:port) of a TypeDB server (default: %(default)s)",
    )
    parser.add_argument(
        "-db",
        "--database",
        default=conf.DB_NAME,
        help="CTI SKB to be used for the analysis (default: %(default)s)",
    )


def _add_rules(subs):
    info = "Show the inference rules defined over the CTI SKB."
    subs.add_parser("rules", description=info, help=info)


def _add_stats(subs):
    info = "Provide statistics on existing STIX domain objects (SDOs)."
    subs.add_parser("stats", description=info, help=info)


def _add_techniques_usage(subs):
    info = (
        "Gain insights into the usage of the MITRE ATT&CK "
        "techniques (STIX attack patterns) by various "
        "threat actors (STIX intrusion sets)."
    )
    subparser = subs.add_parser("techniques", description=info, help=info)
    subparser.add_argument(
        "-min",
        type=int,
        default=None,
        help="Show only techniques used in at least this number of intrusion sets",
    )
    subparser.add_argument(
        "-max",
        type=int,
        default=None,
        help="Show only techniques used in at most this number of intrusion sets",
    )
    subparser.add_argument(
        "-i",
        "--infer",
        action="store_true",
        help="When provided, enable the inference engine",
    )
    subparser.add_argument(
        "--sort", dest="sort", default="desc", help="Sort order: desc(default) or asc"
    )
    subparser.add_argument(
        "--limit",
        dest="limit",
        type=int,
        default=None,
        help="Max number of techniques to be shown",
    )
    subparser.add_argument(
        "--revoked", action="store_true", help="Include revoked techniques"
    )


def _add_attck_mitigations(subs):
    info = "See the mitigations specified in MITRE ATT&CK"
    subs.add_parser("mitigations", description=info, help=info)


def _add_search(subs):
    info = "Search for a STIX object in the CTI SKB using the STIX id"
    subparser = subs.add_parser("search", description=info, help=info)
    subparser.add_argument(
        "stix_id", type=str, help="The STIX id of the object to search for"
    )


def _add_info_mitre(subs):
    info = "Get information about a MITRE ATT&CK element (technique, group, software, etc.)"
    subparser = subs.add_parser("info_mitre", description=info, help=info)
    subparser.add_argument(
        "id",
        type=str,
        help="Show information on the element with this MITRE ATT&CK id",
    )

def _add_mid(subs):
    info = "Get the MITRE ATT&CK ID of an element with a STIX ID."
    subparser = subs.add_parser("mid", description=info, help=info)
    subparser.add_argument(
        "stix_id", type=str, help="The STIX id of the element to search for"
    )


if __name__ == "__main__":
    cli()
