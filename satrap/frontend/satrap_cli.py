import argparse
import sys
from timeit import default_timer as timer
from tabulate import tabulate

from satrap.etl import exceptions
from satrap.etl.extract import extract_constants as extract_ct
from satrap.etl.etlorchestrator import ETLOrchestrator
from satrap.datamanagement.typedb import typedbmanager as db_driver
from satrap.engine.cti_engine import CTIEngine
from satrap.service.satrap_analysis import CTIanalysisToolbox
from satrap.frontend import CLI, DESCRIPTION, VERSION
from satrap import settings as conf
from satrap.commons.log_utils import logger, ACTIVE_LOG_FILE


def _as_function(name):
    """Retrieve a function from the current global namespace.
    The function name is of the form: exec_<name>

    :param name: the name of the triggering command
    :type name: str
    :return: a callable function
    :raises ValueError: If a function associated with the given name
        is not found in the global namespace
    """
    if name:
        return globals()["exec_" + name]
    raise ValueError("No valid command was given")


def cli():
    """Command line management interface that allows setting up a fresh CTI SKB
    , running the ETL process and SATRAP analysis tools.
    """
    parser = argparse.ArgumentParser(prog=CLI, description=DESCRIPTION)
    parser.add_argument("-V", "--version", action="version", version=VERSION)
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

    # parse arguments
    args = parser.parse_args()
    # logger.debug(args)

    # run the selected command
    if args.command is None:
        parser.print_help()
    else:
        function = _as_function(args.command)
        try:
            function(args)
        except KeyboardInterrupt:
            logger.debug("Command cancelled")
            sys.exit(1)
        except Exception as exc:
            logger.error(exc)
            print(exc)
            sys.exit(1)


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
    info = "Shows the inference rules defined over the CTI SKB"
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
        "--norevoked", action="store_true", help="Exclude revoked STIX entities"
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
    info = "Get information about a specific MITRE ATT&CK element (technique, group, software, etc.)"
    subparser = subs.add_parser("info_mitre", description=info, help=info)
    subparser.add_argument(
        "id",
        type=str,
        help="Show information on the element with this MITRE ATT&CK id",
    )


def exec_rules(args):
    try:
        with CTIEngine(args.server, args.database) as engine:
            print("\nInference rules defined in the knowledge base:")
            print(*engine.get_inference_rule_names(), sep="\n")
    except Exception as err:
        handle_gen_exception(err)


def exec_stats(args):
    try:
        print(CTIanalysisToolbox(args.server, args.database).get_sdo_stats())
    except Exception as err:
        handle_gen_exception(err)


def exec_techniques(args):
    try:
        tools = CTIanalysisToolbox(args.server, args.database)
        data = tools.techniques_usage(
            sort_order=args.sort,
            used_by_min=args.min,
            used_by_max=args.max,
            infer=args.infer,
            norevoked=args.norevoked,
            limit=args.limit,
        )

        count_txt = "Used by (num.\nintrusion sets)"
        display(data, ["MITRE ATT&CK\n technique", "Name", count_txt])
        print(f"\nNumber of techniques: {len(data)}")
    except Exception as err:
        handle_gen_exception(err)


def exec_mitigations(args):
    try:
        print(CTIanalysisToolbox(args.server, args.database).mitre_attack_mitigations())
    except Exception as err:
        handle_gen_exception(err)


def exec_search(args):
    try:
        tools = CTIanalysisToolbox(args.server, args.database)
        entity = tools.search_stix_object(args.stix_id).items()
        if not entity:
            print(f"No STIX object found with id: {args.stix_id}")
        else:
            display(entity, ["Property", "Value"], [20, 55])
    except Exception as exc:
        print(f"{type(exc).__name__}: {exc}")


def exec_info_mitre(args):
    try:
        element = CTIanalysisToolbox(args.server, args.database).get_attck_concept_info(
            args.id
        )
        for e in element:
            display(e.items(), ["Property", "Value"], [20, 55])
    except ValueError as exc:
        print(exc)


def display(data, headers, max_widths=None):
    try:
        if not max_widths:
            print(f"\n{tabulate(data, headers, tablefmt='grid')}")
        else:
            print(
                f"\n{tabulate(data, headers, tablefmt='grid', maxcolwidths=max_widths)}"
            )
    except Exception as err:
        handle_gen_exception(err)


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
        help='The setup uses the database "DB_NAME_TST" defined in settings; existing instances are overwritten',
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
        "-t",
        "--type",
        default=extract_ct.DOWNLOADER,
        help="The type of extraction as per the source: 1 - download from URL (default)",
    )
    subparser.add_argument(
        "-tm",
        "--testmode",
        action="store_true",
        help="The etl loads in the database 'DB_NAME_TST' in settings and extracts a sample STIX2.1 file.",
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


def exec_setup(args):
    logger.info("Starting setup process at '%s'", args.server)
    db_name = conf.DB_NAME_TST if args.testmode else args.database

    print(f"Database '{db_name}' will be created at '{args.server}'")
    confirmation = input("Do you want to continue? (y/n): ").strip().lower()
    if confirmation != "y":
        logger.info("Setup process aborted by the user.")
        print("Setup process aborted by the user.")
        sys.exit(0)
    try:
        if args.testmode:
            db_driver.create_database(args.server, conf.DB_NAME_TST, reset=True)
        else:
            db_driver.create_database(args.server, args.database, reset=args.delete)
    except ValueError as e:
        print(e, "Consider running 'setup' with the option '-d'")
        sys.exit(1)
    print(
        f"Database '{db_name}' successfully created from:\n"
        f"Schema: {conf.DB_SCHEMA}\n"
        f"Rules: {conf.DB_RULES}"
    )


def exec_etl(args):
    logger.info("Starting ETL process")
    orch = ETLOrchestrator()
    if args.testmode:
        args.database = conf.DB_NAME_TST
        args.type = extract_ct.DOWNLOADER
        args.src = conf.EXTRACT_URL_TST
    logger.info("with args: %s", args)

    print(
        f"\nThe ETL process will be executed with the following parameters (modify at 'satrap_params.yml'):\n\n"
        f" Extraction datasource: {args.src}\n"
        f" Load into: database '{args.database}' at {args.server}\n"
    )
    confirmation = input("Do you want to continue? (yes/no): ").strip().lower()
    if confirmation != "yes":
        logger.info("ETL process aborted by the user.")
        print("ETL process aborted by the user.")
        sys.exit(0)

    ini_data = db_driver.count_data_instances(args.server, args.database)
    print(f"Logging to file: {ACTIVE_LOG_FILE}")
    try:
        start = timer()
        orch.etl(args.type, args.src, args.server, args.database)
        end = timer()
    except exceptions.ExtractionError as e:
        if conf.EXEC_ENVIRONMENT == "dev":
            logger.exception(e)
        else:
            logger.error(e)
            print(e)
        sys.exit(1)
    except Exception as err:
        handle_gen_exception(err)

    end_data = db_driver.count_data_instances(args.server, args.database)
    logger.info(
        "ETL run finished in %.4f seconds.\n" "Data instances loaded: %i.",
        end - start,
        end_data - ini_data,
    )
    print(
        f"ETL run finished in {end-start} seconds.\n"
        f"Data instances loaded: {end_data-ini_data}"
    )


def exec_tl(args):
    logger.info(
        "Starting transform and load process into '%s' at %s",
        args.database,
        args.server,
    )
    orch = ETLOrchestrator()

    print(
        f"\nThe Transform-Load process will be executed with the following parameters:\n\n"
        f" Datasource file: {args.file}\n"
        f" Load into: database '{args.database}' at {args.server}\n"
    )
    confirmation = input("Do you want to continue? (yes/no): ").strip().lower()
    if confirmation != "yes":
        logger.info("TL process aborted by the user.")
        print("ETL process aborted by the user.")
        sys.exit(0)

    ini_data = db_driver.count_data_instances(args.server, args.database)
    print(f"Logging to file: {ACTIVE_LOG_FILE}")
    try:
        start = timer()
        orch.transform_load(args.file, args.server, args.database)
        end = timer()
    except exceptions.ExtractionError as e:
        if conf.EXEC_ENVIRONMENT == "dev":
            logger.exception(e)
        else:
            logger.error(e)
            print(e)
        sys.exit(1)
    except Exception as err:
        handle_gen_exception(err)

    end_data = db_driver.count_data_instances(args.server, args.database)
    logger.info(
        "ETL run finished in %.4f seconds.\n" "Data instances loaded: %i.",
        end - start,
        end_data - ini_data,
    )
    print(
        f"ETL run finished in {end-start} seconds.\n"
        f"Data instances loaded: {end_data-ini_data}"
    )


def handle_gen_exception(err):
    if conf.EXEC_ENVIRONMENT == "dev":
        logger.exception("Unexpected %s: %s", type(err).__name__, err)
    else:
        logger.error("Unexpected %s: %s", type(err).__name__, err)
    print(err)
    sys.exit(1)


if __name__ == "__main__":
    cli()
