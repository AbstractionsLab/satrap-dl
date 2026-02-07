import sys
from timeit import default_timer as timer
from tabulate import tabulate

from satrap.etl.etlorchestrator import ETLOrchestrator
from satrap.datamanagement.typedb import typedbmanager as db_driver
from satrap.engine.cti_engine import CTIEngine
from satrap.service.satrap_analysis import CTIanalysisToolbox
from satrap.etl import exceptions
from satrap.commons.log_utils import logger, ACTIVE_LOG_FILE
import satrap.commons.file_utils as utils
from satrap.etl.extract import extract_constants as extract_ct
from satrap import settings as conf


def as_function(name):
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


def _get_etl_kwargs(args):
    kwargs = {}
    if int(args.xmode) == extract_ct.DOWNLOADER:
        kwargs["transform_src"] = utils.create_local_filename(conf.STIX_DATA_PATH, args.src)
        kwargs[extract_ct.MAX_CONNECTION_TIME] = args.maxconnectiontime
        kwargs[extract_ct.MAX_RESP_TIME] = args.maxresptime
    if int(args.xmode) == extract_ct.MISP_EXTRACTOR:
        kwargs["transform_src"] = conf.MISP_STIX_DATA_FILE
        kwargs[extract_ct.MISP_APIKEY] = args.apikey
    return kwargs


def _build_exec_end_message(process_name, starttime, endtime, num_data_instances):
    total = endtime - starttime
    if total/60 >= 1:
        total = total/60
        unit = "minutes"
    else:
        unit = "seconds"
    return (f"{process_name} run finished in {total:.3f} {unit}.\n"
            f"Data instances loaded: {num_data_instances}")


def _handle_gen_exception(err):
    if conf.EXEC_ENVIRONMENT == "dev":
        logger.exception("Unexpected %s: %s", type(err).__name__, err)
    else:
        logger.error("Unexpected %s: %s", type(err).__name__, err)
    print(err)
    sys.exit(1)


def exec_setup(args):
    logger.info("Starting setup process at '%s'", args.server)
    db_name = conf.DB_NAME_TST if args.testmode else args.database
    if args.testmode:
        db_name = conf.DB_NAME_TST
        recreate = True
    else:
        db_name = args.database
        recreate = args.delete

    print(f"Database '{db_name}' will be created at '{args.server}'")
    if recreate:
        print(
            f"WARNING: If '{db_name}' exists, it will be deleted and recreated."
        )
    confirmation = input("Type 'y' to continue: ").strip().lower()
    if confirmation != "y":
        logger.info("Setup process aborted by the user.")
        print("Setup process aborted by the user.")
        sys.exit(0)
    try:
        db_driver.create_database(args.server, db_name, reset=recreate)
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
    if args.test:
        args.xmode = extract_ct.DOWNLOADER
        args.src = conf.EXTRACT_URL_TST
        args.database = conf.DB_NAME_TST
    logger.debug("with args: %s", args)

    try:
        xmode = int(args.xmode)
        if xmode not in (extract_ct.DOWNLOADER, extract_ct.MISP_EXTRACTOR):
            raise ValueError()
    except ValueError:
        logger.error("Invalid extractor type: %s.", args.xmode)
        print(
            f"Invalid extractor type: {args.xmode}. "
            f"Valid types are: {extract_ct.DOWNLOADER}, {extract_ct.MISP_EXTRACTOR}"
        )
        sys.exit(1)
    if xmode == extract_ct.MISP_EXTRACTOR and not args.apikey:
        logger.error("Missing API key for MISP extractor.")
        print(
            "The MISP extractor requires an API key. "
            "Please provide it using the '-k' option."
        )
        sys.exit(1)

    print(
        f"\nThe ETL process will be executed with the following parameters "
        "(modify at 'satrap_params.yml'):\n\n"
        f" Extraction type: {xmode}\n"
        f" Extraction datasource: {args.src}\n"
        f" Load into: database '{args.database}' at {args.server}\n"
    )
    confirmation = input("Type \"yes\" to continue: ").strip().lower()
    if confirmation != "yes":
        logger.info("ETL process aborted by the user.")
        print("ETL process aborted by the user.")
        sys.exit(0)

    print(f"Logging to file: {ACTIVE_LOG_FILE}")

    try:
        kwargs = _get_etl_kwargs(args)
        ini_data = db_driver.count_data_instances(args.server, args.database)
        start = timer()
        orch = ETLOrchestrator(xmode)
        orch.etl(args.src, args.server, args.database, **kwargs)
        end = timer()
        end_data = db_driver.count_data_instances(args.server, args.database)
    except exceptions.ExtractionError as e:
        if conf.EXEC_ENVIRONMENT == "dev":
            logger.exception(e)
        else:
            logger.error(e)
            print(e)
        sys.exit(1)
    except Exception as err:
        _handle_gen_exception(err)

    logger.info(_build_exec_end_message("ETL", start, end, end_data-ini_data))
    print(_build_exec_end_message("ETL", start, end, end_data-ini_data))


def exec_tl(args):
    logger.info(
        "Starting transform and load process into '%s' at %s",
        args.database,
        args.server,
    )
    orch = ETLOrchestrator(extract_ct.STIX_READER)

    print(
        f"\nThe Transform-Load process will be executed with the following parameters:\n\n"
        f" Datasource file: {args.file}\n"
        f" Load into: database '{args.database}' at {args.server}\n"
    )
    confirmation = input("Type \"yes\" to continue: ").strip().lower()
    if confirmation != "yes":
        logger.info("TL process aborted by the user.")
        print("TL process aborted by the user.")
        sys.exit(0)

    print(f"Logging to file: {ACTIVE_LOG_FILE}")
    try:
        ini_data = db_driver.count_data_instances(args.server, args.database)
        start = timer()
        orch.transform_load(args.file, args.server, args.database)
        end = timer()
        end_data = db_driver.count_data_instances(args.server, args.database)
    except exceptions.ExtractionError as e:
        if conf.EXEC_ENVIRONMENT == "dev":
            logger.exception(e)
        else:
            logger.error(e)
            print(e)
        sys.exit(1)
    except Exception as err:
        _handle_gen_exception(err)

    logger.info(_build_exec_end_message("TL", start, end, end_data-ini_data))
    print(_build_exec_end_message("TL", start, end, end_data-ini_data))


def exec_rules(args):
    try:
        with CTIEngine(args.server, args.database) as engine:
            print("\nInference rules defined in the knowledge base:")
            print(*engine.get_inference_rule_names(), sep="\n")
    except Exception as err:
        _handle_gen_exception(err)


def exec_stats(args):
    try:
        print(CTIanalysisToolbox(args.server, args.database).get_sdo_stats())
    except Exception as err:
        _handle_gen_exception(err)


def exec_techniques(args):
    try:
        tools = CTIanalysisToolbox(args.server, args.database)
        data = tools.summarize_techniques_usage(
            sort_order=args.sort,
            used_by_min=args.min,
            used_by_max=args.max,
            infer=args.infer,
            revoked=args.revoked,
            limit=args.limit,
        )

        count_txt = "Used by (num.\nintrusion sets)"
        _display(data, ["MITRE ATT&CK\n technique", "Name", count_txt])
        print(f"\nNumber of techniques: {len(data)}")
    except Exception as err:
        _handle_gen_exception(err)


def exec_mitigations(args):
    try:
        print(CTIanalysisToolbox(args.server, args.database).mitre_attack_mitigations())
    except Exception as err:
        _handle_gen_exception(err)


def exec_search(args):
    try:
        tools = CTIanalysisToolbox(args.server, args.database)
        entity = tools.search_by_stix_id(args.stix_id).items()
        if not entity:
            print(f"No STIX object found with id: {args.stix_id}")
        else:
            _display(entity, ["Property", "Value"], [20, 55])
    except Exception as exc:
        print(f"{type(exc).__name__}: {exc}")


def exec_info_mitre(args):
    try:
        element = CTIanalysisToolbox(args.server, args.database).search_by_mitre_id(
            args.id
        )
        for e in element:
            _display(e.items(), ["Property", "Value"], [20, 55])
    except ValueError as exc:
        print(exc)


def exec_mid(args):
    try:
        with CTIEngine(args.server, args.database) as engine:
            print(engine.get_mitre_id(args.stix_id))
    except Exception as err:
        _handle_gen_exception(err)



def _display(data, headers, max_widths=None):
    try:
        if not max_widths:
            print(f"\n{tabulate(data, headers, tablefmt='grid')}")
        else:
            print(
                f"\n{tabulate(data, headers, tablefmt='grid', maxcolwidths=max_widths)}"
            )
    except Exception as err:
        _handle_gen_exception(err)
