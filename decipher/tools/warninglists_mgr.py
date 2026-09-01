"""
Enable or disable the MISP warninglists used by the DECIPHER analyzers.

MISP warninglists are lists of well-known indicators prone to be false
positives. The analyzers use them to filter the IOC search results or
to report matches,e.g., on the alert source IPs. 

Warninglists are disabled in a fresh MISP instance, this script allows
an administrator to enable/disable them before running an analysis.

The MISP URL and API key are read from 'config/decipher-settings.yaml' and can
be overridden per invocation. Enabling or disabling a warninglist requires a
MISP user with administrative privileges.

Run examples:
    python -m decipher.tools.warninglists_mgr list
    python -m decipher.tools.warninglists_mgr enable
    python -m decipher.tools.warninglists_mgr enable --names "Shodan IP Ranges Used for Scanning"
    python -m decipher.tools.warninglists_mgr disable --ids 98 99
"""

import argparse
import sys

from pymisp import PyMISP, PyMISPError

from decipher.settings import MISP_API_KEY, MISP_TIMEOUT, MISP_URL, MISP_VERIFY_SSL
from decipher.tools.wrnlst_defaults import SCANNING_WARNINGLISTS

ADMIN_RIGHTS_HINT = "Managing MISP warninglists requires an admin user's API key."


def _as_bool(value: object) -> bool:
    """Interpret a MISP flag, returned either as a boolean or as a "0"/"1" string."""
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true")


def _is_permission_error(errors: object) -> bool:
    """Tell whether a MISP error payload denotes a lack of privileges."""
    reported = str(errors).lower()
    return any(hint in reported for hint in ("403", "not authorised", "not authorized", "unauthorized"))


def _fetch_warninglists(misp: PyMISP) -> list[dict]:
    """Retrieve the warninglist index of the MISP instance.

    Returns:
        The "Warninglist" entries of the index, empty if it cannot be read.
    """
    try:
        warninglists = misp.warninglists()
    except (PyMISPError, KeyError) as e:
        # pymisp raises a KeyError when MISP answers the index request with an error payload
        print(f"Could not retrieve the warninglist index from MISP: {e}")
        return []

    if isinstance(warninglists, dict):
        warninglists = warninglists.get("Warninglists", [])

    return [entry["Warninglist"] for entry in warninglists if isinstance(entry, dict) and "Warninglist" in entry]


def list_warninglists(misp: PyMISP) -> list[tuple[int, str, bool]]:
    """Retrieve the warninglists available in MISP with their current state.

    Returns:
        (id, name, enabled) of each warninglist, sorted by ID.
    """
    entries = [(int(warninglist["id"]), warninglist["name"], _as_bool(warninglist.get("enabled"))) 
               for warninglist in _fetch_warninglists(misp)]
    return sorted(entries)


def resolve_warninglists(misp: PyMISP, names: list[str] | None = None, ids: list[int] | None = None) -> tuple[list[tuple[int, str]], list[str]]:
    """Match the requested warninglists against the index of the MISP instance.

    Names are matched exactly first, then ignoring case. An unmatched or
    ambiguous request is reported rather than resolved to an arbitrary
    warninglist, so that a typo cannot silently act on a different list.

    Args:
        misp: Connected PyMISP client
        names: Names of the requested warninglists
        ids: IDs of the requested warninglists

    Returns:
        The (id, name) pairs matched in the instance, and the requests that
        could not be matched.
    """
    index = _fetch_warninglists(misp)
    names_by_id = {int(warninglist["id"]): warninglist["name"] for warninglist in index}
    ids_by_name = {warninglist["name"]: int(warninglist["id"]) for warninglist in index}

    candidates_by_lowercase: dict[str, list[tuple[int, str]]] = {}
    for name, warninglist_id in ids_by_name.items():
        candidates_by_lowercase.setdefault(name.lower(), []).append((warninglist_id, name))

    matched: list[tuple[int, str]] = []
    unmatched: list[str] = []

    for warninglist_id in ids or []:
        if warninglist_id in names_by_id:
            matched.append((warninglist_id, names_by_id[warninglist_id]))
        else:
            print(f"No warninglist with ID {warninglist_id} in this MISP instance.")
            unmatched.append(str(warninglist_id))

    for name in names or []:
        if name in ids_by_name:
            matched.append((ids_by_name[name], name))
            continue

        candidates = candidates_by_lowercase.get(name.strip().lower(), [])
        if len(candidates) == 1:
            matched.append(candidates[0])
        elif candidates:
            print(f'"{name}" matches several warninglists: {", ".join(candidate for _, candidate in candidates)}. Use --ids to select one.')
            unmatched.append(name)
        else:
            print(f'No warninglist named "{name}" in this MISP instance. Run the "list" command to see the available ones.')
            unmatched.append(name)

    return matched, unmatched


def _toggle_warninglists(misp: PyMISP, warninglists: list[tuple[int, str]], enable: bool) -> list[str]:
    """Enable or disable the given warninglists in MISP.

    Each list is toggled individually so that a failure on one of them does not
    prevent the remaining ones from being processed.

    Args:
        misp: Connected PyMISP client
        warninglists: (id, name) pairs of the warninglists to toggle
        enable: True to enable the warninglists, False to disable them

    Returns:
        Labels "(id: name)" of the warninglists successfully toggled
    """
    action = "enable" if enable else "disable"
    toggle = misp.enable_warninglist if enable else misp.disable_warninglist
    toggled = []
    admin_rights_reported = False

    for warninglist_id, name in warninglists:
        response = toggle(warninglist_id)

        if isinstance(response, dict) and "errors" in response:
            if _is_permission_error(response["errors"]) and not admin_rights_reported:
                print(ADMIN_RIGHTS_HINT)
                admin_rights_reported = True
                break
            print(f"FAILED to {action} warninglist {warninglist_id} ({name}): {response['errors']}")
            continue

        toggled.append(f"({warninglist_id}: {name})")

    return toggled


def enable_warninglists(misp: PyMISP, warninglists: list[tuple[int, str]]) -> list[str]:
    """Enable the given warninglists in MISP.

    Args:
        misp: Connected PyMISP client
        warninglists: (id, name) pairs of the warninglists to enable

    Returns:
        Labels "(id: name)" of the warninglists successfully enabled
    """
    return _toggle_warninglists(misp, warninglists, enable=True)


def disable_warninglists(misp: PyMISP, warninglists: list[tuple[int, str]]) -> list[str]:
    """Disable the given warninglists in MISP.

    Args:
        misp: Connected PyMISP client
        warninglists: (id, name) pairs of the warninglists to disable

    Returns:
        Labels "(id: name)" of the warninglists successfully disabled
    """
    return _toggle_warninglists(misp, warninglists, enable=False)


def _resolve_connection(args: argparse.Namespace) -> tuple[str, str, bool, int]:
    """Determine the MISP connection parameters from the CLI arguments and the DECIPHER settings.

    Returns:
        URL, API key, SSL verification flag and timeout of the MISP instance.
    """
    url = args.url or MISP_URL
    api_key = args.api_key or MISP_API_KEY
    verify_ssl = False if args.no_verify_ssl else MISP_VERIFY_SSL

    if not url:
        print("No MISP URL configured. Set 'misp.url' in config/decipher-settings.yaml or pass --url.")
        sys.exit(1)
    if not api_key:
        print("No MISP API key configured. Set 'misp.api_key' in config/decipher-settings.yaml or pass --api-key.")
        sys.exit(1)

    return url, api_key, verify_ssl, MISP_TIMEOUT


def _connect(url: str, api_key: str, verify_ssl: bool, timeout: int) -> PyMISP:
    """Connect to the MISP instance, exiting with an error if it is unreachable."""
    try:
        return PyMISP(url, api_key, verify_ssl, timeout=timeout)
    except PyMISPError as e:
        print(f"Could not connect to MISP at {url}: {e}")
        sys.exit(1)


def _print_index(misp: PyMISP) -> int:
    """Print the warninglists available in MISP with their current state.

    Returns:
        The exit code of the "list" command.
    """
    warninglists = list_warninglists(misp)
    if not warninglists:
        return 1

    print(f"{'ID':>5}  {'ENABLED':<7}  NAME")
    for warninglist_id, name, enabled in warninglists:
        print(f"{warninglist_id:>5}  {'yes' if enabled else 'no':<7}  {name}")
    print(f"\n{sum(1 for _, _, enabled in warninglists if enabled)} of {len(warninglists)} warninglists enabled")

    return 0


def _build_parser() -> argparse.ArgumentParser:
    """Build the CLI parser with one subcommand per action."""
    connection = argparse.ArgumentParser(add_help=False)
    connection.add_argument("--url", help="MISP instance URL (default: 'misp.url' from config/decipher-settings.yaml)")
    connection.add_argument("--api-key", help="MISP API key of an admin user (default: 'misp.api_key' from config/decipher-settings.yaml)")
    connection.add_argument("--no-verify-ssl", action="store_true", help="Skip SSL certificate verification, overriding 'misp.verify_ssl'")

    parser = argparse.ArgumentParser(description="Enable or disable the MISP warninglists used by the DECIPHER analyzers (requires an admin API key)")
    subparsers = parser.add_subparsers(dest="action", required=True)

    subparsers.add_parser("list", parents=[connection], help="List the warninglists available in MISP with their current state")

    for action in ("enable", "disable"):
        subparser = subparsers.add_parser(action, parents=[connection], help=f"{action.capitalize()} the given warninglists")
        selection = subparser.add_mutually_exclusive_group()
        selection.add_argument("--names", nargs="+", help=f"Names of the warninglists to {action} (default: the warninglists used by the analyzers)")
        selection.add_argument("--ids", type=int, nargs="+", help=f"IDs of the warninglists to {action}, as reported by the 'list' command")

    return parser


def main() -> None:
    """Main entry point - list, enable or disable warninglists in MISP."""
    args = _build_parser().parse_args()
    url, api_key, verify_ssl, timeout = _resolve_connection(args)

    print(f"MISP URL: {url}")
    misp = _connect(url, api_key, verify_ssl, timeout)

    if args.action == "list":
        sys.exit(_print_index(misp))

    names = None if args.ids else (args.names or SCANNING_WARNINGLISTS)
    warninglists, unmatched = resolve_warninglists(misp, names=names, ids=args.ids)

    if not warninglists:
        print("No existing warninglists selected.")
        sys.exit(1)

    handler = enable_warninglists if args.action == "enable" else disable_warninglists
    toggled = handler(misp, warninglists)

    print(f"\n{args.action.capitalize()}d {len(toggled)} "
          f"of {len(warninglists)} matched warninglists")
    print(*toggled, sep="\n")

    if unmatched:
        print(f"\n{len(unmatched)} warninglist(s) not found in this MISP instance")
        print(*unmatched, sep="\n")
    else:
        print("All the given warninglists were found.")

    sys.exit(0 if len(toggled) == len(warninglists) else 1)


if __name__ == "__main__":
    main()
