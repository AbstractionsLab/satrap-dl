"""
Simulated events for testing DECIPHER analysis functionality.

Creates test events with varying severity levels and IOCs that can be
used to test MISP integration for IOC lookups in the DECIPHER analyzers.

The event definitions are read from a JSON file (by default
`tests/decipher/data/web_scanning_events.json`).

NOTES:
- The tags used in the events have to be enabled for the user creating the events 
in the targeted MISP instance by an administrator.
If tags are not enabled, the events will be created without tags.

Run example:
    python events_simulator.py --url https://host.docker.internal:50001 --api-key <key> --push
"""

from datetime import datetime, timedelta

from pymisp import MISPAttribute, MISPEvent, MISPObject, PyMISP
import argparse
import json
import random

from pathlib import Path


DEFAULT_EVENTS_PATH = Path(__file__).parent.parent / "data" / "web_scanning_events.json"


def load_events(events_path: Path) -> list[dict]:
    """Load the simulated suspicious login alerts from a JSON file."""
    with open(events_path, "r") as f:
        return json.load(f)


def _severity_to_threat_level(severity: str) -> int:
    """Map severity string to MISP threat level ID."""
    mapping = {
        "high": 1,
        "medium": 2,
        "low": 3,
        "undefined": 4
    }
    return mapping.get(severity.lower(), 4)


def _build_object(obj_data: dict) -> MISPObject:
    """
    Build a MISP object from its JSON definition.

    The object template is not enforced, so the attribute type has to be given
    explicitly for each object relation.
    """
    misp_object = MISPObject(obj_data["name"], strict=False)
    misp_object.comment = obj_data.get("comment", "")

    for attr in obj_data.get("attributes",[]):
        misp_object.add_attribute(
            attr["object_relation"],
            value=attr["value"],
            type=attr.get("type"),
            comment=attr.get("comment", ""),
        )

    return misp_object


def _add_sightings(misp: PyMISP, attribute: MISPAttribute, sightings: dict) -> None:
    """
    Register true and false positive sightings for an attribute.

    MISP has no bulk sighting endpoint, so one call per sighting is needed.
    Sighting type "0" is a true positive and "1" a false positive.
    """
    for sighting_type, count in (("0", sightings.get("true_positives", 0)),
                                 ("1", sightings.get("false_positives", 0))):
        for _ in range(count):
            misp.add_sighting(
                {"type": sighting_type, "source": "DECIPHER event simulator"},
                attribute=attribute,
            )

    if sightings:
        print(f"  Sightings added for {attribute.value}: {sightings}")


def create_misp_events(misp: PyMISP, events: list[dict], dry_run: bool = True) -> list[MISPEvent]:
    created_events = []
    
    for event_data in events:
        event = MISPEvent()
        event.info = event_data["name"]
        event.distribution = 0
        event.threat_level_id = _severity_to_threat_level(event_data["expected_severity"])
        event.analysis = event_data.get("analysis_stage", random.randint(0, 2))
        # time of the event set to the ingestion time minus some delta if defined in the event
        event.timestamp = (datetime.now() - timedelta(hours=event_data.get("timedelta",0))).isoformat()
        
        for attr in event_data.get("misp_attributes", []):
            attribute = event.add_attribute(
                attr["type"],
                attr["value"],
                comment=attr.get("comment", ""),
                to_ids=attr["type"] in ("ip-src", "ip-dst", "md5", "sha256", "domain"),
            )
            # Dry-run path: add attribute-level tags directly to the object
            if dry_run:
                for tag in attr.get("tags", []):
                    attribute.add_tag(tag)

        for obj_data in event_data.get("misp_objects", []):
            event.add_object(_build_object(obj_data))
        
        if not dry_run:
            event = misp.add_event(event, pythonify=True)
            
            if event.id:
                created_events.append(event.id)
                print(f"Event created with ID: {event.id}")

                # Add event-level tags
                for tag in event_data.get("tags", []):
                    misp.tag(event, tag)

                # Add attribute-level tags and sightings
                for attribute, attr_data in zip(event.attributes, event_data.get("misp_attributes",[])):
                    for tag in attr_data.get("tags", []):
                        misp.tag(attribute, tag)  # pass the attribute object, not the event
                    _add_sightings(misp, attribute, attr_data.get("sightings", {}))

                print(f"Updated event: {event.info} with {len(event.attributes)} attributes, {len(event.objects)} objects, and tags {event.tags}")
            else:
                print(f"Failed to create event: {event_data['name']}")
        else:
            for tag in event_data.get("tags", []):
                event.add_tag(tag)
            created_events.append(event)
            print(f"[DRY RUN] Would create event: {event_data['name']}")
    
    return created_events


def main():
    """Main entry point - create events or run in dry-run mode."""
    
    parser = argparse.ArgumentParser(description="Create MISP test events for DECIPHER testing")
    parser.add_argument("--url", required=True, help="MISP instance URL")
    parser.add_argument("--api-key", required=True, help="MISP API key")
    parser.add_argument("--push", action="store_true", help="Push events to MISP (default: dry run)")
    parser.add_argument("--events-file", type=Path, default=DEFAULT_EVENTS_PATH,
                        help=f"JSON file with the event definitions (default: {DEFAULT_EVENTS_PATH})")
    args = parser.parse_args()
    
    print(f"MISP URL: {args.url}")
    print(f"Events file: {args.events_file}")
    print(f"Dry run: {not args.push}")
    
    events = load_events(args.events_file)
    
    misp = PyMISP(args.url, args.api_key, ssl=False, timeout=15)
    created = create_misp_events(misp, events, dry_run=not args.push)
    
    print(f"\n{'Created' if args.push else 'Would create'} {len(created)} events")
    
    if not args.push:
        print("\nTo actually push events to MISP, run with --push flag")


if __name__ == "__main__":
    main()
