"""
Simulated suspicious login events for testing DECIPHER analysis functionality.

Creates 5 test events with varying severity levels and IOCs that can be
used to test MISP integration for IOC lookups in the suspicious login analyzer.

NOTES:
- The tags used in the events have to be enabled for the user creating the events 
in the targeted MISP instance by an administrator.
If tags are not enabled, the events will be created without tags.
"""

from pymisp import PyMISP, MISPEvent
import argparse
import random

from datetime import datetime, timedelta


# Base timestamp for events (staggered over 24 hours)
BASE_TIME = datetime.now()

# Simulated suspicious login alerts matching SuspiciousLoginAlert
# Each event represents a different severity scenario for testing
SIMULATED_EVENTS = [
    {
        # Event 1: CRITICAL - Privileged account + known malicious IP
        "name": "[TEST] Critical: Root login from known malicious IP",
        "description": "Attempted root login from TOR exit node to production database server",
        "alert_data": {
            "username": "root",
            "target_host": "10.0.0.1",
            "src_ips": ["185.220.100.1", "185.220.100.42"],
            "timestamp": (BASE_TIME - timedelta(hours=2)).isoformat(),
        },
        "misp_attributes": [
            {"type": "ip-src", "value": "185.220.100.1", "comment": "TOR exit node - known malicious"},
            {"type": "ip-src", "value": "185.220.100.42", "comment": "TOR exit node - same /22 block"},
            {"type": "ip-dst", "value": "10.0.0.1", "comment": "Production database server"},
            {"type": "target-user", "value": "root", "comment": "Privileged account targeted"},
            {"type": "text", "value": "ssh-brute-force", "comment": "Attack pattern indicator"},
        ],
        "tags": ["tlp:red", "type:CYBINT"],
        "expected_severity": "high",
        "analysis_stage": 1 # in progress
    },
    {
        # Event 2: HIGH - Known malicious IP targeting sensitive auth server
        "name": "[TEST] High: Malicious IP targeting authentication server",
        "description": "Login attempt from flagged IP address to authentication infrastructure",
        "alert_data": {
            "username": "svc_backup",
            "target_host": "auth-server",
            "src_ips": ["45.33.32.156"],
            "timestamp": (BASE_TIME - timedelta(hours=6)).isoformat(),
        },
        "misp_attributes": [
            {"type": "ip-src", "value": "45.33.32.156", "comment": "Known scanner IP (Shodan)"},
            {"type": "target-machine", "value": "auth-server", "comment": "Critical authentication infrastructure"},
            {"type": "target-user", "value": "svc_backup", "comment": "Service account"},
            {"type": "domain", "value": "scanme.nmap.org", "comment": "Associated domain"},
        ],
        "tags": ["tlp:amber"],
        "expected_severity": "high",
        "analysis_stage": 0 # initial
    },
    {
        # Event 3: HIGH - Multiple IPs from bad ranges + privileged account
        "name": "[TEST] High: Admin login from suspicious IP ranges",
        "description": "Administrator account accessed from IPs in known bad ranges",
        "alert_data": {
            "username": "admin",
            "target_host": "192.168.1.50",
            "src_ips": ["45.155.204.100", "45.155.204.101", "185.220.101.5"],
            "timestamp": (BASE_TIME - timedelta(hours=12)).isoformat(),
        },
        "misp_attributes": [
            {"type": "ip-src", "value": "45.155.204.100", "comment": "IP in known bad range"},
            {"type": "ip-src", "value": "45.155.204.101", "comment": "IP in known bad range - same subnet"},
            {"type": "ip-src", "value": "185.220.101.5", "comment": "TOR infrastructure"},
            {"type": "target-user", "value": "admin", "comment": "Administrator account"},
            {"type": "text", "value": "credential-stuffing", "comment": "Suspected attack type"},
            {"type": "md5", "value": "d41d8cd98f00b204e9800998ecf8427e", "comment": "Empty file hash - test IOC"},
        ],
        "tags": ["tlp:amber", "type:HUMINT"],
        "expected_severity": "undefined",
        "analysis_stage": 1 # in progress
    },
    {
        # Event 4: MEDIUM - Privileged account from unflagged IP
        "name": "[TEST] Medium: DBA login from unusual location",
        "description": "Database administrator login from unrecognized IP during off-hours",
        "alert_data": {
            "username": "dba",
            "target_host": "db-test-01",
            "src_ips": ["192.168.10.15", "192.168.10.16"],
            "timestamp": (BASE_TIME - timedelta(hours=18)).isoformat(),
        },
        "misp_attributes": [
            {"type": "ip-src", "value": "192.168.10.15", "comment": "Documentation range - simulated external IP", "tags": [{"name": "admiralty-scale:information-credibility=\"5\""}]},
            {"type": "ip-src", "value": "192.168.10.16", "comment": "Documentation range - adjacent"},
            
            {"type": "target-user", "value": "dba", "comment": "Database administrator"},
            {"type": "target-machine", "value": "db-test-01", "comment": "Test database server"},
            {"type": "email-src", "value": "dba@example.com", "comment": "Associated email IOC"},
        ],
        "tags": [
            {"name": "misp-galaxy:mitre-attack-pattern=\"Brute Force - T1110\""},
            {"name": "admiralty-scale:source-reliability=\"a\""},
            {"name": "admiralty-scale:information-credibility=\"2\""},
            {"name": "tlp:amber"},
            {"name": "type:OSINT"}
        ], 
        "expected_severity": "medium",
        "analysis_stage": 2 # completed
    },
    {
        # Event 5: LOW - Normal user, non-sensitive host, clean IPs
        "name": "[TEST] Low: Regular user login from corporate network",
        "description": "Standard user login from internal network - baseline event for testing",
        "alert_data": {
            "username": "jsmith",
            "target_host": "workstation-42",
            "src_ips": ["146.112.61.105"],
            "timestamp": (BASE_TIME - timedelta(hours=24)).isoformat(),
        },
        "misp_attributes": [
            {"type": "ip-src", "value": "146.112.61.105", "comment": "Internal corporate IP"},
            {"type": "target-user", "value": "jsmith", "comment": "Regular user account"},
            {"type": "target-machine", "value": "workstation-42", "comment": "Standard workstation"},
        ],
        "tags": ["tlp:amber", "type:OSINT"],
        "expected_severity": "low",
        "analysis_stage": 2 # completed
    }
]


def _severity_to_threat_level(severity: str) -> int:
    """Map severity string to MISP threat level ID."""
    mapping = {
        "high": 1,
        "medium": 2,
        "low": 3,
        "undefined": 4
    }
    return mapping.get(severity.lower(), 4)


def create_misp_events(misp: PyMISP, dry_run: bool = True) -> list[MISPEvent]:
    created_events = []
    
    for event_data in SIMULATED_EVENTS:
        event = MISPEvent()
        event.info = event_data["name"]
        event.distribution = 0
        event.threat_level_id = _severity_to_threat_level(event_data["expected_severity"])
        event.analysis = event_data.get("analysis_stage", random.randint(0, 2))
        
        for attr in event_data["misp_attributes"]:
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
        
        if not dry_run:
            event = misp.add_event(event, pythonify=True)
            
            if event.id:
                created_events.append(event.id)
                print(f"Event created with ID: {event.id}")

                # Add event-level tags
                for tag in event_data.get("tags", []):
                    misp.tag(event, tag)

                # Add attribute-level tags
                for attribute, attr_data in zip(event.attributes, event_data["misp_attributes"]):
                    for tag in attr_data.get("tags", []):
                        misp.tag(attribute, tag)  # pass the attribute object, not the event

                print(f"Updated event: {event.info} with {len(event.attributes)} attributes and tags {event.tags}")
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
    args = parser.parse_args()
    
    print(f"MISP URL: {args.url}")
    print(f"Dry run: {not args.push}")
    
    misp = PyMISP(args.url, args.api_key, ssl=False, timeout=15)
    created = create_misp_events(misp, dry_run=not args.push)
    
    print(f"\n{'Created' if args.push else 'Would create'} {len(created)} events")
    
    if not args.push:
        print("\nTo actually push events to MISP, run with --push flag")


if __name__ == "__main__":
    main()
