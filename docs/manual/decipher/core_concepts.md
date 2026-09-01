# DECIPHER fundamentals

DECIPHER implements a structured incident handling workflow with key phases reflected in its name:

## Detection (D)

Security controls (SIEM, EDR, WAF) detect suspicious activity and generate alerts. These alerts are the input to DECIPHER.

**Example:** Wazuh detects 5 failed SSH login attempts followed by a successful login from an external IP.

## Enrichment (E)

Indicators from the alert (IPs, domains, file hashes) are enriched with threat intelligence from MISP. This provides context about known threats.

The indicators searched depend on the selected scenario, for instance source and destination IP addresses and the target user for a suspicious login, or source IP addresses, probed URIs, user agents and HTTP methods for web scanning. For every MISP event matching at least one indicator, DECIPHER retrieves the elements that feed the scoring:

- Event identifier, threat level and analysis stage
- Tags identifying a threat, namely the MITRE ATT&CK attack pattern and intrusion set galaxies
- Admiralty scale tags of the event and of each matched attribute
- True and false positive sightings recorded on each matched attribute

The identifiers of the matched events are reported in the analysis result, so that an analyst can open them in MISP and read the full intelligence.

## Correlation (C)

Enriched data is correlated to determine if the alert represents a credible threat. Scoring factors are combined to produce a severity score.

**Correlation factors from MISP:**

- Threat level assigned to the event containing the indicators
- Admiralty Scale rating
- Sightings: number of positive versus negative sightings
- Tags indicating a threat, such as an identified MITRE ATT&CK attack pattern or an intrusion set.
- Stage of the analysis investigation (early analysis phase vs confirmed compromise)

## Incident (I)

Analyzed alerts are escalated to incident cases in the case management system, carrying the analysis report and a priority tag. The severity score determines the priority tag rather than whether a case is opened: when case creation is enabled, a case is created for every analyzed alert, including alerts scoring below the lowest threshold, which are tagged as baseline-minor. An analyzer may nevertheless suppress the case when the analysis found no evidence at all, as the suspicious web scanning scenario does.

Cases consolidate the outcome of the analysis and provide incident responders with a prioritized workload.

## Playbook (P)

Response playbooks can be attached to cases to guide incident responders depending on the threat scenario. Some example of Playbooks include:

- Organization and environment-specific response procedures
- MISP playbooks for known threat scenarios
- SATRAP playbooks for further automated analysis

Attaching a playbook to a case is a manual step today. DECIPHER opens the case and leaves the choice of playbook to the responder.

## Handling (H)

Incident responders execute the playbooks and manage the case through resolution. DECIPHER provides guidelines e.g., based on templates, but leaves final decisions to human analysts.

## Escalation (E)
DECIPHER supports escalation and triage of incidents to helping to maintain a prioritized case repository.

## Recovery (R)

After incident containment, recovery and remediation actions are executed. DECIPHER may support tracking recovery actions (e.g. in the case management system) but does not automate them. 

For full automation of the DECIPHER pipeline, including recovery actions, we strongly recommend integration with [RADAR](https://github.com/AbstractionsLab/idps-escape/tree/main/docs/manual/radar_docs).

<br/>

[Back to home](/docs/manual/decipher/README.md)
