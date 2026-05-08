# DECIPHER fundamentals

DECIPHER implements a structured incident handling workflow with key phases reflected in its name:

### Detection (D)

Security controls (SIEM, EDR, WAF) detect suspicious activity and generate alerts. These alerts are the input to DECIPHER.

**Example:** Wazuh detects 5 failed SSH login attempts followed by a successful login from an external IP.

### Enrichment (E)

Indicators from the alert (IPs, domains, file hashes) are enriched with threat intelligence from MISP. This provides context about known threats.

Enrichment results depend on the selected scenario and might include for instance:

- IPs
- Associated threat actors (APT28, Lazarus, etc.)
- Sightings count (how many times seen in CTI)
- Related advisories and CVEs

### Correlation (C)

Enriched data is correlated to determine if the alert represents a credible threat. Scoring factors are combined to produce a severity score.

**Correlation factors from MISP:**

- Threat level assigned to the event containing the indicators
- Admiralty Scale rating
- Sightings: number of positive versus negative sightings
- Tags indicating a threat, such as an identified MITRE ATT&CK attack pattern or an intrusion set.
- Stage of the analysis investigation (early analysis phase vs confirmed compromise)

### Incident (I)

Alerts meeting severity thresholds are escalated to incident cases. Cases consolidate related alerts and provide incident responders with a prioritized workload.

### Playbook (P)

Response playbooks can be attached to cases to guide incident responders depending on the threat scenario. Some example of Playbooks include:

- Organization and environment-specific response procedures
- MISP playbooks for known threat scenarios
- SATRAP playbooks for further automated analysis

### Handling (H)

Incident responders execute the playbooks and manage the case through resolution. DECIPHER provides guidelines e.g., based on templates, but leaves final decisions to human analysts.

### Escalation (E)
DECIPHER supports escalation and triage of incidents to helping to maintain a prioritized case repository.

### Recovery (R)

After incident containment, recovery and remediation actions are executed. DECIPHER may support tracking recovery actions (e.g. in the case management system) but does not automate them. 

For full automation of the DECIPHER pipeline, including recovery actions, we strongly recommend integration with [RADAR](https://github.com/AbstractionsLab/idps-escape/tree/main/docs/manual/radar_docs).

<br/>

[Back to home](/docs/manual/decipher/README.md)
