"""
This module defines query statements and constant strings used by the CTI engine.
"""

## MITRE ATT&CK ID formats

# Represented with standard STIX2.1 objects
CAMPAIGN_ID_FORMAT = "C[0-9]{4}"
GROUP_ID_FORMAT = "G[0-9]{4}"
MITIGATION_ID_FORMAT = "M[0-9]{4}"
SOFTWARE_ID_FORMAT = "S[0-9]{4}"
SUBTECHNIQUE_ID_FORMAT = "T[0-9]{4}.[0-9]{3}"
TECHNIQUE_ID_FORMAT = "T[0-9]{4}"

# Represented with custom STIX types
ASSET_ID_FORMAT = "A[0-9]{4}"
DATA_SRC_ID_FORMAT = "DS[0-9]{4}"
TACTIC_ID_FORMAT = "TA[0-9]{4}"

ATTCK_TO_STIX = {
	"campaign": "campaign",
	"group": "intrusion-set",
	"mitigation": "course-of-action",
	"software": ["malware", "tool"],
	"subtechnique": "attack-pattern",
	"technique": "attack-pattern"
}

## TypeQL
EXT_REF_VAR = "$exref"
EXT_ID_VAR = "$eid"

MATCH = "match\n"
NOT_REVOKED = "has revoked false;\n"
IS_EXT_REFERENCE = "isa external-reference"
EXT_REFERENCING_REL = " isa external-referencing;"
MITRE_ATTCK = "has source-name 'mitre-attack'"

EXT_MITRE_ATTCK = f'{EXT_REF_VAR} {IS_EXT_REFERENCE}, {MITRE_ATTCK};\n'
EXT_REF_ID = f"{EXT_REF_VAR} has external-id "

CREATOR = (
	"$i isa identity;\n"
	"(creator: $i, object-created: {}) isa created-by-ref;\n"
	"fetch $i:{};")

EXT_REF_SRC = (
	f"$er {IS_EXT_REFERENCE};\n"
	"(referrer: {}, referenced: $er) isa external-referencing;\n"
	"fetch $er:{};")

SDOS = (
	f"{MATCH}"
	"$t sub stix-domain-object;\n"
	"$e isa! $t;\n"
	"$e has revoked false;\n"
	"get;\n"
	"group $t;\n"
	"count;")

MITIGATIONS_OF = (
	f"{MATCH}\n"
	"$sdo has stix-id '{}', has name $t;\n"
	"(mitigation: $mitigation, mitigated: $sdo) isa mitigates;\n"
	"$mitigation has stix-id $mitigation-id, has name $mitigation-name;\n"
	"get $mitigation-id, $mitigation-name;\n"
	"sort $mitigation-name;"
)

TECHNIQUES_USED_BY = (
	f"{MATCH}"
	f"$exref {IS_EXT_REFERENCE}, {MITRE_ATTCK};\n"
	"$exref has external-id '{group_id}';\n"
	"$group isa intrusion-set;\n"
	f"$group {NOT_REVOKED}"
	f"(referrer:$group, referenced:$exref){EXT_REFERENCING_REL}\n"
	"$technique isa attack-pattern, has stix-id $id, has name {name};\n"
	"$usage (used: $technique, user: $group) isa uses;\n"
)

SEARCH_BY_ATTACK_ID = (
    f"{MATCH}"
	f"$exref {IS_EXT_REFERENCE}, {MITRE_ATTCK};\n"
	"$exref has external-id '{mitre_attck_id}';\n"
    "(referrer: ${var}, referenced: $exref)"f"{EXT_REFERENCING_REL}"
)

MITIGATIONS_REL_TECHNIQUE = (
	f"{MATCH}"
	"$intrusion-set isa intrusion-set, has name '{}';\n"
	"$r (source-role: $course-of-action, target-role: $intrusion-set) isa related-to;\n"
	"$course-of-action isa course-of-action, has stix-id $sid, "
	"has name $mitigation-name;\n"
	"get;"
)

# Match all courses of action that relate to a given intursion set,
# addressing the mitigation of a specific SDO.
RELATED_MITIGATIONS_VIA_SDO = (
	f"{MATCH}"
    "$intrusion-set isa intrusion-set, has name '{}';\n"
    "$sdo isa stix-domain-object, has stix-id '{}', has name $t_name;\n"
    "$mitigation (mitigation: $course-of-action, mitigated: $sdo) isa mitigates;\n"
    "$r (source-role: $course-of-action, target-role: $intrusion-set) isa related-to;\n"
    "$course-of-action isa course-of-action, has name $name;\n"
	"get;"
)

EXPLAIN_REL_MITIGATION = (
	f"{MATCH}"
	"$intrusion-set isa intrusion-set, has stix-id '{}', has name $group-name;\n"
	"$course-of-action isa course-of-action, has stix-id '{}', has name $mitigation-name;\n"
	"$r (source-role: $course-of-action, target-role: $intrusion-set) isa related-to;\n"
	"get;"
)
