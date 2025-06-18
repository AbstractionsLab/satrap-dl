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


## Representation of ATT&CK elements in STIX
ATTCK_TO_STIX = {
	"campaign": "campaign",
	"group": "intrusion-set",
	"mitigation": "course-of-action",
	"software": ["malware", "tool"],
	"subtechnique": "attack-pattern",
	"technique": "attack-pattern"
}


## TypeQL
XREF_VAR = "$exref"
XREF_ID_VAR = "$eid"

MATCH = "match\n"
NOT_REVOKED = "has revoked false"
IS_EXT_REFERENCE = "isa external-reference"
EXT_REFERENCING_REL = " isa external-referencing;"
MITRE_ATTCK = "has source-name 'mitre-attack'"

XREF_IS_MITRE_ATTCK = f'{XREF_VAR} {IS_EXT_REFERENCE}, {MITRE_ATTCK};\n'
XREF_HAS_ID = f"{XREF_VAR} has external-id "

CREATOR = (
	"$i isa identity;\n"
	"(creator: $i, object-created: {}) isa created-by-ref;\n"
	"fetch $i:{};")

EXT_REF_SRC = (
	f"$er {IS_EXT_REFERENCE};\n"
	"(referrer: {referrer_var}, referenced: $er) isa external-referencing;\n"
	"fetch $er:{source_name};")

SDOS = (
	f"{MATCH}"
	"$t sub stix-domain-object;\n"
	"$e isa! $t;\n"
	"$e has revoked false;\n"
	"get;\n"
	"group $t;\n"
	"count;")

# Match STIX objects that have an external reference
# and are not revoked, plus the constraints given as filters
JOIN_STIX_ATTCK = (
    f"$exref has external-id {XREF_ID_VAR};\n"
	"${stix_type} isa {stix_type}"f", {NOT_REVOKED};\n"
    "{filters}"
    "$rel (referrer: ${stix_type}, referenced: "f"{XREF_VAR})"
    " isa external-referencing;"
)

MITIGATIONS_OF = (
	f"{MATCH}\n"
	"$sdo has stix-id '{}', has name $t;\n"
	"(mitigation: $mitigation, mitigated: $sdo) isa mitigates;\n"
	"$mitigation has stix-id $mitigation-id, has name $mitigation-name;\n"
	"get $mitigation-id, $mitigation-name;\n"
	"sort $mitigation-name;"
)

SEARCH_BY_ATTACK_ID = (
	f"$exref {IS_EXT_REFERENCE}, {MITRE_ATTCK};\n"
	"$exref has external-id '{mitre_attck_id}';\n"
    "(referrer: ${var}, referenced: $exref)"f"{EXT_REFERENCING_REL}"
)

# Filter the selected groups, then match techniques used by those groups
TECHNIQUES_USED_BY = (
	f"$exref {IS_EXT_REFERENCE}, {MITRE_ATTCK};\n"
	"$exref has external-id like '^({group_ids})$';\n"
	f"(referrer:$group, referenced:$exref){EXT_REFERENCING_REL}\n"
	"$group isa intrusion-set;\n"
	f"$group {NOT_REVOKED};\n"
	"(used: $technique, user: $group) isa uses;\n"
	"$technique isa attack-pattern, has stix-id $id;"
)

MITIGATIONS_REL_TECHNIQUE = (
	f"{MATCH}"
	"$intrusion-set isa intrusion-set, has name '{}';\n"
	"$r (source-role: $course-of-action, target-role: $intrusion-set) isa related-to;\n"
	"$course-of-action isa course-of-action, has stix-id $sid, "
	"has name $mitigation-name;\n"
	"get;"
)

# Match all courses of action that relate to a given intrusion set,
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

# IDs of the MITRE ATT&CK techniques and the SDOs (attack-pattern)
# associated with them.
TECHNIQUES_AS_STIX = (
	f"{XREF_IS_MITRE_ATTCK}"
	f"{XREF_HAS_ID}like '{TECHNIQUE_ID_FORMAT}';\n"
	f"{XREF_HAS_ID}{XREF_ID_VAR};\n"
	"$t isa attack-pattern, has name $t_name;\n"
    "{revoked}"
	f"$rel (referrer: $t, referenced: {XREF_VAR})"
    f"{EXT_REFERENCING_REL}"
)

SDOS_BY_NAME_OR_ALIAS = (
	f"{MATCH}"
	"$sdo has alias $a, has name $n, has stix-id $id,\n"
	f"{NOT_REVOKED};\n"
	"{$n contains '{pattern}';} or {$a contains '{pattern}';};\n"
	"fetch $n; $id; $sdo:alias;"
)


## Auxiliary functions

def build_match_clause(pattern):
    return f"match\n{pattern}\n"