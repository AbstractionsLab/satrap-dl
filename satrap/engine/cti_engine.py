"""This module provides the CTIEngine class, responsible for
supporting Cyber Threat Intelligence (CTI) analysis tasks.
"""

from re import match

from typedb.driver import Entity

from satrap.datamanagement.typedb.typedb_constants import NON_EMPTY_DB, NON_EMPTY_SERVER
from satrap.datamanagement.typedb.typedbhandler import TypeDBHandler
import satrap.engine.query_statements as cons
from satrap.engine.result_structures import Group, InferredAnswer, Mnemonic
from satrap.commons.log_utils import logger


class CTIEngine:
    """
    CTIEngine is responsible for providing functionality to assist with CTI analysis.

    Attributes:
        db_manager (TypeDBHandler): An instance of TypeDBHandler to interact with the CTI database.
    """

    def __init__(self, db_uri: str, db_name: str):
        self.server_address = db_uri
        self.database_name = db_name
        self.db_manager = None

    def __enter__(self):
        """
        :raises ValueError: if the creation of the TypeDBHandler fails
        """
        if not self.server_address:
            raise ValueError(NON_EMPTY_SERVER)
        if not self.database_name:
            raise ValueError(NON_EMPTY_DB)

        self.db_manager = TypeDBHandler(self.server_address, self.database_name)
        return self

    def __exit__(self, _exception_type, _exception_value, traceback):
        self.db_manager.close()
        if traceback:
            raise _exception_type(_exception_value)
        return traceback is None

    def _get_common_properties_of(self, stix_obj: Entity):
        properties = self.db_manager.get_attributes_of(stix_obj)
        properties["created-by"] = self.get_creator(properties.get("stix-id", ""))
        properties["external-references sources"] = self.get_external_references_src(
            properties.get("stix-id", "")
        )
        return properties

    def search_obj_by_stix_id(self, stix_id: str) -> dict:
        """
        Search the database for a STIX object with the provided STIX ID. 
        If the object is found, it retrieves its common properties.

        :param stix_id: The STIX ID of the object to search for.
        :type stix_id: str
        :return: A dictionary containing the common properties of the found object,
                 or an empty dictionary if no object is found.
        :rtype: dict
        """
        query = f"{cons.MATCH}$so has stix-id '{stix_id}';" "get $so;"
        stix_obj = self.db_manager.get_query(query)
        if not stix_obj:
            return {}
        properties = self._get_common_properties_of(stix_obj[0].get("so"))
        return properties

    def search_obj_by_attck_id(self, mitre_attck_id: str, ignore_revoked=True) -> list[dict]:
        """
        Provide information of STIX objects associated to a MITRE ATT&CK ID.
        Only STIX objects of the type corresponding to the format of the given ID
        (as per the ATT&CK-stix2.1 specification) are selected. E.g., SDOs 'attack-pattern'
        for IDs of the form "T####".

        :param mitre_attck_id: The MITRE ATT&CK ID to search for.
        :type mitre_attck_id: str
        :raises ValueError: If the format of the given MITRE ATT&CK ID is invalid.

        :returns: A list of dictionaries, each containing the properties of a related STIX object.
        :rtype: list
        """
        res_var = "stix_obj"
        stix_type = CTIEngine._get_stix_type_from_id(mitre_attck_id)

        query = cons.build_match_clause(
            cons.SEARCH_BY_ATTACK_ID.format(
            mitre_attck_id=mitre_attck_id, var=res_var)
        )
        if stix_type is not None:
            # att&ck ids that can be mapped to different stix types (e.g. software)
            if isinstance(stix_type, list):
                query += " or ".join([f"{{${res_var} isa {st};}}" for st in stix_type]) + ";\n"
            else:
                query += f"${res_var} isa {stix_type};\n"
        if ignore_revoked:
            query += f"${res_var} {cons.NOT_REVOKED};\n"
        query += f"get ${res_var};"
        logger.debug("Search query:\n%s" %query)
        
        stix_objs = self.db_manager.get_query(query)
        if not stix_objs:
            return []

        related = []
        for so in stix_objs:
            properties = self._get_common_properties_of(so.get(res_var))
            related.append(properties)
        return related

    def search_obj_by_name_alias(self, name_alias:str) -> list[Mnemonic]:
        if not name_alias:
            return []
        query = cons.SDOS_BY_NAME_OR_ALIAS.replace("{pattern}",name_alias)
        logger.debug("Search by name:\n%s" %query)
        stix_objs = self.db_manager.fetch_query(query)
        if not stix_objs:
            return []
        matches = []
        for r in stix_objs:
            al = r.get("sdo").get("alias")
            aliases = ", ".join([a.get("value") for a in al]) if al else ""
            matches.append(
                Mnemonic(
                    stix_id = r.get('id').get("value"),
                    name = r.get('n').get("value"),
                    aliases = aliases
                )
            )
        return matches

    def get_creator(self, stix_id):
        """
        Retrieves the creator (referred in 'created-by-ref') of a STIX object using its ID.
        """
        query = (
            f"{cons.MATCH}$so has stix-id '{stix_id}';\n"
            f"{cons.CREATOR.format('$so','name')}"
        )
        creator = self.db_manager.get_attribute_value(query, "name")
        return creator[0] if creator else ""

    def get_external_references_src(self, stix_id):
        """
        Gets the names of the sources of a STIX object's external references.

        :param stix_id: The ID of the STIX object.
        :type stix_id: str
        :returns: A dictionary containing the name of the source (report, org, etc.).
        :rtype: dict
        """
        ext_src_name = "source-name"
        query = (
            f"{cons.MATCH}$so has stix-id '{stix_id}';\n"
            f"{cons.EXT_REF_SRC.format(referrer_var='$so', source_name=ext_src_name)}"
        )
        return self.db_manager.get_attribute_value(query, ext_src_name)
    
    def get_mitre_id(self, stix_id: str) -> str:
        """
        Retrieve the MITRE ATT&CK ID associated with a given STIX ID or None if not found.

        :param stix_id: The STIX ID to search for.
        :type stix_id: str
        """
        query = cons.build_match_clause(
            f"$sdo has stix-id '{stix_id}';\n"
            f"(referrer: $sdo, referenced: {cons.XREF_VAR}){cons.EXT_REFERENCING_REL}\n"
            f"{cons.XREF_IS_MITRE_ATTCK}"
            f"{cons.XREF_HAS_ID}$mid;")
        query += f"get $mid;"
        logger.debug("Get MITRE ID:\n%s" %query)
        result = self.db_manager.get_query(query)
        return result[0].get("mid").get_value() if result else None

    def get_stats(self) -> dict:
        """
        Retrieve statistics of non-revoked STIX domain objects (SDOs) in the CTI SKB.

        :returns: A dictionary containing the number of SDOs per type.
        :rtype: dict
        """
        query = cons.SDOS
        return self.db_manager.aggregate_group_query(query)
    
    def get_inference_rule_names(self) -> set:
        """
        Retrieve the names of inference rules from the database.
        """
        return self.db_manager.get_inference_rules()

    def get_techniques_used_by(self, group_ids: list[str], inference=False) -> dict:
        """
        Retrieve techniques found to be used by any of the members of a given set of groups,
        along with the number of groups that use it.

        :param group_id: A list of identifiers of ATT&CK groups.
        :type group_id: list
        :param inference: True if inference should be used in the query; defaults to False.
        :type inference: bool, optional
        :return: A dictionary of pairs [technique-stix-id:usage-count]
        :rtype: dict
        """
        ids = "|".join(group_ids)
        query = cons.build_match_clause(
            cons.TECHNIQUES_USED_BY.format(group_ids=ids))
        query += (
            "get $id, $group;\n"
            "group $id;\n"
            "count;\n"
        )
        logger.debug("Techniques by any group:\n%s" %query)
        data = self.db_manager.aggregate_group_query(query, inference)
        return data
    
    def get_techniques_at_intersection(self, group_ids: list[str], inference=False) -> dict:
        """
        Retrieve techniques found to be used by all the members of a given set of groups.

        :param group_ids: A list of stix identifiers of the groups.
        :type group_ids: list
        :param inference: True if inference should be used in the query; defaults to False.
        :type inference: bool, optional
        :return: A dictionary with pairs [ATT&CK id:name] of the techniques
        :rtype: dict
        """
        # we use 'replace' instead of 'format' to avoid conflicts due to
        # the presence of {} in the TECHNIQUE_ID_FORMAT inner string
        pattern = cons.TECHNIQUES_AS_STIX.replace(
            "{revoked}", f"$t {cons.NOT_REVOKED};\n")
        query = cons.build_match_clause(pattern)
        for i, group_id in enumerate(group_ids):
            query += f"$g{i} isa intrusion-set, has stix-id '{group_id}';\n"
            query += f"(used: $t, user: $g{i}) isa uses;\n"
        query += (
            f"get {cons.XREF_ID_VAR}, $t_name;\n"
            "sort $t_name;"
        )
        logger.debug("Techniques by all groups:\n%s" %query)
        result = self.db_manager.get_query(query, inference)
        return TypeDBHandler.dict_from_answers(result, "eid", "t_name")

    def explain_techniques_used_by(
        self, group_mitre_ids: list[str], technique_stix_id: str = None
    ) -> InferredAnswer:
        """
        Provides explanations tracing the inference rules that are applied to derive
        the set of techniques used by the specified groups. The explanations can be optionally
        filtered by the stix ID of a specific technique.

        :param group_mitre_ids: The MITRE ATT&CK identifiers of the groups for which to explain techniques.
        :type group_mitre_ids: list[str]
        :param technique_stix_id: The stix ID of a specific technique to explain (optional).
        :type technique_stix_id: str, optional
        :return: An InferredAnswer object containing the explanation of the techniques
            (or the selected technique) used by the group(s).
        :rtype: InferredAnswer
        """
        ids = "|".join(group_mitre_ids)
        if technique_stix_id is not None:
            # the stix-id clause goes at the beginning to optimize the query evaluation
            query = cons.build_match_clause(f"$technique has stix-id '{technique_stix_id}';")
            query += cons.TECHNIQUES_USED_BY.format(group_ids=ids)
        else:
            query = cons.build_match_clause(cons.TECHNIQUES_USED_BY.format(group_ids=ids))
        query += (
            # add the technique name to the result set
            f"\n$technique has name $technique_name;\n"
            "get;\n")
        return InferredAnswer(query, self.db_manager.explain_get_query(query))

    def get_intrusion_sets_per_technique(
        self,
        ignore_revoked=True,
        inference=False,
    ) -> dict:
        """
        Retrieve the number of intrusion sets associated with MITRE ATT&CK techniques.

        :param ignore_revoked: True (default) to ignore revoked techniques, False otherwise.
        :type ignore_revoked: bool
        :param inference: Flag to enable inference in the query. Default is False.
        :type inference: bool

        :returns: A dictionary where the keys are the ATT&CK IDs of the techniques,
            and the value is the number of intrusion sets that use them.
        :rtype: dict
        """
        revoke_flag = f"$t {cons.NOT_REVOKED};\n" if ignore_revoked else ""
        pattern = cons.TECHNIQUES_AS_STIX.replace("{revoked}", revoke_flag)
        query = cons.build_match_clause(pattern)
        # groups using the techniques, aggregated by technique
        query += (
            "$group isa intrusion-set, has name $group_name;\n"
            "$use (used: $t, user: $group) isa uses;\n"
            f"get $t_name,{cons.XREF_ID_VAR},$group_name;\n"
            f"group {cons.XREF_ID_VAR};\n"
            "count;\n"
        )
        logger.debug("Intrusion sets per technique:\n%s" %query)
        data = self.db_manager.aggregate_group_query(query, inference)
        return data

    def get_names_of_mitre_ids(self, attck_ids: list):
        """
        Retrieves the names of techniques based on a list of ATT&CK IDs.

        :param attck_ids: A list of MITRE ATT&CK IDs.
        :type attck_ids: list of str
        :return: A dictionary where the keys are the ATT&CK IDs and the values
            are the names of the techniques.
        :rtype: dict
        """
        query = f"{cons.MATCH}{cons.XREF_IS_MITRE_ATTCK}{cons.XREF_HAS_ID}{cons.XREF_ID_VAR};"
        query += " or".join(
            [f"\n{{{cons.XREF_ID_VAR} == '{tid}';}}" for tid in attck_ids]
        )
        query = query.rstrip(" or") + ";\n"
        query += (
            "$sdo isa stix-domain-object, has name $sdo_name;\n"
            f"$rel (referrer: $sdo, referenced: {cons.XREF_VAR})"
            f"{cons.EXT_REFERENCING_REL}\n"
            f"get {cons.XREF_ID_VAR}, $sdo_name;"
        )
        result = self.db_manager.get_query(query)
        return TypeDBHandler.dict_from_answers(result, "eid", "sdo_name")

    def get_mitigations_for_sdo(self, stix_id) -> dict:
        """
        Retrieve mitigations associated with a given STIX Domain Object (SDO).

        :param stix_id: The STIX identifier of the SDO for which mitigations are to be retrieved.
        :type stix_id: str
        :return: A dictionary with the STIX IDs of the mitigations as keys
            and the mitigation names as values.
        :rtype: dict
        """
        query = cons.MITIGATIONS_OF.format(stix_id)
        mit = self.db_manager.get_query(query)
        return TypeDBHandler.dict_from_answers(mit, "mitigation-id", "mitigation-name")

    def get_mitig_rel_tech(self, group_mitre_id=None, group_name=None):
        """
        Obtains a collection of courses of action that can be associated with a 
         specific group via the "related-to" relation.
        This method always uses inference as the query involves an inferred relation
         that otherwise would never be satisfied.

        If both are given, the group_mitre_id is used. 
        """
        if not group_mitre_id and not group_name:
            raise ValueError("Either group_mitre_id or group_name must be provided.")
        if group_mitre_id:
            name = self.get_names_of_mitre_ids([group_mitre_id]).get(group_mitre_id, "")
        else:
            name = group_name
        mit = self.db_manager.get_query(
            cons.MITIGATIONS_REL_TECHNIQUE.format(name), inference=True
        )
        return TypeDBHandler.dict_from_answers(mit, "sid", "mitigation-name")

    def explain_mitig_rel_tech(
        self, group_stix_id, technique_stix_id
    ) -> InferredAnswer:
        """
        Obtain relevant courses of action for a given intrusion set when addressing the 
        mitigation of a specific SDO. For each course of action, an explanation of
        the rules that concluded on its inclusion is provided.

        :param group_id: The MITRE ATT&CK identifier of the group for which to explain techniques.
        :type group_id: str
        :param technique_stix_id: The stix id of the technique (or other SDO) to be mitigated
        :type technique_name: str
        :return: An InferredAnswer object containing the explanation
        :rtype: InferredAnswer
        """
        query = cons.RELATED_MITIGATIONS_VIA_SDO.format(
            group_stix_id, technique_stix_id
        )
        return InferredAnswer(query, self.db_manager.explain_get_query(query))
    
    def explain_group_rel_mitig(
        self, group_stix_id, mitigation_stix_id
    ) -> InferredAnswer:
        """
        Obtain an explanation on whether a given intrusion set and a course of action
        can be related by the "related-to" inferred relation.

        :param group_stix_id: The stix id of the intrusion set
        :type group_stix_id: str
        :param mitigation_stix_id: The stix id of the course of action to consider
        :type mitigation_stix_id: str
        :return: An InferredAnswer object containing the explanation; the latter is empty
        if there is no inferred relation
        :rtype: InferredAnswer
        """
        query = cons.EXPLAIN_REL_MITIGATION.format(
            group_stix_id, mitigation_stix_id
        )
        return InferredAnswer(query, self.db_manager.explain_get_query(query))

    def get_all_mitigations(self):
        """
        List all the MITRE ATT&CK mitigations
        """
        stix_type = cons.ATTCK_TO_STIX.get("mitigation")
        constraint = f"${stix_type} has name $name;\n"
        query = (
            f"{cons.MATCH}{cons.XREF_IS_MITRE_ATTCK}"
            f"{cons.XREF_HAS_ID}like '{cons.MITIGATION_ID_FORMAT}';\n"
            f"{cons.JOIN_STIX_ATTCK.format(stix_type=stix_type, filters=constraint)}\n"
            f"get {cons.XREF_ID_VAR}, $name;"
            f"sort {cons.XREF_ID_VAR};"
        )
        result = self.db_manager.get_query(query)
        return TypeDBHandler.dict_from_answers(result, "eid", "name")

    def get_all_techniques(self, subtechniques=True):
        """
        List all the MITRE ATT&CK techniques and subtechniques
        """
        stix_type = cons.ATTCK_TO_STIX.get("technique")
        constraint = f"${stix_type} has name $name;\n"
        query = f"{cons.MATCH}{cons.XREF_IS_MITRE_ATTCK}"
        if subtechniques:
            query += (
                f"{{{cons.XREF_HAS_ID}like '{cons.TECHNIQUE_ID_FORMAT}';}} or\n"
                f"{{{cons.XREF_HAS_ID}like '{cons.SUBTECHNIQUE_ID_FORMAT}';}};\n"
            )
        else:
            query += f"{cons.XREF_HAS_ID}like '{cons.TECHNIQUE_ID_FORMAT}';\n"
        query += (
            f"{cons.JOIN_STIX_ATTCK.format(stix_type=stix_type, filters=constraint)}\n"
            f"get {cons.XREF_ID_VAR}, $name;\n"
            f"sort {cons.XREF_ID_VAR};"
        )
        result = self.db_manager.get_query(query)
        return TypeDBHandler.dict_from_answers(result, "eid", "name")

    def filter_groups_keywords(self, keywords=None, all=True) -> list[Group]:
        """
        List all the MITRE ATT&CK groups
        """
        stix_type = cons.ATTCK_TO_STIX.get("group")
        constraints = ""
        if keywords:
            if all:
                constraint_lst = [f"has description contains '{kw}'" for kw in keywords]
                constraints = f"${stix_type} {', '.join(constraint_lst)};\n"
            else:
                constraint_lst = [f"{{${stix_type} has description contains '{kw}';}}" for kw in keywords]
                constraints = " or ".join(constraint_lst) + ";\n"

        query = (
            f"{cons.MATCH}{cons.XREF_IS_MITRE_ATTCK}"
            f"{cons.XREF_HAS_ID}like '{cons.GROUP_ID_FORMAT}';\n"
            f"{cons.JOIN_STIX_ATTCK.format(stix_type=stix_type, filters=constraints)}\n"
            "fetch\n"
            f"{cons.XREF_ID_VAR};\n"
            f"${stix_type}:name,description,alias;\n"
        )

        logger.debug("Get groups by keywords:\n%s" %query)
        result = self.db_manager.fetch_query(query)
        res_as_list = []
        for r in result:
            al = r.get(stix_type).get("alias")
            aliases = ", ".join([a.get("value") for a in al]) if al else ""
            res_as_list.append(
                Group(
                    group_id = r.get('eid').get("value"),
                    name = r.get(stix_type).get("name")[0].get("value"),
                    description = r.get(stix_type).get("description")[0].get("value"),
                    aliases = aliases
                )
            )
        return res_as_list


    @staticmethod
    def _get_stix_type_from_id(attck_id: str) -> str | list | None:
        attck_id_patterns = {
            cons.CAMPAIGN_ID_FORMAT: cons.ATTCK_TO_STIX.get("campaign"),
            cons.GROUP_ID_FORMAT: cons.ATTCK_TO_STIX.get("group"),
            cons.MITIGATION_ID_FORMAT: cons.ATTCK_TO_STIX.get("mitigation"),
            cons.SOFTWARE_ID_FORMAT: cons.ATTCK_TO_STIX.get("software"),
            cons.SUBTECHNIQUE_ID_FORMAT: cons.ATTCK_TO_STIX.get("subtechnique"),
            cons.TECHNIQUE_ID_FORMAT: cons.ATTCK_TO_STIX.get("technique"),
        }

        for id_format, stix_type in attck_id_patterns.items():
            if match(id_format, attck_id):
                return stix_type
        raise ValueError(
            f"Invalid ATT&CK ID format in '{attck_id}'. "
            "Valid formats are: 'C####', 'G####', 'M####', 'S####', 'T####[.###]'"
        )
