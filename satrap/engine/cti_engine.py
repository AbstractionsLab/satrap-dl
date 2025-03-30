"""This module provides the CTIEngine class, responsible for
supporting Cyber Threat Intelligence (CTI) analysis tasks.
"""

from re import match
from typing import NamedTuple

from typedb.driver import Entity

from satrap.datamanagement.typedb.typedb_constants import NON_EMPTY_DB, NON_EMPTY_SERVER
from satrap.datamanagement.typedb.typedbhandler import (
    InferenceExplanation,
    TypeDBHandler,
)
import satrap.engine.query_statements as cons


class InferredAnswer(NamedTuple):
    """
    InferredAnswer is a NamedTuple that represents the explained answer to a query
    that was executed with the explain (and infer) options enabled.

    Attributes:
        query (str): The query string for which the answer is inferred.
        explanations (list[InferenceExplanation]): A list of explanations
        that support the inferred answer.
    """

    query: str
    explanations: list[InferenceExplanation]


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
        :raises SatrapError: if the creation of the TypeDBHandler fails
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
        properties["external-references by"] = self.get_external_references_src(
            properties.get("stix-id", "")
        )
        return properties

    def search_by_stix_id(self, stix_id: str) -> dict:
        """
        Search for an object by its STIX ID.

        This method constructs a query to search for an object in the database
        using the provided STIX ID. If an object is found, it retrieves its
        common properties.

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

    def search_by_attck_id(self, mitre_attck_id) -> list[dict]:
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

        query = cons.SEARCH_BY_ATTACK_ID.format(
            mitre_attck_id=mitre_attck_id, var=res_var
        )
        if stix_type is not None:
            # att&ck ids that can be mapped to different stix types (e.g. software)
            if isinstance(stix_type, list):
                query += " or".join([f"\n{{${res_var} isa {st};}}" for st in stix_type])
                query = query.rstrip(" or") + ";\n"
            else:
                query += f"\n${res_var} isa {stix_type};\n"
        query += f"get ${res_var};"

        stix_objs = self.db_manager.get_query(query)
        if not stix_objs:
            return []

        related = []
        for so in stix_objs:
            properties = self._get_common_properties_of(so.get(res_var))
            related.append(properties)
        return related

    def get_creator(self, stix_id):
        """
        Retrieves the creator of a STIX object using its ID.

        :param stix_id: The ID of the STIX object.
        :type stix_id: str
        :returns: The name of the creator referred in 'created-by-ref'.
        :rtype: str
        """
        query = (
            f"{cons.MATCH}$so has stix-id '{stix_id}';\n"
            f"{cons.CREATOR.format('$so','name')}"
        )
        creator = self.db_manager.get_attribute_value(query, "name")

        return creator[0] if creator else ""

    def get_external_references_src(self, stix_id):
        """
        Retrieves the creator of a STIX object using its ID.

        :param stix_id: The ID of the STIX object.
        :type stix_id: str
        :returns: A dictionary containing the creator's information.
        :rtype: dict
        """
        ext_src_name = "source-name"
        query = (
            f"{cons.MATCH}$so has stix-id '{stix_id}';\n"
            f"{cons.EXT_REF_SRC.format('$so', ext_src_name)}"
        )

        return self.db_manager.get_attribute_value(query, ext_src_name)

    def get_external_references_ids(self, stix_id):
        """
        Retrieves the creator of a STIX object using its ID.

        :param stix_id: The ID of the STIX object.
        :type stix_id: str
        :returns: A dictionary containing the creator's information.
        :rtype: dict
        """
        ext_src_id = "external-id"
        query = (
            f"{cons.MATCH}$so has stix-id '{stix_id}';\n"
            f"{cons.EXT_REF_SRC.format('$so', ext_src_id)}"
        )

        return self.db_manager.get_attribute_value(query, ext_src_id)

    def get_stats(self) -> dict:
        """
        Retrieve statistics of non-revoked STIX domain objects (SDOs) in the CTI SKB.

        :returns: A dictionary containing the number of SDOs per type.
        :rtype: dict
        """
        query = cons.SDOS
        return self.db_manager.aggregate_group_query(query)

    def get_techniques_used_by(self, group_id: str, inference=False) -> dict:
        """
        Retrieve techniques found to be used by a specific group.

        :param group_id: The MITRE ATT&CK identifier of the group.
        :type group_id: str
        :param inference: True if inference should be used in the query; defaults to False.
        :type inference: bool, optional
        :return: A dictionary with pairs [STIX id:name] of the techniques
        :rtype: dict
        """
        query = (
            f"{cons.TECHNIQUES_USED_BY.format(group_id=group_id, name='$t_name')}"
            "get $id, $t_name;\n"
            "sort $t_name;"
        )
        result = self.db_manager.get_query(query, inference)
        return TypeDBHandler.dict_from_answers(result, "id", "t_name")

    def explain_techniques_used_by(
        self, group_id: str, technique_name: str = None
    ) -> InferredAnswer:
        """
        Provides explanations tracing the inference rules that are applied to derive
        the set of techniques used by a specific group. The explanations can be optionally
        filtered by the name of a specific technique.

        :param group_id: The MITRE ATT&CK identifier of the group for which to explain techniques.
        :type group_id: str
        :param technique_name: The name of a specific technique to explain (optional).
        :type technique_name: str, optional
        :return: An InferredAnswer object containing the explanation of the techniques
            (or the selected technique) used by the group.
        :rtype: InferredAnswer
        """
        tech_name = (
            f"'{technique_name}'" if technique_name is not None else "$technique_name"
        )
        query = (
            f"{cons.TECHNIQUES_USED_BY.format(group_id=group_id, name=tech_name)}"
            "get;"
        )
        return InferredAnswer(query, self.db_manager.explain_get_query(query))

    def get_intrusion_sets_per_technique(
        self,
        ignore_revoked=True,
        inference=False,
    ) -> dict:
        """
        Retrieve intrusion sets associated with MITRE ATT&CK techniques.

        :param ignore_revoked: True (default) to ignore revoked techniques, False otherwise.
        :type ignore_revoked: bool
        :param inference: Flag to enable inference in the query. Default is False.
        :type inference: bool

        :returns: A dictionary where the keys are the ATT&CK IDs of the techniques,
            and the value is the number of intrusion sets that use them.
        :rtype: dict
        """
        revoke_flag = f"$ap {cons.NOT_REVOKED}" if ignore_revoked else ""
        # Get all the ids of the MITRE ATT&CK techniques and
        # the SDOs associated with them. There is a one-to-one
        # mapping between a technique and an attack-pattern.
        # Then, get all the instrusion sets using such techniques.
        query = (
            f"{cons.MATCH}{cons.EXT_MITRE_ATTCK}"
            f"{cons.EXT_REF_ID}like '{cons.TECHNIQUE_ID_FORMAT}';\n"
            f"{cons.EXT_REF_ID}{cons.EXT_ID_VAR};\n"
            "$ap isa attack-pattern, has name $ap_name;\n"
            f"{revoke_flag}"
            f"$rel (referrer: $ap, referenced: {cons.EXT_REF_VAR})"
            f"{cons.EXT_REFERENCING_REL}\n"
            "$group isa intrusion-set, has name $group_name;\n"
            "$use (used: $ap, user: $group) isa uses;\n"
            f"get $ap_name,{cons.EXT_ID_VAR},$group_name;\n"
            f"group {cons.EXT_ID_VAR};\n"
            "count;\n"
        )
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
        query = f"{cons.MATCH}{cons.EXT_MITRE_ATTCK}{cons.EXT_REF_ID}{cons.EXT_ID_VAR};"
        query += " or".join(
            [f"\n{{{cons.EXT_ID_VAR} == '{tid}';}}" for tid in attck_ids]
        )
        query = query.rstrip(" or") + ";\n"
        query += (
            "$sdo isa stix-domain-object, has name $sdo_name;\n"
            f"$rel (referrer: $sdo, referenced: {cons.EXT_REF_VAR})"
            f"{cons.EXT_REFERENCING_REL}\n"
            f"get {cons.EXT_ID_VAR}, $sdo_name;"
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
        Obtain relevant courses of action for a given intursion set when addressing the 
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
        query = (
            f"{cons.MATCH}{cons.EXT_MITRE_ATTCK}"
            f"{cons.EXT_REF_ID}like '{cons.MITIGATION_ID_FORMAT}';\n"
            f"{cons.EXT_REF_ID}{cons.EXT_ID_VAR};\n"
            "$measure isa course-of-action, has revoked false, "
            "has name $name;\n"
            f"$rel (referrer: $measure, referenced: {cons.EXT_REF_VAR})"
            f"{cons.EXT_REFERENCING_REL}\n"
            f"get {cons.EXT_ID_VAR}, $name;"
            f"sort {cons.EXT_ID_VAR};"
        )
        result = self.db_manager.get_query(query)
        return TypeDBHandler.dict_from_answers(result, "eid", "name")

    def get_all_techniques(self, subtechniques=True):
        """
        List all the MITRE ATT&CK techniques and subtechniques
        """
        query = f"{cons.MATCH}{cons.EXT_MITRE_ATTCK}"
        if subtechniques:
            query += (
                f"{{{cons.EXT_REF_ID}like '{cons.TECHNIQUE_ID_FORMAT}';}} or\n"
                f"{{{cons.EXT_REF_ID}like '{cons.SUBTECHNIQUE_ID_FORMAT}';}};\n"
            )
        else:
            query += f"{cons.EXT_REF_ID}like '{cons.TECHNIQUE_ID_FORMAT}';\n"
        query += (
            f"{cons.EXT_REF_ID}{cons.EXT_ID_VAR};\n"
            "$technique isa attack-pattern, has revoked false, "
            "has name $name;\n"
            f"$rel (referrer: $technique, referenced: {cons.EXT_REF_VAR})"
            f"{cons.EXT_REFERENCING_REL}\n"
            f"get {cons.EXT_ID_VAR}, $name;\n"
            f"sort {cons.EXT_ID_VAR};"
        )
        result = self.db_manager.get_query(query)

        return TypeDBHandler.dict_from_answers(result, "eid", "name")

    def get_inference_rule_names(self) -> set:
        """
        Retrieve the names of inference rules from the database.
        """
        return self.db_manager.get_inference_rules()

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
