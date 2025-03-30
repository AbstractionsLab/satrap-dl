
"""
This module provides a toolbox for performing various Cyber Threat Intelligence (CTI) analysis tasks.
"""
from operator import itemgetter
from tabulate import tabulate

from satrap.engine.cti_engine import CTIEngine
from satrap.commons.log_utils import logger


class CTIanalysisToolbox:
    """
    A class that provides various automated CTI analysis tasks leveraging the 
    reasoning capabilities of the `CTIEngine`.
    """

    def __init__(self, server, database):
        """
        Initialize the CTIanalysisToolbox with the given server and database.

        :param server: The address of the TypeDB server.
        :type server: str
        :param database: The name of the TypeDB database.
        :type database: str
        """
        self.cti_engine = CTIEngine(server, database)


    def explain_if_related_mitigation(
        self, group_mitre_id: str, mitigation_stix_id: str
    ):
        """
        Obtain an explanation on whether a given mitigation is potentially relevant (is related)
        for addressing the techniques used by a group.

        :param group_mitre_id: The MITRE ATT&CK ID of the group.
        :type group_mitre_id: str
        :param mitigation_stix_id: The STIX ID of the mitigation.
        :type mitigation_stix_id: str

        :raises ValueError: If the given MITRE ATT&CK ID is invalid or no group with
            such an ID is found.

        :return: An InferredAnswer containing explanations for the relation between the mitigation
         and the group. If no relation is inferred, the explanations list is empty.
        :rtype: InferredAnswer
        """
        with self.cti_engine as eng:
            stix_objects = eng.search_by_attck_id(group_mitre_id)
            if stix_objects:
                g_stix_id = stix_objects[0].get("stix-id")
            else:
                raise ValueError(
                    f"No group with MITRE ATT&CK id '{group_mitre_id}' was found."
                )
            return eng.explain_group_rel_mitig(g_stix_id, mitigation_stix_id)
        
    def explain_related_techniques(self, group_name: str, technique_id: str):
        """
        Obtain relevant courses of action for a given intrusion set, when considering the
        mitigation of a specific SDO (usually technique).
        """
        with self.cti_engine as eng:
            stix_objects = eng.search_by_attck_id(technique_id)
            if stix_objects:
                t_stix_id = stix_objects[0].get("stix-id")
            else:
                raise ValueError(
                    f"No concept with MITRE ATT&CK id '{technique_id}' was found."
                )
            return eng.explain_mitig_rel_tech(group_name, t_stix_id)

    def explain_techniques_used_by_group(
        self, group_id: str, technique_name: str = None
    ):
        """
        Provides explanations on the inference rules that are applied to derive
        the set of techniques used by a specific group. The result can be optionally
        filtered by the name of a specific technique.

        :param group_id: The MITRE ATT&CK identifier of the group for which to explain techniques.
        :type group_id: str
        :param technique_name: The name of a specific technique to explain (optional).
        :type technique_name: str, optional
        :return: An InferredAnswer object containing the explanation of the techniques
            (or the selected technique) used by the group.
        :rtype: InferredAnswer
        """
        with self.cti_engine as engine:
            return engine.explain_techniques_used_by(group_id, technique_name)

    def get_attck_concept_info(self, mitre_id) -> list[dict]:
        """
        Get information on the STIX objects associated to a MITRE ATT&CK ID.
        Only STIX objects of the type corresponding to the format of the
        given ID (as per the ATT&CK-stix2.1 specification) are retrieved.

        :param mitre_id: The MITRE ATT&CK ID.
        :type mitre_id: str
        :return: Information about the ATT&CK concept.
        :rtype: dict
        :raises ValueError: If no information is found for the given MITRE ID.
        """
        with self.cti_engine as engine:
            related_data = engine.search_by_attck_id(mitre_id)
        if not related_data:
            raise ValueError(f'No information found for the MITRE ATT&CK ID "{mitre_id}"')
        if len(related_data) > 1:
            warn_message = (
                f"'Multiple objects found for the MITRE ATT&CK ID '{mitre_id}'."
                " Some might be 'revoked'."
            )
            logger.warning(warn_message)
            print(warn_message)
        return related_data

    def get_sdo_stats(self) -> str:
        """
        Get the number of STIX Domain Objects (SDOs) in the database per type.

        :return: Information about SDOs in the knowledge base.
        :rtype: str
        """
        with self.cti_engine as engine:
            info = engine.get_stats()
        if not info:
            return "There are no STIX Domain Objects in the knowledge base."
        return CTIanalysisToolbox.tabulate_stix_obj(
            info, ["STIX Domain Objects", "Total in the CTI SKB"]
        )

    def mitigations_for_technique(self, stix_id: str) -> dict:
        """
        Retrieve mitigations associated to a specific technique.

        :param stix_id: The STIX ID of the technique.
        :type stix_id: str
        :return: Pairs (STIX id:name) representing the mitigations of the technique
        :rtype: dict
        """
        with self.cti_engine as engine:
            return engine.get_mitigations_for_sdo(stix_id)

    def mitre_attack_mitigations(self) -> str:
        """
        Get all mitigations from the MITRE ATT&CK framework (M####).

        :return: All the mitigations defined in MITRE ATT&CK.
        :rtype: str
        """
        with self.cti_engine as engine:
            info = engine.get_all_mitigations()
        if not info:
            return "No MITRE ATT&CK mitigations found. Consider running the ETL command on the ATT&CK dataset."
        return CTIanalysisToolbox.tabulate_stix_obj(
            info, ["MITRE ATT&CK\nMitigation ID", "Name"]
        )

    def mitre_attack_techniques(self, subtechniques=True) -> str:
        """
        Get all techniques from the MITRE ATT&CK framework (T####) and
        optionally include subtechniques (T####.###).

        :param subtechniques: Whether to include subtechniques. Default is True.
        :type subtechniques: bool, optional
        :return: All the techniques defined in MITRE ATT&CK.
        :rtype: str
        """
        with self.cti_engine as engine:
            info = engine.get_all_techniques(subtechniques)
        if not info:
            return "No MITRE ATT&CK techniques found. Consider running the ETL command on the ATT&CK dataset."
        return CTIanalysisToolbox.tabulate_stix_obj(
            info, ["MITRE ATT&CK\ntechnique ID", "Name"]
        )

    def related_mitigations(self, group_id=None, group_name=None) -> dict:
        """
        Obtain the set of courses of action found to mitigate any of the techniques used by a specific group.

        :param group_id: The MITRE ATT&CK id of the group
        :type group_id: str, optional
        :param group_name: The name of the group
        :type group_name: str, optional
        
        :raises ValueError: If none of the optional values is provided
        """
        try:
            with self.cti_engine as eng:
                return eng.get_mitig_rel_tech(
                    group_mitre_id=group_id, group_name=group_name)
        except ValueError as err:
            print(err)

    def search_stix_object(self, stix_id) -> dict:
        """
        Search for a STIX object by its ID.

        :param stix_id: The STIX ID of the object.
        :type stix_id: str
        :return: The STIX object.
        :rtype: dict
        :raises ValueError: If no information is found for the given STIX ID.
        """
        with self.cti_engine as engine:
            entity = engine.search_by_stix_id(stix_id)
        if not entity:
            raise ValueError(f"No STIX object found for stix-id '{stix_id}'")
        return entity

    def techniques_usage(
        self,
        sort_order="desc",
        used_by_min=None,
        used_by_max=None,
        infer=False,
        norevoked=True,
        limit=None,
    ) -> list:
        """
        Get the number of groups that use each ATT&CK technique.

        :param sort_order: Sort order of the results: "asc" for ascending
                or "desc" for descending (default).
        :type sort_order: str
        :param used_by_min: Minimum usage count to filter the results. Default is None.
        :type used_by_min: int, optional
        :param used_by_max: Maximum usage count to filter the results. Default is None.
        :type used_by_max: int, optional
        :param infer: Whether to activate the inference engine. Default is False.
        :type infer: bool, optional
        :param norevoked: True (default) to consider only techniques that have not been revoked.
                False otherwise.
        :type norevoked: bool, optional
        :param limit: Maximum number of results to return. Default is None.
        :type limit: int, optional

        :return: A list of tuples containing the technique ID, name, and usage count.
        :rtype: list
        """
        with self.cti_engine as engine:
            sets_count = engine.get_intrusion_sets_per_technique(
                inference=infer,
                ignore_revoked=norevoked,
            )
            if not sets_count:
                return []
            data = list(sets_count.items())

            if used_by_min:
                data = list(filter(lambda x: x[1] >= used_by_min, data))
            if used_by_max:
                data = list(filter(lambda x: x[1] <= used_by_max, data))
            data = sorted(data, key=itemgetter(1), reverse=(sort_order == "desc"))
            if limit is not None and limit >= 0:
                data = data[0:limit]

            ttp_names = engine.get_names_of_mitre_ids(row[0] for row in data)
            data = list(map(lambda x: (x[0], ttp_names.get(x[0]), x[1]), data))
        return data

    def techniques_used_by_group(self, group_id, infer=False) -> dict:
        """
        Get the techniques used by a specific group.

        :param group_id: The ID of the group.
        :type group_id: str
        :param infer: Whether to activate the inference engine. Default is False.
        :type infer: bool, optional
        :return: Techniques used by the group.
        :rtype: dict
        """
        with self.cti_engine as engine:
            return engine.get_techniques_used_by(group_id, inference=infer)

    @staticmethod
    def tabulate_stix_obj(stix_object: dict, headers: list[str] = None) -> str:
        """
        Convert a dictionary to a table using the tabulate library.

        :param stix_object: The dictionary to be converted.
        :type stix_object: dict
        :param headers: The headers of the table. Default is ["Property", "Value"].
        :type headers: list, optional
        :return: A tabular representation of the dictionary.
        :rtype: str
        """
        if headers is None or len(headers) != 2:
            headers = ["Property", "Value"]
        return tabulate(
            stix_object.items(), headers, tablefmt="grid", maxcolwidths=[20, 55]
        )

    @staticmethod
    def format_dict(dictionary: dict, indent: int = 0) -> str:
        """
        Formats a dictionary into a string with indentation for nested dictionaries.

        :param dictionary: The dictionary to format.
        :type dictionary: dict
        :param indent: The number of spaces to use for indentation. Defaults to 0.
        :type indent: int, optional
        :return: The formatted string representation of the dictionary.
        :rtype: str
        """
        output = []
        for key, value in dictionary.items():
            output.append(f'{" " * indent}{key}: ')
            if isinstance(value, dict):
                output.append("\n")
                output.append(CTIanalysisToolbox.format_dict(value, indent + 4))
            else:
                output.append(str(value) + "\n")
        return "".join(output)
