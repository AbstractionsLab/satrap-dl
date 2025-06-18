from dataclasses import dataclass
from typing import Optional, Dict

from typedb.driver import (
    ConceptMap,
    Entity,
    EntityType,
    SessionType,
    TransactionType,
    TypeDB,
    TypeDBDriverException,
    TypeDBOptions,
    TypeDBTransaction,
)

from satrap.commons.exceptions import SatrapError
from satrap.datamanagement.typedb.typedb_constants import NON_EMPTY_SERVER, NON_EMPTY_DB
from satrap.commons.log_utils import logger


@dataclass
class InferenceExplanation:
    """
    A class to represent an inference explanation.

    Attributes
    ----------
    statement : str, optional
        Statement in the query subject to explanation, as matching data is derived from 
        the application of an inference rule (default is None)
    rule : str, optional
        The inference rule that is applied (default is None)
    condition : str, optional
        The assignment of variables that meets the rule's condition (default is None)
    conclusion : str, optional
        The conclusion resulting from the application of the rule (default is None)
    var_mapping : dict, optional
        The mapping of variables in the query statement to the rule variables 
        (query var: rule var) (default is None)
    """

    statement: Optional[str] = None
    rule: Optional[str] = None
    condition: Optional[str] = None
    conclusion: Optional[str] = None
    var_mapping: Optional[Dict[str, str]] = None

    STATEMENT_DESC = "Data inferred for query statement Q"
    RULE_DESC = "Applied rule (R)"
    CONDITION_DESC = "Condition met"
    CONCLUSION_DESC = "Inferred conclusion"
    MAPPING_DESC = "Mapping of query variables to rule variables (Q var: R var)"

    def as_json(self):
        return {
            InferenceExplanation.STATEMENT_DESC: self.statement,
            InferenceExplanation.RULE_DESC: self.rule,
            InferenceExplanation.CONDITION_DESC: self.condition,
            InferenceExplanation.CONCLUSION_DESC: self.conclusion,
            InferenceExplanation.MAPPING_DESC: self.var_mapping,
        }

    def __str__(self):
        return (
            f"{InferenceExplanation.STATEMENT_DESC} = {self.statement},\n"
            f"{InferenceExplanation.RULE_DESC} = {self.rule},\n"
            f"{InferenceExplanation.CONDITION_DESC} = {self.condition},\n"
            f"{InferenceExplanation.CONCLUSION_DESC} = {self.conclusion},\n"
            f"{InferenceExplanation.MAPPING_DESC} = {self.var_mapping}\n"
        )


class TypeDBHandler:
    """
    TypeDBHandler is a class that provides methods to interact with a TypeDB database.
    """

    def __init__(self, server_address, database_name):
        if not server_address:
            raise ValueError(NON_EMPTY_SERVER)
        if not database_name:
            raise ValueError(NON_EMPTY_DB)

        self.server_address = server_address
        self.database_name = database_name
        try:
            self.driver = TypeDB.core_driver(self.server_address)
        except TypeDBDriverException as error:
            raise SatrapError(
                f"Error initializing the TypeDB manager for {self.database_name} at {self.server_address}: {error}"
            ) from error
        self.session = self.driver.session(database_name, SessionType.DATA)

    def get_attributes_of(self, entity: Entity):
        """
        Retrieves the attributes of a given entity and returns them as a dictionary.

        :param entity: The entity whose attributes are to be retrieved.
        :type entity: Entity

        :returns: A dictionary where the keys are attribute labels and the values are
            the values of the attributes as strings
        :rtype: dict
        """
        with self.session.transaction(TransactionType.READ) as trx:
            attributes = entity.get_has(trx)
            if not attributes:
                return {}
            att_dict = {"type": entity.get_type().get_label().scoped_name()}
            for attr in attributes:
                att_label = attr.get_type().get_label().scoped_name()
                if attr.is_datetime():
                    att_dict[att_label] = attr.as_datetime().strftime("%Y-%m-%d %H:%M")
                elif attr.is_boolean():
                    # the conversion to lower case is to prevent functions,
                    # e.g. "tabulate", from taking this value as a boolean
                    # even after the cast
                    att_dict[att_label] = str(attr.get_value()).lower()
                else:
                    if att_label in att_dict:
                        att_dict[att_label] += f", {str(attr.get_value())}"
                    else:
                        att_dict[att_label] = str(attr.get_value())
                    # att_dict[att_label] = str(attr.get_value())
            return att_dict

    def get_attribute_value(self, query: str, attribute: str) -> list:
        """
        Retrieves the values of a specified attribute from the results of a given query.

        :param query: The query string to be executed.
        :type query: str
        :param attribute: The attribute whose values are to be retrieved.
        :type attribute: str
        :return: A list of values for the specified attribute.
        :rtype: list
        """
        with self.session.transaction(TransactionType.READ) as tx:
            res = tx.query.fetch(query)
            res_values = []

            for e in res:
                for k in e.keys():
                    # the list of values found for this attribute
                    att = e.get(k).get(attribute)
                    if att:
                        res_values.append(att[0].get("value"))
        return res_values

    def aggregate_int_query(self, query: str):
        """
        Run an aggregate query on a TypeDB database whose return
        is expected to be an integer.

        :param server_addr: The address of the TypeDB server.
        :param db_name: The name of the database.
        :param query: The aggregate query to be executed.
        :return: The result of the aggregate query as an integer.
        :rtype: int
        """
        with self.session.transaction(TransactionType.READ) as tx:
            result = tx.query.get_aggregate(query).resolve().as_long()
        return result

    def aggregate_group_query(self, query: str, inference=False) -> dict:
        """
        Executes a group aggregate query on the TypeDB database and returns the results.

        :param query: The TypeQL query string to be executed.
        :type query: str
        :param inference: True to enable inference during the query execution, defaults to False.
        :type inference: bool, optional
        :return: A dictionary where the keys are the grouped concepts' labels and the values
            are the corresponding counts.
        :rtype: dict
        """
        with self.session.transaction(
            TransactionType.READ, TypeDBOptions(infer=inference)
        ) as tx:
            result = tx.query.get_group_aggregate(query)
            grouped_results = {}
            for g in result:
                count_int = g.value().as_long()
                attribute_str = g.owner()
                if isinstance(attribute_str, EntityType):
                    grouped_results[attribute_str.get_label().scoped_name()] = count_int
                else:
                    grouped_results[attribute_str.get_value()] = count_int
        return grouped_results

    def fetch_query(self, query: str, inference=False) -> list:
        """Run a fetch query on a TypeDB database.

        :param server_addr: The address of the TypeDB server
        :type server_addr: str
        :param db_name: The name of the database
        :type db_name: str
        :param query: The fetch query
        :type query: str
        :return: The result of the fetch query as a list
        :rtype: list
        """
        with self.session.transaction(
            TransactionType.READ, TypeDBOptions(infer=inference)
        ) as tx:
            res = list(tx.query.fetch(query))
        return res

    def get_query(self, query: str, inference=False) -> list:
        """Run a get query on a TypeDB database.

        :param server_addr: The address of the TypeDB server
        :type server_addr: str
        :param db_name: The name of the database
        :type db_name: str
        :param query: The fetch query
        :type query: str
        :return: The result of the fetch query as a list
        :rtype: list
        """
        with self.session.transaction(
            TransactionType.READ, TypeDBOptions(infer=inference)
        ) as ta:
            res = list(ta.query.get(query))
        return res

    def explain_get_query(self, query: str) -> list[InferenceExplanation]:
        """
        Provides a collection of explanations of inferred relations for a given TypeDB query.

        This method executes a TypeDB query with inference and explanation options enabled,
        and processes the results to provide detailed explanations of the inferred data.

        :param query: The TypeDB query string to be explained.
        :type query: str
        :return: A list of InferenceExplanation objects explaining the application
            of inference rules in the derivation of the query answer.
        :rtype: list[InferenceExplanation]
        """
        with self.session.transaction(
            TransactionType.READ, TypeDBOptions(infer=True, explain=True)
        ) as tx:
            logger.info("Explaining inference for query:\n %s", query)
            response = tx.query.get(query)

            explained_data = []
            for concept_map in response:
                logger.debug(concept_map.explainables())
                explainable_relations = concept_map.explainables().relations().items()

                for var, explainable in explainable_relations:
                    query_statement = explainable.conjunction()
                    explanations = tx.query.explain(explainable)

                    for explanation in explanations:
                        inference_exp = InferenceExplanation(
                            statement = query_statement,
                            rule = explanation.rule().label
                        )
                        condition = explanation.condition()
                        conclusion = explanation.conclusion()
                        logger.debug("Condition: %s", condition)
                        inference_exp.condition = self._concepts_to_stix(tx, condition)
                        logger.debug("Conclusion: %s", conclusion)
                        inference_exp.conclusion = self._concepts_to_stix(tx, conclusion)

                        variables = explanation.query_variables()
                        var_mappings = {}
                        for var in variables:
                            mapping = explanation.query_variable_mapping(var)
                            var_mappings[var] = mapping
                        inference_exp.var_mapping = var_mappings
                        explained_data.append(inference_exp)
            return explained_data
        
    def get_inference_rules(self):
        """
        Retrieves all the inference rules defined on the database and 
        returns their labels as a set.
        """
        with self.session.transaction(TransactionType.READ) as ta:
            rules = ta.logic.get_rules()
            rule_pack = {r.label for r in rules}
            return rule_pack

    def close(self):
        if self.session:
            self.session.close()
        if self.driver:
            self.driver.close()

    @staticmethod
    def _concepts_to_stix(
        transaction: TypeDBTransaction, concept_map: ConceptMap
    ) -> dict:
        """Create a dictionary where the concepts in a given ConceptMap
        are associated with their identifiers in the DB (stix-id or name)
        instead of with TypeDB iids
        """
        concepts_dict = {}
        stix_id_type = transaction.concepts.get_attribute_type("stix-id").resolve()
        name_type = transaction.concepts.get_attribute_type("name").resolve()

        concept_map_vars = concept_map.variables()
        for var in concept_map_vars:
            concept = concept_map.get(var)
            if concept.is_thing():
                if concept.is_attribute():
                    concepts_dict[var] = concept.get_value()
                else:
                    logger.debug("Concept: %s", concept)
                    # get the 'stix-id' and 'name' attributes of the concept
                    attributes = set(concept.get_has(transaction, attribute_types=[stix_id_type,name_type]))
                    logger.debug("Concept's attributes: %s", str(attributes))
                    stix_id = None
                    name = None
                    for attr in attributes:
                        if attr.get_type() == stix_id_type:
                            stix_id = attr.get_value()
                        if attr.get_type() == name_type:
                            name = attr.get_value()
                    concepts_dict[var] = f"({name}, {stix_id})" if name else stix_id

                    # if the concept has neither stix-id nor name,
                    # use the string representation of the concept
                    if concepts_dict.get(var) is None:
                        concepts_dict[var] = (
                            f"{concept} {'(Inferred)' if concept.is_inferred() else ''}"
                        )
            else:
                concepts_dict[var] = concept

        return concepts_dict

    @staticmethod
    def dict_from_answers(typedb_result: list[ConceptMap], key_var: str, value_var: str):
        """
        Convert a list of TypeDB ConceptMap results into a dictionary.

        :param typedb_result: A list of ConceptMap objects from a TypeDB query.
        :type typedb_result: list[ConceptMap]
        :param key_var: The variable name in typedb_result to be used as the key
            in the output dictionary.
        :type key_var: str
        :param value_var: The variable name in typedb_result to be used as the value
            in the output dictionary.
        :type value_var: str
        :return: A dictionary with keys and values extracted from the ConceptMap objects.
        :rtype: dict
        """
        if not typedb_result:
            return {}

        res_as_dict = {
            q.get(key_var).get_value(): q.get(value_var).get_value()
            for q in typedb_result
        }
        return res_as_dict
