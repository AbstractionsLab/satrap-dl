from typing import NamedTuple
from satrap.datamanagement.typedb.typedbhandler import InferenceExplanation


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


class Group(NamedTuple):
    """
    A tuple that represents the result of searching for ATT&CK groups.
    """
    group_id: str
    name: str
    aliases: str
    description: str

    def as_tuple(self):
        return (self.group_id, self.name, self.aliases, self.description)

    def __str__(self):
        return f"GroupID={self.group_id}, Name={self.name}, Aliases=[{self.aliases}], Description: {self.description}"
    

class Mnemonic(NamedTuple):
    stix_id: str
    name: str
    aliases: str

    def __str__(self):
        return f"Stix ID: {self.stix_id}, Name: {self.name}, Aliases: [{self.aliases}]"