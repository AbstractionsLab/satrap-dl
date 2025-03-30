import json
import unittest

from satrap.etl.transform.stix_to_typedb_mapper import STIXtoTypeDBMapper
from satrap.etl.transform.transformer import STIXtoTypeQLTransformer
from satrap.datamanagement.typedb.typeql_builder import TypeQLBuilder
from satrap.datamanagement.typedb.dataobjects import VariableDealer
from satrap.datamanagement.typedb import typedb_constants
from satrap.datamanagement.typedb.typedb_constants import to_typedb_string
import satrap.etl.transform.stix_typeql_constants as constants


def build_attribute(name: str, value: str) -> str:
    attribute = typedb_constants.ATTRIBUTE_SEPARATOR
    attribute += typedb_constants.ATTRIBUTE_KEYWORD
    attribute += typedb_constants.ATTRIBUTE_KEYWORD_KEY_SEPARATOR
    attribute += name
    attribute += typedb_constants.ATTRIBUTE_KEY_VALUE_SEPARATOR
    attribute += value
    return attribute


def build_string_attribute(name: str, value: str) -> str:
    return build_attribute(name, to_typedb_string(value))


def build_type(name) -> str:
    typedb_type = typedb_constants.BEFORE_TYPEKEYWORD_SEPARATOR
    typedb_type += typedb_constants.TYPE_KEYWORD
    typedb_type += typedb_constants.TYPEKEYWORD_TYPE_SEPARATOR
    typedb_type += name
    return typedb_type


def permutations(attr_list: list) -> list[list]:
    attr_list = attr_list[0:len(attr_list)]
    if len(attr_list) <= 1:
        return [attr_list]

    res = []
    head = attr_list.pop(0)
    perms = permutations(attr_list)
    for perm in perms:
        for i in range(len(perm)+1):
            _perm = perm[0:len(perm)]
            _perm.insert(i, head)
            res.append(_perm)
    return res


def format_permutations(
    text: str,
    args: list[str],
    warning_barrier=8
) -> list[str]:
    """Inserts the args in every possible order into the format string.

    :param text: The format string
    :type text: str
    :param args: The arguments to insert into the format string.
        The length must equal the number of arguments of the format string.
    :type args: list[str]
    :param warning_barrier: Specifies how many arguments are allowed to 
        prevent too long running times
    :type warning_barrier: int, optional

    :return: All strings that can be created by inserting the arguments
        into the format string in different orders
    :rtype: list[str]
    """
    if len(args) >= warning_barrier:
        raise ValueError(
            "Do you really want to do this? Remember, the runtime "
            "is bad and the output length even worse. "
            "If you still want to proceed, higher the warning barrier."
        )
    return [text.format(*attrs) for attrs in permutations(args)]


def concat_permutations(*args) -> list[str]:
    """Concatenates every selection of items from the list.

    :param args: The lists whose items should be concatenated
    :type args: list[str]

    :return: All combinations that can be created by choosing one
        element from each list and concatenating them in order
    :rtype: list[str]
    """
    res = [""]
    for arg in args:
        res_temp = []
        for re in res:
            for item in arg:
                temp = re + item
                res_temp.append(temp)
        res = res_temp
    return res


class TestTypes(unittest.TestCase):

    def setUp(self) -> None:
        self.transformer = STIXtoTypeQLTransformer()
        STIXtoTypeDBMapper.get_data()
        VariableDealer.reset()

    def test_permutations(self):
        expect = [[0, 1, 2], [0, 2, 1], [1, 2, 0],
                  [1, 0, 2], [2, 0, 1], [2, 1, 0]]
        expect.sort()
        res = permutations([0, 1, 2])
        res.sort()
        self.assertEqual(expect, res)

    def test_concat_permutations(self):
        list1 = ["1", "2"]
        list2 = ["a", "b"]
        expect = ["1a", "1b", "2a", "2b"]
        expect.sort()
        res = concat_permutations(list1, list2)
        res.sort()
        self.assertEqual(
            res,
            expect
        )

    def test_simple(self):
        test = {
            "type": "attack-pattern",
            "id": "attack-pattern--0001",
            "_custom": "test",
            "name": "test_name",
            "description": "test_description",
            "extensions": {
                "custom_ext": {
                    "key1": "value1"
                }
            }
        }
        first, second, third = self.transformer.transform(test)

        expect = typedb_constants.INSERT_KEYWORD
        expect += typedb_constants.KEYWORD_SEPARATOR
        expect += typedb_constants.VARIABLE_PREFIX + "v0"
        expect += build_type("attack-pattern")

        attributes = []
        attributes.append(build_string_attribute(
            constants.TYPEDB_ID_ATTRIBUTE,
            "attack-pattern--0001"
        ))
        attributes.append(build_string_attribute(
            "name",
            "test_name"
        ))
        attributes.append(build_string_attribute(
            "description",
            "test_description"
        ))
        expect += "{}{}{}"
        expect += typedb_constants.OBJECT_ENDING
        expect += typedb_constants.OBJECT_SEPARATOR

        expects = format_permutations(expect, attributes)

        self.assertIn(
            TypeQLBuilder.build_insert_query(first),
            expects
        )
        self.assertIsNone(second)
        self.assertIsNone(third)

    def test_SDO_with_composite(self):
        test = {
            "type": "attack-pattern",
            "id": "attack-pattern--0001",
            "external_references": [
                {
                    "source_name": "mitre-attack"
                }
            ]
        }
        first, second, third = self.transformer.transform(test)

        expect_first = typedb_constants.INSERT_KEYWORD
        expect_first += typedb_constants.KEYWORD_SEPARATOR

        # main entity
        expect_first += typedb_constants.VARIABLE_PREFIX + "v0"
        expect_first += build_type("attack-pattern")
        expect_first += build_string_attribute(
            constants.TYPEDB_ID_ATTRIBUTE,
            "attack-pattern--0001"
        )
        expect_first += typedb_constants.OBJECT_ENDING
        expect_first += typedb_constants.OBJECT_SEPARATOR

        # composite entity
        expect_first += typedb_constants.VARIABLE_PREFIX + "v1"
        expect_first += build_type("external-reference")
        expect_first += build_string_attribute(
            "source-name",
            "mitre-attack"
        )
        expect_first += typedb_constants.OBJECT_ENDING
        expect_first += typedb_constants.OBJECT_SEPARATOR

        # composite relation
        roles = []
        role_object = "referrer"
        role_object += typedb_constants.ROLE_VARIABLE_SEPARATOR
        role_object += typedb_constants.VARIABLE_PREFIX + "v0"
        roles.append(role_object)

        role_value = "referenced"
        role_value += typedb_constants.ROLE_VARIABLE_SEPARATOR
        role_value += typedb_constants.VARIABLE_PREFIX + "v1"
        roles.append(role_value)

        expect_first += typedb_constants.VARIABLE_PREFIX + "v2"
        expect_first += typedb_constants.VARIABLE_RELATION_SEPARATOR
        expect_first += typedb_constants.ROLES_BEGINNING
        expect_first += "{}"
        expect_first += typedb_constants.ROLE_SEPARATOR
        expect_first += "{}"
        expect_first += typedb_constants.ROLES_ENDING
        expect_first += build_type("external-referencing")
        expect_first += typedb_constants.OBJECT_ENDING
        expect_first += typedb_constants.OBJECT_SEPARATOR

        expect = format_permutations(expect_first, roles)
        insert_q = TypeQLBuilder.build_insert_query(first)

        self.assertIn(
            insert_q,
            expect
        )
        self.assertIsNone(second)
        self.assertIsNone(third)

    def test_mitre_single_object(self):

        # Please note, the object has less attributes than the original
        # but the permutations function cannot handle this size
        # also note that for testing, only one attribute that takes additional
        # variables should be specified as the order is unknown and therefore
        # the variables cannot be anticipated correctly

        test = {
            "modified": "2024-04-11T02:36:24.044Z",
            "name": "Elderwood",
            "aliases": [
                "Elderwood",
                "Elderwood Gang"
            ],
            "x_mitre_deprecated": False,
            "x_mitre_version": "1.3",
            "x_mitre_contributors": [
                "Valerii Marchuk, Cybersecurity Help s.r.o."
            ],
            "type": "intrusion-set",
            "id": "intrusion-set--03506554-5f37-4f8f-9ce4-0e9f01a1b484",
            # "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "G0066"
                },
                {
                    "source_name": "Beijing Group",
                    "description": "(Citation: CSM Elderwood Sept 2012)"
                }
            ],
            "object_marking_refs": [
                "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
            ],
            "x_mitre_domains": [
                "enterprise-attack"
            ]
        }
        self.maxDiff = None
        test = json.loads(json.dumps(test))
        first, second, third = self.transformer.transform(test)

        expect_first = typedb_constants.INSERT_KEYWORD
        expect_first += typedb_constants.KEYWORD_SEPARATOR
        expect_first += typedb_constants.VARIABLE_PREFIX + "v0"
        expect_first += build_type("intrusion-set")
        attributes = []
        attributes.append(build_attribute(
            "modified",
            "2024-04-11T02:36:24.044"
        ))
        attributes.append(build_string_attribute(
            "name",
            "Elderwood"
        ))
        attributes.append(build_string_attribute(
            "alias",
            "Elderwood"
        ))
        attributes.append(build_string_attribute(
            "alias",
            "Elderwood Gang"
        ))
        attributes.append(build_string_attribute(
            "stix-id",
            "intrusion-set--03506554-5f37-4f8f-9ce4-0e9f01a1b484"
        ))
        for _ in range(len(attributes)):
            expect_first += "{}"

        expect_first += typedb_constants.OBJECT_ENDING
        expect_first += typedb_constants.OBJECT_SEPARATOR

        # composite entities
        ext_ent_1 = typedb_constants.VARIABLE_PREFIX + "v1"
        ext_ent_1 += build_type("external-reference")
        ext_ent_1_attributes = [
            build_string_attribute(
                "source-name",
                "mitre-attack"
            )
        ]
        ext_ent_1_attributes.append(
            build_string_attribute(
                "external-id",
                "G0066"
            )
        )
        for _ in range(len(ext_ent_1_attributes)):
            ext_ent_1 += "{}"
        ext_ent_1 += typedb_constants.OBJECT_ENDING
        ext_ent_1 += typedb_constants.OBJECT_SEPARATOR

        ext_ent_1_expects = format_permutations(
            ext_ent_1,
            ext_ent_1_attributes
        )

        ext_ent_2 = typedb_constants.VARIABLE_PREFIX + "v3"
        ext_ent_2 += build_type("external-reference")
        ext_ent_2_attributes = [
            build_string_attribute(
                "source-name",
                "Beijing Group"
            )
        ]
        ext_ent_2_attributes.append(
            build_string_attribute(
                "description",
                "(Citation: CSM Elderwood Sept 2012)"
            )
        )
        for _ in range(len(ext_ent_2_attributes)):
            ext_ent_2 += "{}"
        ext_ent_2 += typedb_constants.OBJECT_ENDING
        ext_ent_2 += typedb_constants.OBJECT_SEPARATOR

        ext_ent_2_expects = format_permutations(
            ext_ent_2,
            ext_ent_2_attributes
        )

        # composite relation
        role_object = "referrer"
        role_object += typedb_constants.ROLE_VARIABLE_SEPARATOR
        role_object += typedb_constants.VARIABLE_PREFIX + "v0"

        role_value = "referenced"
        role_value += typedb_constants.ROLE_VARIABLE_SEPARATOR
        role_value += typedb_constants.VARIABLE_PREFIX + "{}"

        ext_role_1 = role_value.format("v1")
        ext_role_2 = role_value.format("v3")

        ext_roles_1 = [role_object, ext_role_1]
        ext_roles_2 = [role_object, ext_role_2]

        ext_rel = typedb_constants.VARIABLE_PREFIX + "{}"
        ext_rel += typedb_constants.VARIABLE_RELATION_SEPARATOR
        ext_rel += typedb_constants.ROLES_BEGINNING
        ext_rel_roles = "{}"
        ext_rel_roles += typedb_constants.ROLE_SEPARATOR
        ext_rel_roles += "{}"
        ext_rel_roles += typedb_constants.ROLES_ENDING
        ext_rel_roles += build_type("external-referencing")
        ext_rel_roles += typedb_constants.OBJECT_ENDING
        ext_rel_roles += typedb_constants.OBJECT_SEPARATOR

        ext_rel_1_var = ext_rel.format("v2")
        ext_rel_2_var = ext_rel.format("v4")

        ext_rel_1_roles_expects = format_permutations(
            ext_rel_roles, ext_roles_1)
        ext_rel_2_roles_expects = format_permutations(
            ext_rel_roles, ext_roles_2)

        ext_rel_1_expects = concat_permutations(
            [ext_rel_1_var],
            ext_rel_1_roles_expects
        )
        ext_rel_2_expects = concat_permutations(
            [ext_rel_2_var],
            ext_rel_2_roles_expects
        )

        ext_1_expects = concat_permutations(
            ext_ent_1_expects,
            ext_rel_1_expects
        )
        ext_2_expects = concat_permutations(
            ext_ent_2_expects,
            ext_rel_2_expects
        )

        expect_main = format_permutations(expect_first, attributes)

        expects = concat_permutations(
            expect_main,
            ext_1_expects,
            ext_2_expects
        )
        self.assertIn(
            TypeQLBuilder.build_insert_query(first),
            expects
        )
        self.assertIsNone(second)

        # SMO object_marking_refs as third element
        main_obj = build_type("intrusion-set")
        main_obj += build_string_attribute(
            "stix-id",
            "intrusion-set--03506554-5f37-4f8f-9ce4-0e9f01a1b484"
        )
        marking = build_type("marking-definition")
        marking += build_string_attribute(
            "stix-id",
            "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
        )
        rel = build_type("object-marking")
        q = TypeQLBuilder.build_insert_query(third)
        self.assertIn(main_obj, q)
        self.assertIn(marking, q)
        self.assertIn(rel, q)

    def test_SRO(self):
        test = {
            "type": "relationship",
            "id": "relationship--78b504a4-2bdd-44dd-b954-a7fa120f1efd",
            "modified": "2018-04-18T17:59:24.739Z",
            "relationship_type": "uses",
            "source_ref": "malware--ff6840c9-4c87-4d07-bbb6-9f50aa33d498",
            "target_ref": "attack-pattern--b21c3b2d-02e6-45b1-980b-e69051040839",
            "external_references": [
                {
                    "source_name": "Kaspersky Flame"
                }
            ],
        }
        self.maxDiff = None
        test = json.loads(json.dumps(test))
        first, second, third = self.transformer.transform(test)

        # Match
        expect_match = typedb_constants.MATCH_KEYWORD
        expect_match += typedb_constants.KEYWORD_SEPARATOR
        expect_match += "{}{}"

        # first entity
        entity_source = typedb_constants.VARIABLE_PREFIX + "v1"
        entity_source += build_type("malware")
        entity_source += build_string_attribute(
            "stix-id",
            "malware--ff6840c9-4c87-4d07-bbb6-9f50aa33d498"
        )
        entity_source += typedb_constants.OBJECT_ENDING
        entity_source += typedb_constants.OBJECT_SEPARATOR

        # second entity
        entity_target = typedb_constants.VARIABLE_PREFIX + "v2"
        entity_target += build_type("attack-pattern")
        entity_target += build_string_attribute(
            "stix-id",
            "attack-pattern--b21c3b2d-02e6-45b1-980b-e69051040839"
        )
        entity_target += typedb_constants.OBJECT_ENDING
        entity_target += typedb_constants.OBJECT_SEPARATOR

        # Summarize match
        match_expected: list[str] = format_permutations(
            expect_match,
            [entity_source, entity_target]
        )

        # main SRO

        # SRO beginning (up to first attribute)
        expect_sro_beginning = typedb_constants.INSERT_KEYWORD
        expect_sro_beginning += typedb_constants.KEYWORD_SEPARATOR
        expect_sro_beginning += typedb_constants.VARIABLE_PREFIX + "v0"
        expect_sro_beginning += typedb_constants.VARIABLE_RELATION_SEPARATOR
        expect_sro_beginning += typedb_constants.ROLES_BEGINNING
        expect_sro_beginning += "{}"
        expect_sro_beginning += typedb_constants.ROLE_SEPARATOR
        expect_sro_beginning += "{}"
        expect_sro_beginning += typedb_constants.ROLES_ENDING
        expect_sro_beginning += build_type("uses")

        # roles
        role_object = "user"
        role_object += typedb_constants.ROLE_VARIABLE_SEPARATOR
        role_object += typedb_constants.VARIABLE_PREFIX + "v1"
        role_value = "used"
        role_value += typedb_constants.ROLE_VARIABLE_SEPARATOR
        role_value += typedb_constants.VARIABLE_PREFIX + "v2"

        sro_beginning_expected: list[str] = format_permutations(
            expect_sro_beginning,
            [role_object, role_value]
        )

        # SRO attributes and ending
        attributes = []
        attributes.append(
            build_string_attribute(
                "stix-id",
                "relationship--78b504a4-2bdd-44dd-b954-a7fa120f1efd"
            )
        )
        attributes.append(
            build_attribute(
                "modified",
                "2018-04-18T17:59:24.739"
            )
        )
        attributes_expect = ""
        for _ in range(len(attributes)):
            attributes_expect += "{}"

        attributes_expect += typedb_constants.OBJECT_ENDING
        attributes_expect += typedb_constants.OBJECT_SEPARATOR

        sro_attributes_expected = format_permutations(
            attributes_expect,
            attributes
        )

        # summarize SRO
        sro_expected = concat_permutations(
            sro_beginning_expected,
            sro_attributes_expected
        )

        # External reference

        # External reference entity
        ext_ref_ent_expected = typedb_constants.VARIABLE_PREFIX + "v3"
        ext_ref_ent_expected += build_type("external-reference")
        ext_ref_ent_expected += build_string_attribute(
            "source-name",
            "Kaspersky Flame"
        )
        ext_ref_ent_expected += typedb_constants.OBJECT_ENDING
        ext_ref_ent_expected += typedb_constants.OBJECT_SEPARATOR

        # External reference relation
        role_object = "referrer"
        role_object += typedb_constants.ROLE_VARIABLE_SEPARATOR
        role_object += typedb_constants.VARIABLE_PREFIX + "v0"
        role_value = "referenced"
        role_value += typedb_constants.ROLE_VARIABLE_SEPARATOR
        role_value += typedb_constants.VARIABLE_PREFIX + "v3"

        ext_ref_rel_expected: list[str] = [""]
        ext_ref_rel_expected = typedb_constants.VARIABLE_PREFIX + "v4"
        ext_ref_rel_expected += typedb_constants.VARIABLE_RELATION_SEPARATOR
        ext_ref_rel_expected += typedb_constants.ROLES_BEGINNING
        ext_ref_rel_expected += "{}"
        ext_ref_rel_expected += typedb_constants.ROLE_SEPARATOR
        ext_ref_rel_expected += "{}"
        ext_ref_rel_expected += typedb_constants.ROLES_ENDING
        ext_ref_rel_expected += build_type("external-referencing")
        ext_ref_rel_expected += typedb_constants.OBJECT_ENDING
        ext_ref_rel_expected += typedb_constants.OBJECT_SEPARATOR

        ext_ref_rel_expected = format_permutations(
            ext_ref_rel_expected,
            [role_object, role_value]
        )

        # summarize external references
        ext_ref_expected = concat_permutations(
            [ext_ref_ent_expected],
            ext_ref_rel_expected
        )

        # Summarize whole insert query
        expect = concat_permutations(
            match_expected,
            sro_expected,
            ext_ref_expected
        )

        self.assertIsNone(first)
        # self.assertEqual(TypeQLBuilder.build_insert_query(second), expect[0])
        self.assertIn(TypeQLBuilder.build_insert_query(second), expect)
        self.assertIsNone(third)


if __name__ == "__main__":
    unittest.main()
