import unittest
import os
import re
import stix2.exceptions as se
from stix2.utils import parse_into_datetime

from satrap.etl.etlorchestrator import ETLOrchestrator
from satrap.datamanagement.typedb import typedbmanager as TypeDBMgr
from satrap.etl.exceptions import STIXParsingError
from satrap.commons.log_utils import logger
from satrap.etl.extract.extract_constants import STIX_READER
import satrap.etl.transform.stix_typeql_constants as constants
import tests.etl.load as test_utils


class TestTransformLoadSDO(unittest.TestCase):
    """
    Test cases for the transformation and loading of STIX objects (SDOs) into
    the CTI SKB of SATRAP.
    """

    @classmethod
    def setUpClass(cls):
        cls.server = test_utils.SERVER
        cls.db = test_utils.TEST_DB
        cls.stix_src = test_utils.STIX_TEST_FILE
        TypeDBMgr.create_database(cls.server, cls.db, reset=True)

    def setUp(self):
        self.orchestrator = ETLOrchestrator(STIX_READER)

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.stix_src):
            os.remove(cls.stix_src)

    def test_tl_sdo(self):
        """
        Verifies an "attack-pattern" SDO to be correctly transformed and
        then loaded into the database, and the external references to be 
        properly stored.
        """
        stix_object = {
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": "attack-pattern--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
            "created": "2016-05-12T08:17:27.000Z",
            "modified": "2016-05-12T08:17:27.000Z",
            "name": "Spear Phishing",
            "description": "...",
            "aliases": ["alias1", "alias2"],
            "external_references": [
                {
                    "source_name": "capec",
                    "external_id": "CAPEC-163"
                }
            ]
        }

        test_utils.run_tl(stix_object, self.orchestrator)

        validation_query = ("match "
                            "$x isa attack-pattern, has stix-id 'attack-pattern--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061';"
                            "(referrer:$x, referenced:$eref) isa $external-reference;"
                            "fetch"
                            "$x:attribute;"
                            "$eref:external-id;")
        res = TypeDBMgr.fetch_query(self.server, self.db, validation_query)
        self.assertEqual(len(res), 1)
        result = res[0]

        # check the STIX type
        self.assertIn("x", result)
        self.assertIn("type", result["x"])
        self.assertIn("label", result["x"]["type"])
        self.assertEqual("attack-pattern", result["x"]["type"]["label"])

        attrs = result["x"]["attribute"]
        # next, we consider the 'revoked' attribute added by default
        # by stix2, and that the 2 aliases are stored separately
        self.assertEqual(len(attrs), 9)

        for att in attrs:
            sdo_property = test_utils.get_stix_property_name(
                "attack-pattern", att["type"]["label"], constants.FILE_SDO)
            value = att["value"]

            # adjust the timestamp format for attack-pattern properties
            if sdo_property in ("created", "modified"):
                value = value+"Z"

            if sdo_property == "aliases":
                self.assertIn(value, ["alias1", "alias2"])
            elif sdo_property in stix_object:
                # check that the JSON input is equal to the stored value
                self.assertEqual(stix_object.get(sdo_property), value)
            else:
                # the only property not in the JSON input that can be added is 'revoked'
                self.assertEqual(sdo_property, 'revoked')

        # check that the external reference relation was created
        self.assertEqual(result["eref"]["type"]["label"], "external-reference")
        self.assertEqual(result["eref"]["external-id"]
                         [0]["value"], "CAPEC-163")

    def test_repeated_property(self):
        """Test a STIX object with repeated properties.
        The last occurrence of a property should overwrite the previous ones.
        """
        sdo = {
            "id": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "type": "identity",
            "identity_class": "organization",
            "created": "2017-06-01T00:00:00.000Z",
            "modified": "2022-04-25T14:00:00.188Z",
            "name": "The MITRE Corporation",
            "spec_version": "2.1",
            "created": "2021-05-12T08:17:27.000Z",
            "name": "A second name in the same object",
            "name": "A third instance"
        }

        test_utils.run_tl(sdo, self.orchestrator)

        validation_query = ("match "
                            "$x isa identity,"
                            "has stix-id 'identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5';"
                            "fetch"
                            "$x:attribute;")
        res = TypeDBMgr.fetch_query(self.server, self.db, validation_query)
        self.assertEqual(len(res), 1)
        result = res[0]

        # check the STIX type
        self.assertEqual("identity", result["x"]["type"]["label"])
        attrs = result["x"]["attribute"]
        self.assertEqual(len(attrs), len(sdo.keys()))

        for att in attrs:
            sdo_property = test_utils.get_stix_property_name(
                "identity", att["type"]["label"], constants.FILE_SDO)
            value = att["value"]

            # adjust the timestamp format
            if sdo_property in ("created", "modified"):
                value = value+"Z"

            if sdo_property in sdo:
                # check that the JSON input is equal to the stored value
                self.assertEqual(sdo.get(sdo_property), value)
            else:
                self.assertEqual(sdo_property, 'revoked')

    def test_ov_invalid_value(self):
        """
        Verifies that the attempt at transforming-loading a STIX object (SDO) with
        an invalid value for a predefined open-vocabulary (here `identity_class`)
        logs an appropriate error message. 
        """
        sdo = {
            "id": "identity--733c5838-34d9-4fbf-949c-62aba761184c",
            "type": "identity",
            "identity_class": "an unregistered class",
            "created": "2017-06-01T00:00:00.000Z",
            "modified": "2022-04-25T14:00:00.188Z",
            "name": "The MITRE Corporation",
            "spec_version": "2.1"
        }

        err_str = (
            r"not satisfy the regular expression[\s\S]*?"
            r"identity--733c5838-34d9-4fbf-949c-62aba761184c"
        )

        with self.assertLogs(logger, level='ERROR') as log:
            test_utils.run_tl(sdo, self.orchestrator)
            # Check if the log contains the specific error message for the invalid value
            self.assertTrue(any(
                re.search(err_str, message)
                for message in log.output))

    def test_missing_required_property(self):
        """Test STIX object missing a required property (here `name`)."""
        sdo = {
            "id": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "type": "identity",
            "created": "2017-06-01T00:00:00.000Z",
            "modified": "2022-04-25T14:00:00.188Z",
            "spec_version": "2.1"
        }

        with self.assertRaises(STIXParsingError) as missing:
            test_utils.run_tl(sdo, self.orchestrator)
        self.assertEqual(missing.exception.err_type,
                         se.InvalidValueError.__name__)
        # check the corresponding error message
        self.assertIn("No values for required properties",
                      missing.exception.message)

    def test_custom_stix_type(self):
        """Test STIX object with a non-standard type."""
        sdo = {
            "id": "custom--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "type": "custom",
            "created": "2017-06-01T00:00:00.000Z",
            "modified": "2022-04-25T14:00:00.188Z",
            "name": "Non-standard STIX Type",
            "spec_version": "2.1"
        }

        test_utils.run_tl_and_check_log(self,
            self.orchestrator, sdo, 'WARNING', "Skip object 'custom'")

    def test_kill_chain_phase(self):
        """Test that an indicator SDO with specified kill chain phases is correctly
        transformed and loaded into the database, and that the kill chain phases 
        are correctly associated with the indicator.
        """
        sdo = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--1a536280-ec50-4f95-86ce-f1fd179a68fe",
            "created": "2024-07-23T14:24:42.000Z",
            "name": "Malicious IP 1",
            "pattern": "[ipv4-addr:value = '192.168.1.1']",
            "pattern_type": "stix",
            "valid_from": "2024-07-23T14:24:42.000Z",
            "modified": "2023-10-01T02:28:45.147Z",
            "kill_chain_phases": [
                {
                    "kill_chain_name": "mitre-attack",
                    "phase_name": "initial-access"
                },
                {
                    "kill_chain_name": "mitre-attack",
                    "phase_name": "command-and-control"
                }
            ],
            "revoked": True
        }

        test_utils.run_tl(sdo, self.orchestrator)

        validation_query = ("match "
                            "$x isa indicator, has stix-id 'indicator--1a536280-ec50-4f95-86ce-f1fd179a68fe';"
                            "(used-sdo:$x, kill-chain-step:$kch) isa $kill-chain-ttp-association;"
                            "fetch"
                            "$x:attribute;"
                            "$kch:phase-name;")
        res = TypeDBMgr.fetch_query(self.server, self.db, validation_query)
        # we expect 2 results, one for each kill-chain-phase
        self.assertEqual(len(res), 2)

        # check the STIX type
        self.assertEqual("indicator", res[0]["x"]["type"]["label"])
        # check that the 'indicator' is the same in both results
        self.assertDictEqual(res[0]["x"], res[1]["x"])

        attrs = res[0]["x"]["attribute"]
        self.assertEqual(len(attrs), 10)

        for att in attrs:
            sdo_property = test_utils.get_stix_property_name(
                "indicator", att["type"]["label"], constants.FILE_SDO)
            # logger.debug(f"""{att["type"]["label"]}:{sdo_property} = {att["value"]}""")
            value = att["value"]

            # for timestamp values, adjust the format for comparison
            try:
                parse_into_datetime(value+'Z')
                value = value+"Z"
            except Exception:
                pass  # not a timestamp, nothing to do

            # check that the stored value is equal to the JSON input
            if sdo_property in sdo:
                self.assertEqual(value, sdo[sdo_property])
            else:
                logger.testing(
                    f"""Not in the JSON definition: - {sdo_property}:{att["value"]}""")

        # check that the kill-chain-ttp-associations were created
        if res[0]["kch"]["phase-name"][0]["value"] == "initial-access":
            self.assertEqual(res[1]["kch"]["phase-name"][0]
                             ["value"], "command-and-control")
        else:
            self.assertEqual(res[1]["kch"]["phase-name"]
                             [0]["value"], "initial-access")
            self.assertEqual(res[0]["kch"]["phase-name"][0]
                             ["value"], "command-and-control")

    def test_created_by_missing(self):
        """
        Test case for an SDO where the identity in the 'created_by_ref'
        property does not exist in the database.
        """
        sdo = {
            "type": "intrusion-set",
            "id": "intrusion-set--899ce53f-13a0-479b-a0e4-67d46e241542",
            "created": "2017-05-31T21:31:52.748Z",
            "created_by_ref": "identity--d78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "object_marking_refs": [
                "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
            ],
            "goals": ["goal1", "goal2", "goal3"],
            "spec_version": "2.1",
            "name": "test-set"
        }

        # the identity in created_by_ref does not exist, thus, we expect
        # the corresponding warning
        test_utils.run_tl_and_check_log(self,
            self.orchestrator, sdo, 'WARNING', "Data matching the 'match' clause")

        # we expect each goal to be stored separately
        validation_query = ("match "
                            "$x isa intrusion-set, has stix-id 'intrusion-set--899ce53f-13a0-479b-a0e4-67d46e241542',"
                            "has goals $g;"
                            "fetch $g;")

        res = TypeDBMgr.fetch_query(self.server, self.db, validation_query)
        self.assertEqual(len(res), 3)

    def test_object_refs(self):
        """
        Test the creation of relations corresponding to the 'object_refs' property
        from different SDOs.
        """
        grouping_test_file = "tests/data/test_grouping.json"
        self.orchestrator.transform_load(grouping_test_file, self.server, self.db)

        # check that the relations corresponding to the
        # 'object_refs' property have been created
        verification_query = ("match"
                              "$x isa object-refs;"
                              "get;"
                              "count;")
        res = TypeDBMgr.aggregate_int_query(
            self.server, self.db, verification_query)
        self.assertEqual(res, 6)

    def test_observed_data(self):
        """
        Test the creation of relations corresponding to the 'observed-data' SDO.
        """
        test_file = "tests/data/test_observed_data.json"
        self.orchestrator.transform_load(test_file, self.server, self.db)

        # check that the entities and embedded relations have been created
        verification_query = ("match"
                              "$s isa stix-core-object;"
                              "{$s has stix-id 'observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf';}"
                              "or {$s has stix-id 'domain-name--ecb120bf-2694-4902-a737-62b74539a41b';}"
                              "or {$s has stix-id 'ipv4-addr--efcd5e80-570d-4131-b213-62cb18eaa6a8';}"
                              "or {$s has stix-id 'identity--e5f1b90a-d9b6-40ab-81a9-8a29df4b6b65';};"
                              "$r ($s,$t) isa relation;"
                              "get;"
                              "count;")
        res = TypeDBMgr.aggregate_int_query(
            self.server, self.db, verification_query)
        self.assertEqual(res, 8) # 4 entities and 4 relations

    def test_infrastructure_dates_validation(self):
        """
        Test the validation of infrastructure dates in the 'infrastructure' SDO.
        If 'first_seen' > 'last_seen', a STIXParsingError should be raised.
        """
        sdo = {
            "created": "2024-05-07T11:22:30.000Z",
            "id": "infrastructure--38c47d93-d984-4fd9-b87b-d69d0841628d",
            "infrastructure_types": [
                "command-and-control"
            ],
            "labels": [
                "command-and-control"
            ],
            "modified": "2024-05-07T11:22:30.000Z",
            "name": "Poison Ivy C2",
            "type": "infrastructure",
            "spec_version": "2.1",
            "first_seen": "2018-05-07T11:22:30.000Z",
            "last_seen": "2016-05-07T11:22:30.000Z"
        }

        with self.assertRaises(STIXParsingError) as err:
            test_utils.run_tl(sdo, self.orchestrator)
        self.assertEqual(err.exception.err_type, se.InvalidValueError.__name__)
        self.assertIn("must be greater than", err.exception.message)

    def test_location_validations(self):
        """
        Test several validations on the 'location' SDO. 

        - if 'precision' is present, 'latitude' and 'longitude' must be present too
        - one of 'country', 'region' or ('latitude' and 'longitude') properties
        must be present in the SDO.
        - the 'region' must be valid from an open vocabulary
        - if 'latitude' is present, 'longitude' must be present too and the other way around
        - 'latitude' must be in [-90,90] and 'longitude' in [-180,180]
        """
        location = {
            "id": "location--d78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "type": "location",
            "created": "2017-06-01T00:00:00.000Z",
            "modified": "2022-04-25T14:00:00.188Z",
            "spec_version": "2.1",
            "precision": 25.5
        }

        with self.assertRaises(STIXParsingError) as missing:
            test_utils.run_tl(location, self.orchestrator)
            self.assertEqual(missing.exception.err_type,
                             se.InvalidValueError.__name__)
            self.assertIn("(longitude, precision, latitude, precision) are not met",
                          missing.exception.message)

        location.pop("precision")
        with self.assertRaises(STIXParsingError) as missing:
            test_utils.run_tl(location, self.orchestrator)
        self.assertEqual(missing.exception.err_type,
                         se.InvalidValueError.__name__)
        self.assertIn("must have the properties 'region', 'country', or 'latitude' and 'longitude'",
                      missing.exception.message)

        # check that an invalid 'region' value throws an error
        location["region"] = "mexico"
        test_utils.run_tl_and_check_log(self,
            self.orchestrator, location, 'ERROR', "Invalid Thing Write")

        # give a valid 'region' to enable the continuation of the test
        location["region"] = "melanesia"

        location["latitude"] = 56
        # check that the existence of both 'latitude' and 'longitude' values
        # is validated when only one of them is given
        with self.assertRaises(STIXParsingError) as incomplete:
            test_utils.run_tl(location, self.orchestrator)
        self.assertEqual(incomplete.exception.err_type,
                         se.InvalidValueError.__name__)
        self.assertIn("dependencies for Location: (longitude, latitude) are not met",
                      incomplete.exception.message)

        location["longitude"] = -181.0
        with self.assertRaises(STIXParsingError) as exc:
            test_utils.run_tl(location, self.orchestrator)
        self.assertEqual(exc.exception.err_type, se.InvalidValueError.__name__)
        self.assertIn("minimum value is -180", exc.exception.message)

        # when all is fixed, the TL process runs without errors
        location["longitude"] = -81.0
        location["precision"] = 25.5
        test_utils.run_tl(location, self.orchestrator)

    def test_malware_as_family(self):
        """
        Test case for verifying that a malware SDO is correctly subtyped in TypeDB 
        according to the value of the "is_family" property

        :raises AssertionError: If the length of the query result is not 1 
            or the `subtype` label is not `malware-family`.
        """
        sdo = {
            "type": "malware",
            "id": "malware--00806466-754d-44ea-ad6f-0caf59cb8556",
            "created": "2018-10-17T00:14:20.652Z",
            "revoked": False,
            "modified": "2024-04-10T22:28:21.746Z",
            "name": "TrickBot",
            "description": "[TrickBot](https://attack.mitre.org/software/S0266) is a Trojan spyware\
                program written in C++ that first emerged in September 2016 as a possible successor to\
                [Dyre](https://attack.mitre.org/software/S0024). [TrickBot](https://attack.mitre.org/software/S0266) \
                was developed and initially used by [Wizard Spider](https://attack.mitre.org/groups/G0102) for \
                targeting banking sites in North America, Australia, and throughout Europe; it has since been used \
                against all sectors worldwide as part of \"big game hunting\" ransomware campaigns.\
                (Citation: S2 Grupo TrickBot June 2017)(Citation: Fidelis TrickBot Oct 2016)\
                (Citation: IBM TrickBot Nov 2016)(Citation: CrowdStrike Wizard Spider October 2020)",
            "spec_version": "2.1",
            "is_family": True
        }

        test_utils.run_tl(sdo, self.orchestrator)

        validation_query = ("match"
                            "$x has stix-id 'malware--00806466-754d-44ea-ad6f-0caf59cb8556'; "
                            "$subtype sub! malware;"
                            "$x isa $subtype;"
                            "fetch $subtype;")

        res = TypeDBMgr.fetch_query(self.server, self.db, validation_query)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].get("subtype").get("label"), "malware-family")

    def test_malware_as_instance(self):
        """
        Test case for verifying that a malware SDO is correctly subtyped in TypeDB 
        according to the value of the "is_family" property

        :raises AssertionError: If the length of the query result is not 1 
            or the `subtype` label is not `malware-instance`.
        """
        sdo = {
            "type": "malware",
            "id": "malware--dd974ab6-1db2-4491-a9f2-c4560bac549f",
            "modified": "2024-04-10T22:28:21.746Z",
            "name": "TrickBot2",
            "description": "Another's malware",
            "spec_version": "2.1",
            "is_family": False
        }

        test_utils.run_tl(sdo, self.orchestrator)

        validation_query = ("match"
                            "$x has stix-id 'malware--dd974ab6-1db2-4491-a9f2-c4560bac549f'; "
                            "$subtype sub! malware;"
                            "$x isa $subtype;"
                            "fetch $subtype;")

        res = TypeDBMgr.fetch_query(self.server, self.db, validation_query)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].get("subtype").get(
            "label"), "malware-instance")

    def test_malware_operating_system_refs(self):
        """
        Test the handling of the `operating_system_refs` property in a malware SDO.

        This test verifies that:
        1. An invalid STIX identifier in `operating_system_refs` raises a STIXParsingError with the appropriate message.
        2. A valid STIX identifier of an incorrect STIX type in `operating_system_refs` raises an appropriate STIXParsingError.
        3. A valid STIX identifier of the correct type in `operating_system_refs` does not raise an error 
           but logs a warning as the referred STIX objects are not present in the DB.
       """
        sdo = {
            "type": "malware",
            "id": "malware--31c7253b-81c3-4501-bf4e-56ee1859efac",
            "modified": "2024-04-10T22:28:21.746Z",
            "name": "TrickBot2",
            "description": "Another's malware",
            "spec_version": "2.1",
            "is_family": False,
            "operating_system_refs": "windows"
        }

        with self.assertRaises(STIXParsingError) as exc:
            test_utils.run_tl(sdo, self.orchestrator)
        self.assertIn("not a valid STIX identifier", exc.exception.message)

        sdo["operating_system_refs"] = ["course-of-action--00806466-754d-44ea-ad6f-0caf59cb8556"]
        with self.assertRaises(STIXParsingError) as exc:
            test_utils.run_tl(sdo, self.orchestrator)
        self.assertEqual(exc.exception.err_type, se.InvalidValueError.__name__)
        self.assertIn(
            "not one of the valid types for this property: software", exc.exception.message)

        sdo["operating_system_refs"] = "software--00000000-754d-44ea-ad6f-0caf59cb8556"

        test_utils.run_tl_and_check_log(self,
            self.orchestrator, sdo, 'WARNING', "Data matching the 'match' clause")

    def test_malware_sample_refs_validation(self):
        """
        Test the validation of the 'sample_refs' property in a malware SDO.
        """
        sdo = {
            "type": "malware",
            "id": "malware--73406466-754d-44ea-ad6f-0caf59cb8551",
            "modified": "2024-04-10T22:28:21.746Z",
            "name": "TrickBot2",
            "description": "Another's malware",
            "spec_version": "2.1",
            "is_family": False,
            "sample_refs": ["malware sample"]
        }

        with self.assertRaises(STIXParsingError) as exc:
            test_utils.run_tl(sdo, self.orchestrator)
        self.assertIn("not a valid STIX identifier", exc.exception.message)

        sdo["sample_refs"] = "attack-pattern--0203b5c8-f8b6-4ddb-9ad0-527d727f968b"
        with self.assertRaises(STIXParsingError) as exc:
            test_utils.run_tl(sdo, self.orchestrator)
        self.assertEqual(exc.exception.err_type, se.InvalidValueError.__name__)
        self.assertIn(
            "not one of the valid types for this property:", exc.exception.message)
        self.assertIn("artifact", exc.exception.message)
        self.assertIn("file", exc.exception.message)

        sdo["sample_refs"] = ["artifact--0203b5c8-f8b6-4ddb-9ad0-527d727f968b",
                              "file--ec026a1c-f283-4407-81a2-17cafe5cc38d"]
        test_utils.run_tl_and_check_log(self,
            self.orchestrator, sdo, 'WARNING', "Data matching the 'match' clause")

    def test_malware_os_refs(self):
        """
        This test verifies that a malware SDO correctly references the STIX
        objects referred in its properties.
        """
        # software SCO referred in the malware SDO
        sw = {
            "type": "software",
            "spec_version": "2.1",
            "id": "software--00806466-754d-44ea-ad6f-0caf59cb8556",
            "name": "Word",
            "cpe": "cpe:2.3:a:microsoft:word:2000:*:*:*:*:*:*:*",
            "version": "2002",
            "vendor": "Microsoft"
        }
        sdo = {
            "type": "malware",
            "id": "malware--73406466-754d-44ea-ad6f-0caf59cb8551",
            "modified": "2024-04-10T22:28:21.746Z",
            "name": "TrickBot2",
            "description": "Another's malware",
            "spec_version": "2.1",
            "is_family": False,
            "operating_system_refs": "software--00806466-754d-44ea-ad6f-0caf59cb8556"
        }

        test_utils.run_tl(sw, self.orchestrator)
        test_utils.run_tl(sdo, self.orchestrator)

        self.assertTrue(
            test_utils.check_relation_exists(
            "execution",
            "malware--73406466-754d-44ea-ad6f-0caf59cb8551", 
            "software--00806466-754d-44ea-ad6f-0caf59cb8556"))

    def test_malware_analysis_validations(self):
        """
        Test the validation of malware analysis objects in the ETL process.

        This test case verifies that the ETL process correctly identifies and raises
        errors for invalid values in the properties of a malware-analysis object as per 
        the STIX 2.1 specification.
        """
        ma = {
            "type": "malware-analysis",
            "spec_version": "2.1",
            "id": "malware-analysis--d25167b7-fed0-4068-9ccd-a73dd2c5b07c",
            "created": "2020-01-16T18:52:24.277Z",
            "modified": "2020-01-16T18:52:24.277Z",
            "product": "microsoft",
            "analysis_engine_version": "5.1.0",
            "analysis_definition_version": "053514-0062",
            "analysis_started": "2012-02-11T08:36:14Z",
            "analysis_ended": "2012-02-11T08:36:14Z"
        }

        with self.assertRaises(STIXParsingError) as exc:
            test_utils.run_tl(ma, self.orchestrator)
        self.assertIn("At least one of ", exc.exception.message)

        ma["result"] = "malicious"
        ma["host_vm_ref"] = "autonomous-system--8bcf14e9-2ba2-44ef-9e32-fbbc9d2608b2"
        with self.assertRaises(STIXParsingError) as exc:
            test_utils.run_tl(ma, self.orchestrator)
        self.assertIn("valid types for this property: software",
                      exc.exception.message)

        # set a valid host_vm_ref
        ma["host_vm_ref"] = "software--8bcf14e9-2ba2-44ef-9e32-fbbc9d2608b2"
        # add an invalid operating_system_ref
        ma["operating_system_ref"] = "malware--8bcf14e9-2ba2-44ef-9e32-fbbc9d2608b2"
        with self.assertRaises(STIXParsingError) as exc:
            test_utils.run_tl(ma, self.orchestrator)
        self.assertIn("valid types for this property: software",
                      exc.exception.message)

        ma["operating_system_ref"] = "software--8bcf14e9-2ba2-44ef-9e32-fbbc9d2608b2"
        ma["installed_software_refs"] = ["operating-system--8bcf14e9-2ba2-44ef-9e32-fbbc9d2608b2"]
        with self.assertRaises(STIXParsingError) as exc:
            test_utils.run_tl(ma, self.orchestrator)
        self.assertIn("valid types for this property: software",
                      exc.exception.message)

        # remove all the references to inexistent objects
        # to exclude the associated error and continue with the test
        ma.pop("host_vm_ref")
        ma.pop("operating_system_ref")
        ma.pop("installed_software_refs")

        # insert an email to be used as a sample_ref
        email = {
            "type": "email-addr",
            "spec_version": "2.1",
            "id": "email-addr--ccb4a88e-0d3f-4e80-ad2b-238d82e8f8c8",
            "value": "john@example.com",
            "display_name": "John Doe"
        }
        test_utils.run_tl(email, self.orchestrator)

        ma["sample_ref"] = "email-addr--ccb4a88e-0d3f-4e80-ad2b-238d82e8f8c8"
        test_utils.run_tl_and_check_log(self,
            self.orchestrator, ma, 'ERROR', "objects of type 'email-addr' are not valid")

    def test_malware_analysis_refs(self):
        """
        Test the transformation and loading of references in the properties
        of a malware-analysis object.

        The validation query checks:
        - The number of 'dynamic-analysis-component' relations created.
        - The number of 'analysis-sco-refs' relations created.
        """
        test_file = "tests/data/test_mwa_refs.json"
        self.orchestrator.transform_load(test_file, self.server, self.db)

        validation_query = ("match "
                            "$x has stix-id 'malware-analysis--d25167b7-fed0-4068-9ccd-a73dd2c5b07c'; "
                            "fetch "
                            "analysis-comp-rel: { "
                                "match "
                                "$da ($x,$t) isa dynamic-analysis-component; "
                                "get $da; "
                                "count; "
                            "}; "
                            "sco-ref-rel: { "
                                "match "
                                "$r ($x,$y) isa analysis-sco-refs; "
                                "get $r; "
                                "count; "
                            "};")
        res = TypeDBMgr.fetch_query(self.server, self.db, validation_query)
        # number of 'dynamic-analysis-component' relations created
        self.assertEqual(res[0].get("analysis-comp-rel").get("value"), 4)
        # number of 'analysis-sco-refs' relations created
        self.assertEqual(res[0].get("sco-ref-rel").get("value"), 1)

    def test_opinion_enum(self):
        """
        Test the validation of the 'opinion' field in an Opinion SDO (Structured Data Object).
        """
        sdo = {
            "type": "opinion",
            "spec_version": "2.1",
            "id": "opinion--b01efc25-77b4-4003-b18b-f6e24b5cd9f7",
            "created": "2016-05-12T08:17:27.000Z",
            "modified": "2016-05-12T08:17:27.000Z",
            "opinion": "unregistered",
            "object_refs": ["ipv4-addr--16d2358f-3b0d-4c88-b047-0da2f7ed4471"],
            "explanation": "This doesn't seem feasible. We've seen PandaCat \
                attacking Spanish infrastructure over the last 3 years,\
                so this change in targeting seems too great to be viable. \
                Those methods are more commonly associated with the FlameDragonCrew."
        }

        with self.assertRaises(STIXParsingError) as exc:
            test_utils.run_tl(sdo, self.orchestrator)
        self.assertIn("Invalid value for Opinion 'opinion'", exc.exception.message)

        # check case sensitive for the value of 'opinion'
        sdo["opinion"] = "Strongly-disagree"
        with self.assertRaises(STIXParsingError) as exc:
            test_utils.run_tl(sdo, self.orchestrator)
        self.assertIn("Invalid value for Opinion", exc.exception.message)

        sdo["opinion"] = "strongly-disagree"

        ref = {
			"type": "ipv4-addr",
			"spec_version": "2.1",
			"id": "ipv4-addr--16d2358f-3b0d-4c88-b047-0da2f7ed4471",
			"value": "198.51.100.3"
        }
        test_utils.run_tl(ref, self.orchestrator)
        test_utils.run_tl(sdo, self.orchestrator)


if __name__ == '__main__':
    unittest.main()
