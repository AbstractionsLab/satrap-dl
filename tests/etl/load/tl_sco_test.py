import unittest
import os

from satrap.datamanagement.typedb.inserthandler import TypeDBBatchInsertHandler
from satrap.etl.etlorchestrator import ETLOrchestrator
from satrap.etl.exceptions import STIXParsingError
import satrap.etl.transform.stix_typeql_constants as constants
from satrap.datamanagement.typedb import typedbmanager as TypeDBMgr
import tests.etl.load as test_utils


class TestTransformLoadSCO(unittest.TestCase):
    """
    Test cases for the transformation and loading of STIX Cyber Observables (SCOs)
    """

    @classmethod
    def setUpClass(cls):
        cls.server = test_utils.SERVER
        cls.db = test_utils.TEST_DB
        cls.stix_src = test_utils.STIX_TEST_FILE
        TypeDBMgr.create_database(cls.server, cls.db, reset=True)

    def setUp(self):
        self.orchestrator = ETLOrchestrator()

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.stix_src):
            os.remove(cls.stix_src)


    def test_artifact_validations(self):
        """
        Test the validation of STIX Artifact objects

        Note:
        The following validations are observed to be missing: 
        - 'decryption_key' MUST NOT be present when the encryption_algorithm property is absent
        - The value of 'url' MUST be a valid URL
        """
        sco = {
            "type": "artifact",
            "spec_version": "2.1",
            "id": "artifact--d9b2d63d-a233-4123-847a-4f4a3b733b8f",
            "mime_type": "application/zip",
            "payload_bin": "ZX7HIBWPQA99NSUhEUgAAADI== ...",
            "url": "some url",
            "decryption_key": "My voice is my passport"
        }

        # only one of 'payload_bin' and 'url' must be present
        with self.assertRaises(STIXParsingError) as exc:
            test_utils.run_tl(sco, self.orchestrator)
        self.assertIn("(payload_bin, url) properties for Artifact are mutually exclusive",
                      exc.exception.message)

        sco.pop("payload_bin")

        # 'hashes' must be present when the 'url' property is present
        with self.assertRaises(STIXParsingError) as exc:
            test_utils.run_tl(sco, self.orchestrator)
        self.assertIn("property dependencies for Artifact: (hashes, url) are not met",
                    exc.exception.message)

        sco['hashes'] = {"sha-256":
                         "effb46bba03f6c8aea5c653f9cf984f170dcdd3bbbe2ff6843c3e5da0e698766"}

        # the encryption algorithm must come from a predefined enumeration
        sco["encryption_algorithm"] = "some alg"
        with self.assertRaises(STIXParsingError) as exc:
            test_utils.run_tl(sco, self.orchestrator)
        self.assertIn("'encryption_algorithm': value 'some alg' is not valid ",
                    exc.exception.message)

        sco.pop("encryption_algorithm")

        # the hashes must come from a predefined vocabulary
        sco['hashes'] = {
            "new-alg": "effb46bba03f6c8aea5c653f9cf984f170dcdd3bbbe2ff6843c3e5da0e698766"
        }
        test_utils.run_tl_and_check_log(
            self, self.orchestrator, sco, "ERROR",
            "Custom keys are not supported in the STIX key-value type 'hashes'")


    def test_directory_validations(self):
        """
        Test the validation of STIX Directory objects

        NOTES:
        Validations are observed to be missing:
        - 'path' MUST be a valid non-empty path
        """
        sco = {
            "type": "directory",
            "spec_version": "2.1",
            "id": "directory--550e8400-e29b-41d4-a716-446655440001",
            "contains_refs": 
                ["artifact--0243bda4-7084-4ae4-803a-3697cb606d0e", 
                 "file--550e8400-e29b-41d4-a716-446655440002"]
        }

        # 'file' or 'directory' for 'contains_refs'
        with self.assertRaises(STIXParsingError) as exc:
            test_utils.run_tl(sco, self.orchestrator)
        self.assertIn('contains_refs', exc.exception.message)
        self.assertIn("not one of the valid types", exc.exception.message)

        sco["contains_refs"].remove("artifact--0243bda4-7084-4ae4-803a-3697cb606d0e")

        # 'path' must be included
        with self.assertRaises(STIXParsingError) as exc:
            test_utils.run_tl(sco, self.orchestrator)
        self.assertIn("No values for required properties",
                        exc.exception.message)

        sco["path"] = ""

        # Valid Directory object should not raise any exceptions
        try:
            test_utils.run_tl(sco, self.orchestrator)
        except STIXParsingError as e:
            self.fail(f"Unexpected STIXParsingError raised for valid Directory object: {e}")


    def test_file(self):
        ref = {
			"type": "file",
			"id": "file--550e8400-e29b-41d4-a716-446655440002",
			"spec_version": "2.1",
			"size": 77312,
            "parent_directory_ref": "file--3333bda4-7084-4ae4-803a-3697cb606d0e"
		}

        # parent_directory_ref must have a 'directory'
        with self.assertRaises(STIXParsingError) as exc:
            test_utils.run_tl(ref, self.orchestrator)
        self.assertIn(
            "not one of the valid types for this property: directory", exc.exception.message)

        ref["parent_directory_ref"] = "directory--3333bda4-7084-4ae4-803a-3697cb606d0e"

        # a 'file' must contain at least one of 'hashes' or 'name'
        with self.assertRaises(STIXParsingError) as exc:
            test_utils.run_tl(ref, self.orchestrator)
        self.assertIn("At least one of ", exc.exception.message)

        ref["name"] = "a92e5b2bae.exe"
        ref["content_ref"] = "artifact--d9b2d63d-a233-4123-847a-4f4a3b733b8f"
        ref.pop("parent_directory_ref")
        test_utils.run_tl(ref, self.orchestrator)

        validation_query = ("match"
                    f"$v isa file, has stix-id '{ref.get('id')}';"
                    "fetch"
                    "$v:attribute;")
        res = TypeDBMgr.fetch_query(self.server, self.db, validation_query)
        self.assertEqual(len(res), 1)
        result = res[0]

        attrs = result["v"]["attribute"]
        self.assertEqual(len(attrs), 5) # including 'defanged' added by stix2

        for att in attrs:
            sco_property = test_utils.get_stix_property_name(
                "file", att["type"]["label"], constants.FILE_SCO)
            value = att.get("value")

            if sco_property in ref:
                self.assertEqual(ref.get(sco_property), value)


    def test_file_dir_refs(self):
        test_file = "tests/data/test_file_dir.json"
        self.orchestrator.transform(test_file)
        self.orchestrator.load(self.server, self.db)

        validation_query = ("match "
                    "{$s has stix-id 'file--0243bda4-7084-4ae4-803a-3697cb606d0e';} or "
                    "{$s has stix-id 'directory--550e8400-e29b-41d4-a716-446655440000';};"
                    "$r ($s,$t) isa relation;")
        res = TypeDBMgr.aggregate_int_query(self.server, self.db, validation_query+"get $r; count;")
        self.assertEqual(res, 3) # 3 relations
        res = TypeDBMgr.aggregate_int_query(self.server, self.db, validation_query+"get $t; count;")
        self.assertEqual(res, 3) # 3 entities


    def test_domain_name(self):
        """
        Test the validation of STIX Domain Name objects
        """
        sco = {
            "type": "domain-name",
            "spec_version": "2.1",
            "id": "domain-name--550e8400-e29b-41d4-a716-446655440003",
        }

        # 'value' must be included
        with self.assertRaises(STIXParsingError) as exc:
            test_utils.run_tl(sco, self.orchestrator)
        self.assertIn("No values for required properties", exc.exception.message)

        sco["value"] = "example.com"
        sco["resolves_to_refs"] = ["any--410e8400-e29b-41d4-a716-446655440007"]

        # resolves_to_refs must be one of ipv6-addr, domain-name, ipv4-addr
        with self.assertRaises(STIXParsingError) as exc:
            test_utils.run_tl(sco, self.orchestrator)
        self.assertIn(
            "not one of the valid types", exc.exception.message)

        sco["resolves_to_refs"] = ["ipv4-addr--550e8400-e29b-41d4-a716-446655440004"]
        test_utils.run_tl(sco, self.orchestrator)

        self.assertTrue(
            test_utils.check_relation_exists(
                "dns-resolves-to", sco.get("id"), sco.get("resolves_to_refs")[0]))


    def test_ipv4_mac(self):
        """
        Test the validation of STIX IPv4 Address objects
        """
        sco = {
            "type": "ipv4-addr",
            "spec_version": "2.1",
            "id": "ipv4-addr--550e8400-e29b-41d4-a716-446655440004",
            "resolves_to_refs": ["mac-addr--65cfcf98-8a6e-4a1b-8f61-379ac4f92d00"]
        }
        ref = {
            "type": "mac-addr",
            "spec_version": "2.1",
            "id": "mac-addr--65cfcf98-8a6e-4a1b-8f61-379ac4f92d00",
            "value": "d2:fb:49:24:37:18"
        }

        test_utils.run_tl(ref, self.orchestrator)

        # 'value' must be included
        with self.assertRaises(STIXParsingError) as exc:
            test_utils.run_tl(sco, self.orchestrator)
        self.assertIn("No values for required properties", exc.exception.message)

        sco["value"] = "192.168.0.1"
        test_utils.run_tl(sco, self.orchestrator)

        self.assertTrue(
            test_utils.check_relation_exists(
                "ip-resolves-to", sco.get("id"), ref.get("id")))


    def test_email_refs(self):
        """
        Test the creation of an email message and its references in the database.
        """
        email_refs = ["email-addr--89f52ea8-d6ef-41e9-8fce-6a29236436ed",
            "email-addr--e4ee5301-b52d-49cd-a8fa-8036738c7194",
            "email-addr--cc1e5301-b52d-49cd-a8fa-8036738c7194",
            "email-addr--73b7698f-b52d-49cd-a8fa-8036738c7194"]
        raw_ref = "artifact--d9b2d63d-a233-4123-847a-4f4a3b733b8f"

        sco = {
            "type": "email-message",
            "spec_version": "2.1",
            "id": "email-message--72b7698f-10c2-465a-a2a6-b4996a2f2265",
            "from_ref": email_refs[0],
            "sender_ref": email_refs[0],
            "to_refs": [email_refs[1]],
            "cc_refs": email_refs[2],
            "bcc_refs": email_refs[3],
            "raw_email_ref": raw_ref,
            "is_multipart": False,
            "message_id": "an email message id",
            "date": "1997-11-21T15:55:06.000Z",
            "subject": "Hello test message"
        }

        # insert referred emails into the DB
        emails = []
        for email_id in email_refs:
            emails.append('insert $v0 isa email-addr, '
                'has spec-version "2.1", '
                f'has stix-id "{email_id}", '
                'has ea-value "alan@example.com", '
                'has display-name "Alan Turing";'
            )

        with TypeDBBatchInsertHandler(self.server, self.db) as inserter:
            inserter.insert(emails)

        # insert email-message and validate the creation of references
        test_utils.run_tl(sco, self.orchestrator)

        validation_query = ("match "
                    f"$v has stix-id '{sco.get('id')}'; "
                    "($v,$x) isa email-sending; "
                    "$x has stix-id $id;"
                    "get $id;")
        result = TypeDBMgr.get_query(self.server, self.db, validation_query)
        self.assertTrue(result) # check that result is not empty

        email_refs.append(raw_ref)
        for res in result:
            self.assertIn(res.get('id').get_value(), email_refs)


    def test_user_acc(self):
        sco = {
            "type": "user-account",
            "spec_version": "2.1",
            "id": "user-account--0007698f-10c2-465a-a2a6-b4996a2f2265",
            "user_id": "1001",
            "account_login": "jdoe",
            "account_type": "unix",
            "display_name": "John Doe",
            "is_service_account": False,
            "is_privileged": False,
            "can_escalate_privs": True,
            "account_created": "2016-01-20T12:31:12Z",
            "credential_last_changed": "2016-01-20T14:27:43Z",
            "account_first_login": "2016-01-20T14:26:07Z",
            "account_last_login": "2016-07-22T16:08:28Z"
        }
        test_utils.run_tl(sco, self.orchestrator)

        # check that the number of attributes of the user account is aligned
        # with the number of properties in the sco: -'type'+'defanged' (added by stix2)
        nattrs = test_utils.get_attributes_num(sco.get("id"))
        self.assertEqual(nattrs,len(sco.keys()))


    def test_email_addr(self):
        """
        Test the transformation and loading of an email address SCO (STIX Cyber Observable).
        It checks that the relationship "email-addr-belongs-to" between the email address 
        and the user account is created.
        """
        sco = {
            "type": "email-addr",
            "spec_version": "2.1",
            "id": "email-addr--72b7698f-10c2-465a-a2a6-b4996a2f2265",
            "value": "john@example.com",
            "display_name": "John Doe",
            "belongs_to_ref": "user-account--0007698f-10c2-465a-a2a6-b4996a2f2265"
        }
        test_utils.run_tl(sco, self.orchestrator)

        self.assertTrue(
            test_utils.check_relation_exists(
                "email-addr-belongs-to", sco.get("id"), sco.get("belongs_to_ref")))


    def test_email_additional_header_fields(self):
        """
        Test the correct TL of the additional_header_fields property of an email-message
        """
        sco = {
            "type": "email-message",
            "spec_version": "2.1",
            "id": "email-message--12b7698f-10c2-465a-a2a6-b4996a2f2265",
            "is_multipart": False,
            "message_id": "123456",
            "date": "2017-11-21T15:55:06.000Z",
            "subject": "Message with headers",
            "additional_header_fields": {
                "Received": "from mail.example.com by smtp.example.com",
                "X-Mailer": "Example Mailer",
                "Reply-To": [
                    "steve@example.com",
                    "jane@example.com"
                ]
            }
        }

        test_utils.run_tl(sco, self.orchestrator)

        validation_query = (
            "match "
            f"$v0 has stix-id '{sco.get('id')}'; "
            "$v2 (item: $x, owner: $v0) isa has-dictionary, has name 'additional_header_fields'; "
            "$x has item-key $k;"
            "get $k;"
        )
        result = TypeDBMgr.get_query(self.server, self.db, validation_query)
        # check that the result set is not empty
        self.assertTrue(result)
        # validate that the inserted keys correspond to the ones in the 
        # 'sco' additional_header_fields' dictionary
        for res in result:
            self.assertIn(res.get('k').get_value(),
                          sco.get("additional_header_fields").keys())


    def test_email_body_multipart(self):
        """
        Test the correct TL of the body-multipart property of an email-message
        """
        sco = {
            "type": "email-message",
            "spec_version": "2.1",
            "id": "email-message--34b7694a-10c2-465a-a2a6-b4996a2f2265",
            "is_multipart": True,
            "subject": "Multipart message",
            "body_multipart": [
                {
                    "body": "This is the first part of the body.",
                    "content_type": "text/plain; charset=utf-8",
                    "content_disposition": "inline"
                },
                {
                    "body": "<html><body>This is the second part of the body.</body></html>",
                    "content_type": "text/html"
                },
                {
                    "content_type": "image/png",
                    "content_disposition": "attachment; filename=\"tabby.png\"",
                    "body_raw_ref": "artifact--4cce66f8-6eaa-53cb-85d5-3a85fca3a6c5"
                }
            ]
        }

        test_utils.run_tl(sco, self.orchestrator)

        validation_query = (
            "match "
            f"$v0 has stix-id '{sco.get('id')}'; "
            "(mime-part:$v1, message:$v0) isa body-multipart; "
            "(mime-part:$v1, non-textual-body:$sco) isa body-raw-ref; "
            "$sco has stix-id $id;"
            "get $id;"
        )
        result = TypeDBMgr.get_query(self.server, self.db, validation_query)
        # TODO: uncomment when 'body-raw-ref' is supported
        # self.assertTrue(result)
        for res in result:
            self.assertIn(res.get('id').get_value(),
                          "artifact--4cce66f8-6eaa-53cb-85d5-3a85fca3a6c5")


    def test_arch_ext(self):
        file = {
            "type": "file",
            "spec_version": "2.1",
            "id": "file--3421bda4-7084-4ae4-803a-3697cb606d0e",
            "name": "foo.zip",
            "hashes": {
                "SHA-256": "35a01331e9ad96f751278b891b6ea09699806faedfa237d40513d92ad1b7100f"
            },
            "mime_type": "application/zip",
            "extensions": {
                "archive-ext": {
                    "contains_refs": [
                        "file--0243bda4-7084-4ae4-803a-3697cb606d0e",
                        "file--550e8400-e29b-41d4-a716-446655440002"
                    ],
                    "comment": "testing TL of archive-ext"
                },
                "ntfs-ext": {
                    "alternate_data_streams": [
                        {
                            "name": "second.stream",
                            "size": 25536
                        }
                    ]
                }
            }
        }
        # error expected as extensions are mutually exclusive
        test_utils.run_tl_and_check_log(
            self, self.orchestrator, file,
            "ERROR", "Two predefined extensions given")

        file.get("extensions").pop("ntfs-ext")
        test_utils.run_tl(file, self.orchestrator)

        self.assertTrue(test_utils.is_of_type(file,"archive-ext"))

        # attributes of the file + attributes of the extension
        self.assertEqual(test_utils.get_attributes_num(file.get("id")), 6)

        # check the creation of the embedded relations
        for ref in file.get("extensions").get("archive-ext").get("contains_refs"):
            self.assertTrue(
            test_utils.check_relation_exists(
                "contains-refs", file.get("id"), ref))


    def test_windows_pebinary_ext(self):
        """
        Test the 'windows-pebinary-ext' extension of a file object.
        This test verifies that the 'windows-pebinary-ext' extension is correctly
        processed and that the appropriate relations are created for the composite
        types or embedded relations within the extension.
        """
        file = {
            "type": "file",
            "spec_version": "2.1",
            "id": "file--f47ac10b-58cc-4372-a567-0e02b2c3d479",
            "name": "foo.exe",
            "hashes": {
                "SHA-256": 
                    "35a01331e9ad96f751278b891b6ea09699806faedfa237d40513d92ad1b7100f"
            },
            "mime_type": "application/x-dosexec",
            "extensions": {
                "windows-pebinary-ext": {
                    "pe_type": "exe",
                    "machine_hex": "014c",
                    "number_of_sections": 4,
                    "number_of_symbols": 0,
                    "size_of_optional_header": 224,
                    "characteristics_hex": "0102",
                    "file_header_hashes": {
                        "MD5": "d41d8cd98f00b204e9800998ecf8427e",
                        "SHA-1": "da39a3ee5e6b4b0d3255bfef95601890afd80709"
                    },
                    "optional_header": {
                        "major_linker_version": 9,
                        "minor_linker_version": 0,
                        "size_of_code": 4096,
                        "size_of_initialized_data": 8192,
                        "size_of_uninitialized_data": 0,
                        "address_of_entry_point": 4096,
                        "base_of_code": 4096,
                        "base_of_data": 8192,
                        "image_base": 4194304,
                        "section_alignment": 4096,
                        "file_alignment": 512,
                        "major_os_version": 5,
                        "minor_os_version": 0,
                        "major_image_version": 0,
                        "minor_image_version": 0,
                        "major_subsystem_version": 5,
                        "minor_subsystem_version": 0,
                        "win32_version_value_hex": "00",
                        "size_of_image": 16384,
                        "size_of_headers": 1024,
                        "size_of_heap_commit": 4096,
                        "loader_flags_hex": "00",
                        "number_of_rva_and_sizes": 16
                    },
                    "sections": [
                        {
                            "name": ".text",
                            "size": 4096,
                            "entropy": 6.5,
                            "hashes": {
                                "MD5": "098f6bcd4621d373cade4e832627b4f6",
                                "SHA-1": "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
                            }
                        },
                        {
                            "name": ".data",
                            "size": 8192,
                            "entropy": 7.2
                        }
                    ]
                }
            }
        }
        test_utils.run_tl(file, self.orchestrator)

        self.assertTrue(test_utils.is_of_type(file,"windows-pebinary-ext"))

        relations = test_utils.get_direct_relations_for_id(file.get('id'))
        # get the STIX property names corresponding to the relations
        # created for composite types or embedded relations
        ext_relations = []

        for res in relations:
            stix_name = test_utils.get_stix_ext_prop_name(
                constants.FILE_SCO,"file","windows-pebinary-ext",res)
            if stix_name is not None:
                ext_relations.append(stix_name)

        # assert that the extracted relations match the expected relations
        self.assertCountEqual(["optional_header", "sections"], ext_relations)


    def test_raster_image_ext(self):
        file = {
            "type": "file",
            "spec_version": "2.1",
            "id": "file--1234bda4-7084-4ae4-803a-3697cb606d0e",
            "name": "image.png",
            "hashes": {
                "SHA-256": "35a01331e9ad96f751278b891b6ea09699806faedfa237d40513d92ad1b7100f"
            },
            "mime_type": "image/png",
            "extensions": {
                "raster-image-ext": {
                    "image_height": 800,
                    "image_width": 600,
                    "bits_per_pixel": 24,
                    "exif_tags": {
                        "Make": "Canon",
                        "Model": "EOS 80D"
                    }
                }
            }
        }

        test_utils.run_tl(file, self.orchestrator)

        self.assertTrue(test_utils.is_of_type(file, "raster-image-ext"))
        self.assertCountEqual(
            ['has-hash', 'has-dictionary'],
            test_utils.get_direct_relations_for_id(file.get('id'))
        )


    def test_network_traffic(self):
        """
        Test the validation of STIX Network Traffic objects
        """
        sco = {
            "type": "network-traffic",
            "spec_version": "2.1",
            "id": "network-traffic--550e8400-e29b-41d4-a716-446655440005",
            "start": "2021-08-01T12:34:56Z",
            "end": "2021-08-01T12:35:56Z",
            "src_ref": "ipv4-addr--550e8400-e29b-41d4-a716-446655440004",
            "dst_ref": "mac-addr--65cfcf98-8a6e-4a1b-8f61-379ac4f92d00",
            "src_port": 12345,
            "dst_port": 80,
            "protocols": ["tcp"],
            "is_active": False,
            "encapsulates_refs": "ipv4-addr--550e8400-e29b-41d4-a716-446655440004"
        }
        ref = {
            "type": "network-traffic",
            "spec_version": "2.1",
            "id": "network-traffic--250e8400-e29b-41d4-a716-446655440006",
            "start": "2021-08-01T12:34:56Z",
            "protocols": ["ipv4", "udp"],
            "src_ref": "ipv4-addr--550e8400-e29b-41d4-a716-446655440004"
        }
        with self.assertRaises(STIXParsingError) as exc:
            test_utils.run_tl(sco, self.orchestrator)
        self.assertIn("not one of the valid types", exc.exception.message)

        test_utils.run_tl(ref, self.orchestrator)
        sco["encapsulates_refs"] = ref.get("id")
        test_utils.run_tl(sco, self.orchestrator)

        self.assertTrue(
            test_utils.check_relation_exists(
                "network-traffic-src", sco.get("id"), sco.get("src_ref")))
        self.assertTrue(
            test_utils.check_relation_exists(
                "network-traffic-dst", sco.get("id"), sco.get("dst_ref")))
        self.assertTrue(
            test_utils.check_relation_exists(
                "encapsulation", sco.get("id"), sco.get("encapsulates_refs")))


    def test_http_request_ext_dicts(self):
        sco = {
            "type": "network-traffic",
            "spec_version": "2.1",
            "id": "network-traffic--56429103-3131-4b74-8d40-a6c76815f85f",
            "dst_ref": "domain-name--550e8400-e29b-41d4-a716-446655440003",
            "protocols": ["tcp"],
            "ipfix": {
                "minimumIpTotalLength": 32,
                "maximumIpTotalLength": 2556
            },
            "extensions": {
                "http-request-ext": {
                    "request_method": "get",
                    "request_value": "/download.html",
                    "request_version": "http/1.1",
                    "request_header": {
                        "Accept-Encoding": "gzip,deflate",
                        "User-Agent": 
                            "Mozilla/5.0 (Windows; U; en-US; rv:1.6) Gecko/20040113",
                        "Host": "www.example.com"
                    }
                }
            }
        }
        test_utils.run_tl(sco, self.orchestrator)

        self.assertTrue(test_utils.is_of_type(sco, "http-request-ext"))

        validation_query = (
            "match "
            f"$v0 has stix-id '{sco.get('id')}';"
            "(item: $x, owner: $v0) isa has-dictionary, has name $n; "
            "get $n;"
        )
        result = TypeDBMgr.get_query(self.server, self.db, validation_query)
        # check that the result set is not empty
        self.assertTrue(result)
        for res in result:
            self.assertIn(res.get('n').get_value(), ['request-header','ipfix'])


    def test_win_service_ext(self):
        process_test_file = "tests/data/test_process.json"
        sco_id = "process--99ab297d-4c39-48ea-9d64-052d596864df"

        self.orchestrator.transform(process_test_file)
        self.orchestrator.load(self.server, self.db)

        self.assertTrue(
            test_utils.check_relation_exists(
                "process-refs",sco_id, 
                "network-traffic--56429103-3131-4b74-8d40-a6c76815f85f")
        )
        self.assertTrue(
            test_utils.check_relation_exists(
                "process-creator-user-ref",sco_id, 
                "user-account--0007698f-10c2-465a-a2a6-b4996a2f2265")
        )
        self.assertTrue(
            test_utils.check_relation_exists(
                "process-refs",sco_id, 
                "file--fc497ad2-640c-4e94-876b-70d2e2b7af4a")
        )
        self.assertTrue(
            test_utils.check_relation_exists(
                "process-hierarchy",sco_id, 
                "process--ba8f56d2-9123-4f8e-9504-3a19c8a91b2e")
        )
        self.assertTrue(
            test_utils.check_relation_exists(
                "service-dll",sco_id, 
                "file--fc497ad2-640c-4e94-876b-70d2e2b7af4a")
        )

        validation_query = (
            "match "
            f"$v0 has stix-id '{sco_id}';"
            "(item: $x, owner: $v0) isa has-dictionary, has name $n; "
            "get $n;"
        )
        result = TypeDBMgr.get_query(self.server, self.db, validation_query)
        self.assertEqual(len(result),1)
        self.assertEqual(result[0].get('n').get_value(), 'environment-variables')


    def test_x509_certificate(self):
        """
        Test the validation of STIX X.509 Certificate objects with x509_v3_extensions
        """
        sco = {
            "type": "x509-certificate",
            "spec_version": "2.1",
            "id": "x509-certificate--550e8400-e29b-41d4-a716-446655440006",
            "serial_number": "1234567890",
            "issuer": "C=US, O=Example Org, CN=example.com",
            "validity_not_before": "2021-01-01T00:00:00Z",
            "validity_not_after": "2022-01-01T00:00:00Z",
            "subject": "C=US, O=Example Org, CN=example.com",
            "subject_public_key_algorithm": "rsa",
            "subject_public_key_modulus": "00:af:82:1d:...",
            "subject_public_key_exponent": 65537,
            "x509_v3_extensions": {
                "basic_constraints": "CA:FALSE",
                "key_usage": ["digitalSignature", "keyEncipherment"],
                "subject_alternative_name": ["DNS:example.com", "DNS:www.example.com"],
                "issuer_alternative_name": "email:ca@example.com",
                "subject_directory_attributes": "dateOfBirth=19900101000000Z",
                "crl_distribution_points": ["http://example.com/crl"],
                "inhibit_any_policy": 0
            }
        }

        test_utils.run_tl(sco, self.orchestrator)
        self.assertTrue(test_utils.is_of_type(sco, "x509-certificate"))
        self.assertTrue(test_utils.is_of_type(sco, "x509-v3-extensions"))


def load_tests(loader, tests, pattern):
    """
    Implements the unittest protocol to run the test cases in an ordered suite
    The signature is predefined by the unittest framework.

    Returns:
        unittest.TestSuite: The suite containing all the specified test cases.
    """
    suite = unittest.TestSuite()
    suite.addTest(TestTransformLoadSCO('test_artifact_validations'))
    suite.addTest(TestTransformLoadSCO('test_x509_certificate'))
    suite.addTest(TestTransformLoadSCO('test_user_acc'))
    suite.addTest(TestTransformLoadSCO('test_email_addr'))
    suite.addTest(TestTransformLoadSCO('test_raster_image_ext'))
    suite.addTest(TestTransformLoadSCO('test_email_refs'))
    suite.addTest(TestTransformLoadSCO('test_file_dir_refs'))
    suite.addTest(TestTransformLoadSCO('test_file'))
    suite.addTest(TestTransformLoadSCO('test_windows_pebinary_ext'))
    suite.addTest(TestTransformLoadSCO('test_directory_validations'))
    suite.addTest(TestTransformLoadSCO('test_ipv4_mac'))
    suite.addTest(TestTransformLoadSCO('test_domain_name'))
    suite.addTest(TestTransformLoadSCO('test_email_additional_header_fields'))
    suite.addTest(TestTransformLoadSCO('test_email_body_multipart'))
    suite.addTest(TestTransformLoadSCO('test_arch_ext'))
    suite.addTest(TestTransformLoadSCO('test_network_traffic'))
    suite.addTest(TestTransformLoadSCO('test_http_request_ext_dicts'))
    suite.addTest(TestTransformLoadSCO('test_win_service_ext'))

    return suite

if __name__ == '__main__':
    unittest.main()
