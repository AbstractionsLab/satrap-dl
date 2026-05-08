"""
Unit tests for decipher.casemanagement.flowintel_connector.create_case_from_bundle.
"""

import unittest
from unittest.mock import Mock, patch

from pyflowintel import PyflowintelException
from pyflowintel.commons.exceptions import PyflowintelConfigurationError

from decipher.casemanagement.flowintel_connector import (
    CaseCreationError,
    UnavailablePyFlowintelError,
    create_case_from_bundle,
)
from decipher.models import IncidentRequest


def _make_client(case_id: int = 42) -> Mock:
    client = Mock()
    client.cases.create.return_value = {"case_id": case_id}
    return client


def _make_bundle(**kwargs) -> IncidentRequest:
    defaults = {"priority_level": "priority-level:low"}
    defaults.update(kwargs)
    return IncidentRequest(**defaults)


_PYFLOW_CLIENT = "decipher.casemanagement.flowintel_connector.PyFlowintel.from_config"


class TestCreateCaseFromBundleSuccess(unittest.TestCase):
    """Success-path tests for create_case_from_bundle."""

    def setUp(self):
        self.client = _make_client(case_id=7)
        patcher = patch(_PYFLOW_CLIENT, return_value=self.client)
        self.addCleanup(patcher.stop) # Equivalent to patcher.stop() in tearDown, but ensures cleanup even if setUp fails
        patcher.start()

    def test_returns_case_id(self):
        """Should return the case_id from the Flowintel response."""
        result = create_case_from_bundle(_make_bundle())
        self.assertEqual(result, 7)
        self.client.cases.create.assert_called_once()

    def test_custom_title_included_in_case(self):
        """Custom title should appear in the title passed to cases.create."""
        create_case_from_bundle(_make_bundle(title="Login Alert"))
        # get the arguments that were passed to the mock when called
        call_args = self.client.cases.create.call_args
        title_arg = call_args.args[0] # title is the only mandatory argument for the create call
        self.assertIn("Login Alert", title_arg)

    def test_default_title_when_not_provided(self):
        """'Incident' should be used when no title is supplied."""
        create_case_from_bundle(_make_bundle())
        title_arg = self.client.cases.create.call_args.args[0]
        self.assertIn("Incident", title_arg)

    def test_title_prefixed_with_decipher(self):
        """Title must always start with the [DECIPHER] prefix."""
        create_case_from_bundle(_make_bundle(title="My Alert"))
        title_arg = self.client.cases.create.call_args.args[0]
        self.assertTrue(title_arg.startswith("[DECIPHER]"))

    def test_priority_level_with_prefix_passed_as_tag(self):
        """A fully-qualified priority tag should be forwarded unchanged."""
        create_case_from_bundle(_make_bundle(priority_level="priority-level:high"))
        kwargs = self.client.cases.create.call_args.kwargs
        self.assertIn("priority-level:high", kwargs["tags"])

    def test_priority_level_normalized(self):
        """A bare level (e.g. 'medium') should be normalized to 'priority-level:medium'."""
        create_case_from_bundle(_make_bundle(priority_level="medium"))
        kwargs = self.client.cases.create.call_args.kwargs
        self.assertIn("priority-level:medium", kwargs["tags"])

    def test_description_dict_formatted_as_string(self):
        """Description dict should be serialized before being passed to Flowintel."""
        create_case_from_bundle(_make_bundle(description={"system": "db01", "severity": "high"}))
        kwargs = self.client.cases.create.call_args.kwargs
        description = kwargs["description"]
        self.assertIsInstance(description, str)
        self.assertIn("db01", description)

    def test_none_description_produces_empty_body(self):
        """A None description should produce an empty string, not raise."""
        create_case_from_bundle(_make_bundle(description=None))
        kwargs = self.client.cases.create.call_args.kwargs
        self.assertEqual(kwargs["description"], "")

    def test_unknown_template_id_falls_back_to_no_template(self):
        """Unknown template_id should log a warning and fall back to creating case without template."""
        # Mock the templates.find_case_temp_by_id to return no template found
        self.client.templates.find_case_temp_by_id.return_value = {"message": "Case template not found"}   
        with self.assertLogs("decipher.casemanagement.flowintel_connector", level="WARNING") as log:
            create_case_from_bundle(_make_bundle(template_id=1))       
        # Verify the warning was logged about missing template
        self.assertTrue(any("No Flowintel template found with ID 1" in message for message in log.output))

    def test_known_template_id_creates_case(self):
        """Known template_id should create a case with the specified template."""
        # Mock the templates.find_case_temp_by_id to return a valid template
        self.client.templates.find_case_temp_by_id.return_value = {"id": 1, "name": "Test Template"}
        with self.assertLogs("decipher.casemanagement.flowintel_connector", level="INFO") as log:
            create_case_from_bundle(_make_bundle(template_id=1))
        # Verify the case was created with the template
        self.client.cases.create.assert_called_once()
        self.assertTrue(any("currently unsupported" in message for message in log.output))


class TestCreateCaseFromBundleErrors(unittest.TestCase):
    """Error-path tests for create_case_from_bundle."""

    def test_configuration_error_raises_unavailable_error(self):
        """PyflowintelConfigurationError during client init should raise UnavailablePyFlowintelError."""
        with patch(_PYFLOW_CLIENT, side_effect=PyflowintelConfigurationError("bad config")):
            with self.assertRaises(UnavailablePyFlowintelError):
                create_case_from_bundle(_make_bundle())

    def test_unavailable_error_is_subclass_of_case_creation_error(self):
        """UnavailablePyFlowintelError must be catchable as CaseCreationError."""
        with patch(_PYFLOW_CLIENT, side_effect=PyflowintelConfigurationError("bad config")):
            with self.assertRaises(CaseCreationError):
                create_case_from_bundle(_make_bundle())

    def test_flowintel_api_error_raises_case_creation_error(self):
        """A PyflowintelException during case creation should be wrapped in CaseCreationError."""
        client = _make_client()
        client.cases.create.side_effect = PyflowintelException("API timeout")
        with patch(_PYFLOW_CLIENT, return_value=client):
            with self.assertRaises(CaseCreationError):
                create_case_from_bundle(_make_bundle())

    def test_case_creation_error_chains_original_exception(self):
        """CaseCreationError should expose the original PyflowintelException as __cause__."""
        original = PyflowintelException("upstream failure")
        client = _make_client()
        client.cases.create.side_effect = original
        with patch(_PYFLOW_CLIENT, return_value=client):
            with self.assertRaises(CaseCreationError) as ctx:
                create_case_from_bundle(_make_bundle())
        self.assertIs(ctx.exception.__cause__, original)


if __name__ == "__main__":
    unittest.main()
