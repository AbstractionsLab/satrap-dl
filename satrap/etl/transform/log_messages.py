"""Log messages for the transformer."""

# Create
CREATE_START = "Creating STIX Object..."
CREATE_SUCCESS = lambda stix_id, stix_type, class_type: \
	f"STIX Object created: id='{stix_id}', type='{stix_type}', class='{class_type}'"

# build_properties
PROPERTIES_START = "Adding TypeDB attributes..."

# build_extensions
EXTENSIONS_START = "Building extensions..."
EXTENSIONS_FAILED_MISSING_OBJECT = "No extension object found for defined extension"

# find_extension
EXTENSIONS_FIND_START = "Search relevant extension..."
EXTENSIONS_FIND_MULTIPLE_DEFINED = "Extension '%s' already defined. Skip."
EXTENSIONS_FIND_FOUND = "STIX extension found: '%s'"
EXTENSIONS_FIND_CUSTOM = "Custom STIX extension not supported. Skip extension '%s'"
EXTENSIONS_FIND_FINAL = "Relevant extension: '%s'"
EXTENSIONS_FIND_NOTHING_FOUND = "No relevant extension found"

# build_extension_properties
EXTENSIONS_BUILD_PROPERTIES_START = "Building properties for extension: '%s'"

# build_extension_property
EXTENSIONS_PROPERTY_START = "Building extension property '%s'"
EXTENSIONS_PROPERTY_TRANSFORM = "Assignments to '%s': TypeDB name '%s' and value type '%s'"

# property
PROPERTY = "Property '%s': "
PROPERTY_START = PROPERTY + "Start building"
PROPERTY_CUSTOM_ENCOUNTERED = "Custom property encountered: " + PROPERTY
PROPERTY_SUCCESS = "Property '%s' mapped to attribute '%s' of type '%s'"

# custom property
PROPERTY_CUSTOM =  "Unsupported custom property. Skipping property '%s' in STIX object '%s'."

# determine type
DETERMINE_TYPE_START = "Determine type"
DETERMINE_TYPE_FINISHED = "Chosen TypeDB type: '%s'"

# build_typeql
# custom
BUILD_CUSTOM_OBJECT_START = "Custom STIX object not supported. Skip object '%s'"

# core
BUILD_CORE_START = "Building TypeQL statements for '%s'"

# set_up_match
SET_UP_MATCH_START = "set up match object"


# mapping invalid
MAPPING_INVALID = ("Invalid mapping in '{reference}' for '{stix_name}': "
	"'{stix_value}'.\n{exception}")
INVALID_SCHEMA = "Schema invalid"

# value conversion failed
CONVERSION_FAILED = ("Conversion of type '{value_type}' failed in '{reference}' for "
	"\"{stix_name}\": \"{stix_value}\". {exception}")

# unexpected
UNEXPECTED_EXCEPTION = "An unexpected exception occurred"

# transformer
START_TRANSFORM = "Start transformation..."
STIX_OBJECT_CREATION_FAILED = "Creation of STIX Object '%s' failed"
BUILD_TYPEQL_FAILED = "Creation of TypeQL statement failed for STIX Object '%s'"
BUILD_TYPEQL_FAILED_TRANSF = "Creation of TypeQL statement failed"
TRANSFORMATION_COMPLETED = "Transformation of '%s' completed"
BUILDING_FAILED = "Building failed"
