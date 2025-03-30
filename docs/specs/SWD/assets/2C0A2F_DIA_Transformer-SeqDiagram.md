```{mermaid}
sequenceDiagram
STIXtoTypeQLTransformer ->> STIXObjectConverter: create(stix_object)
STIXObjectConverter ->> STIXtoTypeDBMapper: get_class(stix_object.type)
STIXtoTypeDBMapper -->> STIXObjectConverter: class
STIXObjectConverter -->> STIXtoTypeQLTransformer: stix_object_converter_subclass
STIXtoTypeQLTransformer ->> STIXObjectConverter: convert_to_typeql()
STIXObjectConverter ->> STIXObjectConverter: create_typeql_object()
STIXObjectConverter -->> STIXObjectConverter: thing
STIXObjectConverter ->> STIXObjectConverter: create_typeql_properties()
loop for every property
STIXObjectConverter ->> STIXtoTypeDBMapper: get_object_attribute_info(stix_object_type, property_name)
STIXtoTypeDBMapper -->> STIXObjectConverter: typedb_attribute_name, typedb_attribute_value_type
STIXObjectConverter ->> ValueConverter: get_converter(typedb_attribute_value_type)
ValueConverter -->> STIXObjectConverter: converter
STIXObjectConverter ->> ValueConverter: parse_stix_2_1(property_value)
ValueConverter -->> STIXObjectConverter: 
STIXObjectConverter ->> ValueConverter: convert_to_typeql()
ValueConverter -->> STIXObjectConverter: values, queries
end
STIXObjectConverter -->> STIXObjectConverter: attributes, queries
STIXObjectConverter ->> STIXObjectConverter: create_typeql_extensions()
loop for every extension property
STIXObjectConverter ->> STIXtoTypeDBMapper: get_extension_attribute_info(stix_object_type, extension_name, property_name)
STIXtoTypeDBMapper -->> STIXObjectConverter: typedb_attribute_name, typedb_attribute_value_type
STIXObjectConverter ->> ValueConverter: get_converter(typedb_attribute_value_type)
ValueConverter -->> STIXObjectConverter: converter
STIXObjectConverter ->> ValueConverter: parse_stix_2_1(property_value)
ValueConverter -->> STIXObjectConverter: 
STIXObjectConverter ->> ValueConverter: convert_to_typeql()
ValueConverter -->> STIXObjectConverter: values, queries
end
STIXObjectConverter -->> STIXObjectConverter: attributes, queries
STIXObjectConverter -->> STIXtoTypeQLTransformer: query_bundle
STIXtoTypeQLTransformer ->> QueryBundle: build()
QueryBundle -->> STIXtoTypeQLTransformer: main_entity, main_relation, embedded_relations
```