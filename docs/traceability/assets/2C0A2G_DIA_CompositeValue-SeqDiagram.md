```{mermaid}
sequenceDiagram
ValueConverterAdapter ->> CompositeValueConverter: convert_to_typeql(reference)
CompositeValueConverter ->> QueryBundle: __init__()
QueryBundle -->> CompositeValueConverter: queries
CompositeValueConverter ->> Entity: __init__() with entity_type
Entity -->> CompositeValueConverter: entity
CompositeValueConverter ->> Identification: __init__()
Identification -->> CompositeValueConverter: selfref
loop for every property (stix_name, stix_value) of the composite value
CompositeValueConverter ->> STIXtoTypeDBMapper: get_composite_attribute_info()
STIXtoTypeDBMapper -->> CompositeValueConverter: typedb_name, typedb_type
CompositeValueConverter ->> ValueConverter: get_converter(typedb_type)
ValueConverter -->> CompositeValueConverter: converter
CompositeValueConverter ->> ValueConverter: parse_stix_2_1(stix_value)
ValueConverter -->> CompositeValueConverter:  
CompositeValueConverter ->> ValueConverter: convert_to_typeql(selfref)
ValueConverter -->> CompositeValueConverter: values, additional_queries
loop for every value in values
CompositeValueConverter ->> Entity: add_attribute(typedb_name, value)
Entity -->> CompositeValueConverter:  
end
CompositeValueConverter ->> QueryBundle: extend(additional_queries)
QueryBundle -->> CompositeValueConverter: 
end 
CompositeValueConverter ->> STIXtoTypeDBMapper: get_composite_type_relation()
STIXtoTypeDBMapper -->> CompositeValueConverter: relation_name
CompositeValueConverter ->> Relation: __init__(relation_name)
Relation -->> CompositeValueConverter: relation
CompositeValueConverter ->> STIXtoTypeDBMapper: get_composite_relation_roles()
STIXtoTypeDBMapper -->> CompositeValueConverter: object_role, value_role
CompositeValueConverter ->> Relation: add_roleplayer(object_role, reference.get_variable())
Relation -->> CompositeValueConverter:  
CompositeValueConverter ->> Relation: add_roleplayer(value_role, selfref.get_variable())
Relation -->> CompositeValueConverter:  
CompositeValueConverter ->> QueryBundle: add_structured_attribute(entity, relation)
QueryBundle -->> CompositeValueConverter:  
CompositeValueConverter -->> ValueConverterAdapter: queries
```