```{mermaid}
sequenceDiagram
ETLOrchestrator ->> Downloader: fetch
Downloader -->> ETLOrchestrator: 
ETLOrchestrator ->> STIXExtractor: fetch
STIXExtractor -->> ETLOrchestrator: stix_objects
loop for every STIX object
ETLOrchestrator ->> STIXtoTypeQLTransformer: transform(stix_object)
STIXtoTypeQLTransformer -->> ETLOrchestrator: main_entity, main_relation, embedded_relations
end
ETLOrchestrator ->> TypeDBLoader: load(main_entities)
TypeDBLoader -->> ETLOrchestrator: 
ETLOrchestrator ->> TypeDBLoader: load(main_relations)
TypeDBLoader -->> ETLOrchestrator: 
ETLOrchestrator ->> TypeDBLoader: load(embedded_relations)
TypeDBLoader -->> ETLOrchestrator: 
```