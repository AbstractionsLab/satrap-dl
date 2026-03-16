from satrap.etl.extract.extractor import STIXExtractor
from satrap.etl.transform.transformer import STIXtoTypeQLTransformer
import satrap.settings as conf


def extract_transform(input_file):
    extractor = STIXExtractor()
    transformer = STIXtoTypeQLTransformer()
    queries_first = []
    queries_second = []
    queries_third = []
    counter = 0

    for obj in (extractor.fetch(input_file)):
        res = transformer.transform(obj)
        if not res:
            continue

        first, second, third = res
        if first:
            queries_first.append(first)
        if second:
            queries_second.append(second)
        if third:
            queries_third.append(third)
        counter += 1
        print(f"Extraction and transformation #{str(counter)};"
              f"lengths of the lists: "
              f"{str(len(queries_first))}, "
              f"{str(len(queries_second))}, "
              f"{str(len(queries_third))}")

    print("--> First batch of queries to be created and inserted. Main entities: ")
    print(*queries_first)
    print("--> Second batch of queries to be created and inserted. Relations: ")
    print(*queries_second)
    print("--> Last batch of queries to be created and inserted. Embedded relations: ")
    print(*queries_third)

if __name__ == "__main__":
    extract_transform(conf.TRANSFORM_SRC_TST)
