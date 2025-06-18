
from tabulate import tabulate
from satrap.engine.result_structures import Group


def format_dict(dictionary: dict, indent: int = 0) -> str:
	"""
	Formats a dictionary into a string with indentation for nested dictionaries.

	:param dictionary: The dictionary to format.
	:type dictionary: dict
	:param indent: The number of spaces to use for indentation. Defaults to 0.
	:type indent: int, optional
	:return: The formatted string representation of the dictionary.
	:rtype: str
	"""
	output = []
	for key, value in dictionary.items():
		output.append(f'{" " * indent}{key}: ')
		if isinstance(value, dict):
			output.append("\n")
			output.append(format_dict(value, indent + 4))
		else:
			output.append(str(value) + "\n")
	return "".join(output)


def tabulate_stix_obj(stix_object: dict, headers: list[str] = None) -> str:
	"""
	Formats a JSON STIX object as a tabular string using the tabulate library.

	:param stix_object: The STIX object to be formatted.
	:type stix_object: dict
	:param headers: The headers of the table. Default: ["Property", "Value"].
	:type headers: list, optional
	:return: A tabular representation of the dictionary or the empty string.
	:rtype: str
	"""
	if not stix_object:
		return ""
	if headers is None or len(headers) != 2:
		headers = ["Property", "Value"]
	return tabulate(
		stix_object.items(), headers, tablefmt="grid", maxcolwidths=[20, 55]
	)


def tabulate_groups(group_results:list[Group]) -> str:
    if not group_results:
        return ""
    headers = ["Group ID", "Name", "Associated groups", "Description"]
    rows = [group.as_tuple() for group in group_results]
    return tabulate(rows, headers=headers, tablefmt="grid", maxcolwidths=[15,20,30,55])