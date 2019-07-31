import demistomock as demisto
from CommonServerPython import *
import json
import re
import tempfile
from datetime import datetime

from stix.core import STIXPackage

""" HELPER FUNCTIONS"""


def convert_to_json(string):
    """Will try to convert given string to json.

    Args:
        string: str of stix/json file. may be xml, then function will fail

    Returns:
        json object if succeed
        False if failed
    """
    try:
        js = json.loads(string)
        return js
    except ValueError:
        return None


def create_timestamp(timestamp):
    """Takes a timestamp and checks if it matches pattern.

    Args:
        timestamp: (str) given timestamp

    Returns:
        str: timestamp or None if not matches pattern
    """
    try:
        datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%fZ")
        return timestamp
    except ValueError:
        return None


def create_indicator_entry(
        indicator_type,
        value,
        pkg_id,
        ind_id,
        timestamp,
        source=None,
        score=None,
):
    """Creating a JSON object of given args

    Args:
        indicator_type: (str) indicator type
        value: (str) indicator value
        pkg_id: (str) package id
        ind_id: (str) indicator id
        timestamp: (str) timestamp
        source: (str) source of indicator (custom field)
        score: (str) score of indicator (custom field)

    Returns:
        dict:
            {
                "indicator_type": indicator_type,
                "value": value,
                "CustomFields": {
                    "indicatorId": ind_id,
                    "stixPackageId": pkg_id
                }
                "source": ind_id.split("-")[0] or source if provided
                "score": if source is "DBot" then score should be here.
            }
    """
    entry = dict()
    entry["indicator_type"] = indicator_type
    entry["value"] = value
    entry["CustomFields"] = {"indicatorId": ind_id, "stixPackageId": pkg_id}
    entry["source"] = source if source else ind_id.split("-")[0]
    entry["score"] = score
    # Times
    entry["timestamp"] = timestamp
    return entry


def get_score(description):
    """Getting score from description field in STIX2

    Args:
        description: (str)

    Returns:
        str: `IMPACT` field
    """
    if description and isinstance(description, (str, unicode)):
        regex = re.compile("(IMPACT:)(Low|Medium|High)")
        groups = regex.match(description)
        score = groups.group(2) if groups else None
        if score in ("Low", "Medium"):
            return 2
        if score == "High":
            return 3
    return 0


def dscore(score):
    if score == "High":
        return 3
    if score == "Medium":
        return 2
    if score == "Low":
        return 1
    return 0


def build_entry(stx_obj, indicators):
    """Extracting all pattern from stix object
    function will take care of one bundle only.
    Args:
        indicators: (dict) output
        stx_obj: json stix2 format
    """
    if "objects" in stx_obj:
        results_list = list()
        pkg_id = stx_obj.get("id")
        objects = stx_obj.get("objects")
        if isinstance(objects, list):
            for obj in objects:
                if isinstance(obj, dict):
                    # Creating parameters
                    ind_id = obj.get("id")
                    source = obj.get("source")
                    # times
                    timestamp = obj.get("created")

                    score = (
                        dscore(obj.get("score"))
                        if "score" in obj
                        else get_score(obj.get("description"))
                    )

                    for k, v in indicators.items():
                        if isinstance(v, list):
                            for indicator in v:
                                if indicator:
                                    result = create_indicator_entry(
                                        indicator_type=k,
                                        value=indicator,
                                        pkg_id=pkg_id,
                                        ind_id=ind_id,
                                        timestamp=timestamp,
                                        source=source,
                                        score=score,
                                    )
                                    if result:
                                        results_list.append(result)
                        elif v:
                            result = create_indicator_entry(
                                indicator_type=k,
                                value=v,
                                pkg_id=pkg_id,
                                ind_id=ind_id,
                                timestamp=timestamp,
                                source=source,
                                score=score,
                            )
                            if result:
                                results_list.append(result)
        return results_list
    return None


def extract_indicators(data):
    """Gets dict of STIX2.0 object (one in a time)

    Args:
        data: (dict) of STIX2 object. can be

    Returns:
        dict: containing all indicators data

    """
    regex = re.compile("(\\w.*?) = '(.*?)'")

    patterns_dict = {
        "file:hashes": "File",
        "ipv6-addr": "IP",
        "ipv4-addr:": "IP",
        "url:": "URL",
        "domain-name:": "Domain",
        "email:": "Email",
    }

    patterns_lists = {
        "File": list(),
        "IP": list(),
        "Domain": list(),
        "Email": list(),
        "URL": list(),
    }  # type: dict
    # Check if is it's
    if isinstance(data, dict) and data.get("objects"):
        # Create objects
        objects = data.get("objects")

        # Use regex to extract indicators
        if isinstance(objects, list):
            for obj in objects:
                pattern = obj.get("pattern")
                groups = regex.findall(pattern)
                for key, value in patterns_dict.items():
                    for term in groups:
                        if len(term) == 2 and key in term[0]:
                            patterns_lists[value].append(term[1])
        else:
            if isinstance(objects, dict):
                pattern = objects.get("pattern")
                groups = regex.findall(pattern)
                for key, value in patterns_dict.items():
                    for term in groups:
                        if len(term) == 2 and key in term[0]:
                            patterns_lists[value].append(term[1])

        # Make all the values unique
        for key, value in patterns_lists.items():
            patterns_dict[key] = list(set(value))  # type: ignore
        return patterns_lists
    else:
        return_error("No STIX2 object could be parsed")


def stix2_to_demisto(stx_obj):
    """Converts stix2 json to demisto object

    Args:
        stx_obj: json object
    """
    data = list()
    if isinstance(stx_obj, dict):
        indicators = extract_indicators(stx_obj)
        entry = build_entry(stx_obj, indicators)
        if isinstance(entry, list):
            data.extend(entry)
        else:
            data.append(entry)
    elif isinstance(stx_obj, list):
        for obj in stx_obj:
            indicators = extract_indicators(obj)
            entry = build_entry(stx_obj, indicators)
            if entry:
                if isinstance(entry, list):
                    data.extend(entry)
                else:
                    data.append(entry)

    dumped = json.dumps(data)
    demisto.results(dumped)


""" STIX 1 """


def create_new_ioc(data, i, timestamp, pkg_id, ind_id):
    data.append({})
    data[i]["CustomFields"] = {"indicatorId": ind_id, "stixPackageId": pkg_id}
    data[i]["source"] = ind_id.split(":")[0]
    if timestamp:
        data[i]["timestamp"] = timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# SCRIPT START

# IF STIX2 FILE
if __name__ == '__main__':
    txt = demisto.args().get("iocXml").encode("utf-8")
    stx = convert_to_json(txt)
    if stx:
        stix2_to_demisto(stx)
    else:
        with tempfile.NamedTemporaryFile() as temp:
            temp.write(demisto.args()["iocXml"].encode("utf-8"))
            temp.flush()
            stix_package = STIXPackage.from_xml(temp.name)
        data = list()  # type: list
        i = 0

        stix_id = stix_package.id_
        if stix_package.indicators:
            for ind in stix_package.indicators:
                ind_id = ind.id_
                for obs in ind.observables:
                    if hasattr(obs.object_.properties, "hashes"):
                        # File object
                        for digest in obs.object_.properties.hashes:
                            if hasattr(digest, "simple_hash_value"):
                                if isinstance(digest.simple_hash_value.value, list):
                                    for hash in digest.simple_hash_value.value:
                                        create_new_ioc(
                                            data, i, ind.timestamp, stix_id, ind_id
                                        )
                                        data[i]["indicator_type"] = "File"
                                        data[i]["value"] = hash
                                        i = i + 1
                                else:
                                    create_new_ioc(data, i, ind.timestamp, stix_id, ind_id)
                                    data[i]["indicator_type"] = "File"
                                    data[i][
                                        "value"
                                    ] = digest.simple_hash_value.value.strip()
                                    i = i + 1
                    elif hasattr(obs.object_.properties, "category"):
                        # Address object
                        category = obs.object_.properties.category
                        if category.startswith("ip"):
                            for ip in obs.object_.properties.address_value.values:
                                create_new_ioc(data, i, ind.timestamp, stix_id, ind_id)
                                data[i]["indicator_type"] = "IP"
                                data[i]["value"] = ip
                                i = i + 1
                    elif hasattr(obs.object_.properties, "type_"):
                        if obs.object_.properties.type_ == "URL":
                            # URI object
                            create_new_ioc(data, i, ind.timestamp, stix_id, ind_id)
                            data[i]["indicator_type"] = "URL"
                            data[i]["value"] = obs.object_.properties.value.value
                            i = i + 1
                        elif hasattr(obs.object_.properties.value, "values"):
                            for url in obs.object_.properties.value.values:
                                # URI object
                                create_new_ioc(data, i, ind.timestamp, stix_id, ind_id)
                                data[i]["indicator_type"] = "URL"
                                data[i]["value"] = url
                                i = i + 1
        json_data = json.dumps(data)
        demisto.results(json_data)