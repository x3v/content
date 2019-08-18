import pytest

import demistomock as demisto
import json


def test_get_alert_contents():
    from ZeroFox import get_alert_contents
    with open('./TestData/alert.json') as f:
        alert_input = json.load(f)
    result = get_alert_contents(alert_input)
    with open('./TestData/alert_result.json') as f:
        expected_output = json.load(f)
    assert expected_output == result

def test_get_alert_contents_war_room():
    from ZeroFox import get_alert_contents_war_room
    with open('./TestData/alert_result.json') as f:
        contents_input = json.load(f)
    result = get_alert_contents_war_room(contents_input)
    with open('./TestData/contents_result.json') as f:
        expected_output = json.load(f)
    assert expected_output == result