from CommonServerPython import *

''' IMPORTS '''

from requests import Session
from zeep import Client
from zeep.transports import Transport
from requests.auth import AuthBase, HTTPBasicAuth
from zeep import helpers
from zeep.cache import SqliteCache
import random
from datetime import datetime
import json
import requests

requests.packages.urllib3.disable_warnings()


class SymantecAuth(AuthBase):
    def __init__(self, user, password, host):
        self.basic = HTTPBasicAuth(user, password)
        self.host = host

    def __call__(self, r):
        if r.url.startswith(self.host):
            return self.basic(r)
        else:
            return r


USE_SSL = not demisto.params().get('insecure', False)
# Remove trailing slash to prevent wrong URL path to service
SERVER_IP = demisto.params().get('url')[:-1] \
    if (demisto.params().get('url') and demisto.params().get('url').endswith('/')) else demisto.params().get('url')
CREDENTIALS = demisto.params().get('credentials')
USERNAME = CREDENTIALS['identifier'] if CREDENTIALS else ''
PASSWORD = CREDENTIALS['password'] if CREDENTIALS else ''
SAVED_REPORT_ID = demisto.params().get('saved-Report-id')  # TODO: Figure out this field
FETCH_TIME = demisto.params().get('fetch_time')
SEVERITY = {
    'high': 3,
    'medium': 2,
    'low': 1,
    'info': 5  # TODO: Check with @maya
}


def get_client():
    wsdl = '{}/ProtectManager/services/v2011/incidents?wsdl'.format(SERVER_IP)

    session = Session()
    session.auth = SymantecAuth(USERNAME, PASSWORD, SERVER_IP)
    session.verify = USE_SSL
    cache = SqliteCache(timeout=None)
    transport = Transport(session=session, cache=cache)

    return Client(wsdl=wsdl, transport=transport)


def get_inc_list(dtobj):
    if type(dtobj) is datetime:
        return CLIENT.service.incidentList(savedReportId=SAVED_REPORT_ID,
                                           incidentCreationDateLaterThan=dtobj)
    else:
        return_error('expected datetime object')


def incident_detail(_id):
    return CLIENT.service.incidentDetail(incidentId=_id,
                                         includeHistory=True,
                                         includeViolations=True)


def myconverter(o):
    if isinstance(o, datetime):
        return o.__str__()


def fetch_incidents():
    last_run = demisto.getLastRun()
    if 'lt_time' not in last_run:
        fetch_time, _ = parse_date_range(FETCH_TIME)
        last_run['lt_time'] = fetch_time
    else:
        last_run['lt_time'] = datetime.strptime(last_run['lt_time'], '%d/%m/%Y %H:%M:%S.%f')

    incident_ids = get_inc_list(last_run['lt_time'])
    incidents = []
    if len(incident_ids['incidentId']) > 0:
        for incident_id in incident_ids['incidentId']:
            inc = incident_detail(str(incident_id))
            rule_name = inc[0]['incident']['violatedPolicyRule'][0]['ruleName']
            inc_created = inc[0]['incident']['incidentCreationDate']
            serialized_obj = helpers.serialize_object(inc[0])
            incidents.append({
                'name': "#" + str(incident_id) + " DLP " + rule_name + "RULE has been violated",
                'details': json.dumps(serialized_obj, default=myconverter),
                'rawJSON': json.dumps(serialized_obj, default=myconverter),
                'severity': SEVERITY[inc[0]['incident']['severity']]
            })
            if inc_created.isoformat() > last_run['lt_time'].isoformat():
                demisto.setLastRun({'lt_time': inc_created.strftime("%d/%m/%Y %H:%M:%S.%f")})
    demisto.incidents(incidents)


def update_incident_command():
    args = demisto.args()
    inc_id = args['incidentId']
    args.pop('incidentId')
    if args['status'] == 'New':
        args['status'] = 'incident.status.New'
    raw_res = CLIENT.service.updateIncidents(
        updateBatch={
            'batchId': str(random.randint(11111, 99999)),  # todo: switch to uuid?
            'incidentId': inc_id, 'incidentAttributes': args
        }
    )
    return_outputs('Incident updated', {}, raw_res)


def get_incident_binaries_command():
    args = demisto.args()
    binaries = CLIENT.service.incidentBinaries(**args)
    if len(binaries["Component"]) > 0:
        for binary in binaries["Component"]:
            demisto.results(fileResult(binary["name"], binary["content"]))
            component = {
                "name": binary["name"],
                "componentId": binary["componentId"],
                "componentType": binary["componentType"]
            }
            demisto.results({
                'ContentsFormat': formats['json'],
                'Type': entryTypes['note'],
                'Contents': component,
                'EntryContext': {'binaries': component}
            })
    else:
        demisto.results("No binaries for the incident")


def get_incident_details_command():
    inc_details = incident_detail(demisto.args()['incidentId'])
    res = helpers.serialize_object(inc_details[0])
    json_res = json.loads(json.dumps(res, default=myconverter))
    demisto.results({
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': json_res,
        'EntryContext': {'SymantecDLP': {'Incident': json_res}}
    })


def get_incident_violations_command():
    args = demisto.args()
    violations = CLIENT.service.incidentViolations(**args)
    if len(violations[0]["violatingComponent"]) > 0:
        for violation in violations[0]["violatingComponent"]:
            violation = helpers.serialize_object(violation)
            demisto.results({
                'ContentsFormat': formats['json'],
                'Type': entryTypes['note'],
                'Contents': json.dumps(violation, ),
                'EntryContext': {'ViolationComponents': violation}
            })


def list_incident_status_command():
    status_list = CLIENT.service.listIncidentStatus()
    demisto.results({
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': status_list,
        'EntryContext': {'incidentStatusList': status_list}
    })


def list_custom_attributes_command():
    custom_attributes = CLIENT.service.listCustomAttributes()
    demisto.results({
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': custom_attributes,
        'EntryContext': {'customAttributes': custom_attributes}
    })


try:
    CLIENT = get_client()
except Exception as e:
    return_error(str(e))


def main():
    handle_proxy()
    command = demisto.command()
    LOG(f'Command being called is {command}')

    try:
        if command == 'fetch-incidents':
            fetch_incidents()
        elif command == 'test-module':
            get_inc_list(datetime.now())
            demisto.results("ok")
        elif command == 'sdlp-incident-details':
            get_incident_details_command()
        elif demisto.command() == 'sdlp-update-incident':
            update_incident_command()
        elif demisto.command() == 'sdlp-incident-binaries':
            get_incident_binaries_command()
        elif demisto.command() == 'sdlp-incident-violations':
            get_incident_violations_command()
        elif demisto.command() == 'sdlp-list-incident-status':
            list_incident_status_command()
        elif demisto.command() == 'sdlp-list-custom-attributes':
            list_custom_attributes_command()
    # Log exceptions
    except Exception as e:
        return_error(str(e))


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
