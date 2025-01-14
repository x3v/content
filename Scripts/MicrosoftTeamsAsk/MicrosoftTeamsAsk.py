import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


def main():
    script_arguments: dict = demisto.args()
    persistent: bool = script_arguments.get('persistent', '') == 'true'
    response: list = demisto.executeCommand('addEntitlement', {'persistent': persistent})
    if isError(response[0]):
        demisto.results(response)
        return

    entitlement: str = response[0]['Contents']
    investigation_id: str = demisto.investigation()['id']
    task_id: str = script_arguments.get('task_id', '')
    message_text: str = script_arguments.get('message', '')

    first_option: str = script_arguments.get('option1', '')
    second_option: str = script_arguments.get('option2', '')
    options: list = [first_option, second_option]
    additional_options: list = argToList(script_arguments.get('additional_options'))
    options.extend(additional_options)

    message: dict = {
        'message_text': message_text,
        'options': options,
        'entitlement': entitlement,
        'investigation_id': investigation_id,
        'task_id': task_id
    }

    command_arguments: dict = {
        'team_member': script_arguments.get('team_member'),
        'message': json.dumps(message),
        'using-brand': 'Microsoft Teams'
    }

    demisto.results(demisto.executeCommand('send-notification', command_arguments))


if __name__ == 'builtins':
    main()
