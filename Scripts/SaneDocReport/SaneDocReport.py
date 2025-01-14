import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import os
import base64
from sane_doc_reports.main import run


OUTPUT_FILE_PATH = 'out.docx'
try:
    sane_json_b64 = demisto.args().get('sane_docx_report_base64', '').encode(
        'utf-8')
    orientation = demisto.args().get('orientation', 'portrait').encode(
        'utf-8')
    paper_size = demisto.args().get('paperSize', 'A4').encode(
        'utf-8')
    with open('sane.json', 'wb') as f:
        f.write(base64.b64decode(sane_json_b64))

    run('sane.json', OUTPUT_FILE_PATH, {
        'orientation': orientation.decode('utf-8', 'ignore'),
        'paper_size': paper_size.decode('utf-8', 'ignore')
    })

    with open(OUTPUT_FILE_PATH, 'rb') as f:
        encoded = base64.b64encode(f.read()).decode('utf-8', 'ignore')

    os.remove(OUTPUT_FILE_PATH)
    return_outputs(readable_output='Successfully generated docx',
                   outputs={}, raw_response={'data': encoded})
except Exception as e:
    err = repr(e)
    return_error(f'[SaneDocReports Automation Error] - {err}')
