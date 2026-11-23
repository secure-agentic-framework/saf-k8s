"""Run the build or evidence stage with the Pod's own scoped API identity."""

import base64
import hashlib
import json
import os
from pathlib import Path
import ssl
import subprocess
import urllib.error
import urllib.request

AUTH = Path('/var/run/fixture-api')
KEY = Path('/var/run/fixture-signer/private.pem')
BUILD = 'handoff-artifact'
EVIDENCE = 'handoff-evidence'
MARKER = 'public-handoff-fixture-v1'
IDENTITY = 'system:serviceaccount:saf-test:handoff-observer'


def request(method, name, fields=None):
    data = json.dumps({'data': fields}).encode() if fields is not None else None
    headers = {'Authorization': 'Bearer ' + (AUTH / 'token').read_text().strip()}
    if data is not None:
        headers['Content-Type'] = 'application/merge-patch+json'
    endpoint = 'https://kubernetes.default.svc/api/v1/namespaces/saf-test/configmaps/' + name
    outgoing = urllib.request.Request(endpoint, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(outgoing, context=ssl.create_default_context(cafile=str(AUTH / 'ca.crt')),
                                    timeout=8) as response:
            return response.status, json.load(response).get('data', {})
    except urllib.error.HTTPError as error:
        return error.code, {}


def main():
    if os.environ['STAGE'] == 'build':
        wrote, _ = request('PATCH', BUILD, {'marker': MARKER})
        denied, _ = request('PATCH', EVIDENCE, {'fixture-comparison': 'unapproved-writer'})
        result = {'artifact_write': wrote, 'evidence_write': denied, 'key_mounted': KEY.exists()}
        print(json.dumps(result))
        return 0 if result == {'artifact_write': 200, 'evidence_write': 403, 'key_mounted': False} else 1
    read, artifact = request('GET', BUILD)
    denied, _ = request('PATCH', BUILD, {'fixture-comparison': 'observer-cannot-edit-build'})
    if read != 200 or artifact.get('marker') != MARKER or denied != 403:
        print(json.dumps({'artifact_read': read, 'artifact_write': denied, 'expected_marker': artifact.get('marker') == MARKER}))
        return 1
    digest = 'sha256:' + hashlib.sha256(artifact['marker'].encode()).hexdigest()
    body = json.dumps({'identity': IDENTITY, 'subject_digest': digest}, sort_keys=True)
    signature = subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(KEY)],
                               input=body.encode(), stdout=subprocess.PIPE, check=True).stdout
    wrote, _ = request('PATCH', EVIDENCE, {'statement': body, 'signature': base64.b64encode(signature).decode()})
    print(json.dumps({'artifact_read': read, 'artifact_write': denied, 'evidence_write': wrote, 'subject_digest': digest}))
    return 0 if wrote == 200 else 1


if __name__ == '__main__':
    raise SystemExit(main())
