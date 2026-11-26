"""Run the digest-pinned tokenizer over a local Kubernetes Service."""
import importlib.util
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
FIXTURE = 'saf-bpe-stream'
CLIENT = 'saf-bpe-stream-client'
TCP_PORT = 8080


def tokenizer_image(lab):
    spec = importlib.util.spec_from_file_location('tokenizer_image', HERE / 'tokenizer_image.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.load_for_kind(lab)


def pod(name, image, command, readiness=None):
    container = {
        'name': 'fixture', 'image': image, 'imagePullPolicy': 'Never',
        'command': ['python', '-B', *command],
        'resources': {'requests': {'cpu': '25m', 'memory': '64Mi'},
                      'limits': {'cpu': '400m', 'memory': '192Mi'}},
        'securityContext': {'allowPrivilegeEscalation': False,
                            'readOnlyRootFilesystem': True,
                            'capabilities': {'drop': ['ALL']}},
        'volumeMounts': [{'name': 'case-files', 'mountPath': '/fixture', 'readOnly': True}],
    }
    if readiness:
        container['ports'] = [{'name': 'http', 'containerPort': TCP_PORT}]
        container['readinessProbe'] = {'httpGet': {'path': readiness, 'port': 'http'},
                                       'periodSeconds': 2, 'timeoutSeconds': 2}
    return {
        'apiVersion': 'v1', 'kind': 'Pod',
        'metadata': {'name': name, 'labels': {'fixture': name}},
        'spec': {'automountServiceAccountToken': False, 'restartPolicy': 'Never',
                 'securityContext': {'runAsNonRoot': True, 'runAsUser': 65534,
                                     'seccompProfile': {'type': 'RuntimeDefault'}},
                 'volumes': [{'name': 'case-files', 'configMap': {'name': FIXTURE}}],
                 'containers': [container]},
    }


def run(lab):
    image, provenance = tokenizer_image(lab)
    scripts = {file: (HERE / file).read_text() for file in ('stream_worker.py', 'stream_client.py')}
    lab.create({'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': FIXTURE},
                'immutable': True, 'data': scripts})
    lab.create({'apiVersion': 'v1', 'kind': 'Service', 'metadata': {'name': FIXTURE},
                'spec': {'selector': {'fixture': FIXTURE},
                         'ports': [{'name': 'http', 'port': TCP_PORT, 'targetPort': 'http'}]}})
    lab.create(pod(FIXTURE, image, ['/fixture/stream_worker.py'], readiness='/health'))
    lab.create(pod(CLIENT, image, ['-c', 'import time; time.sleep(150)']))
    lab.kubectl('wait', '--for=condition=Ready', 'pod/' + FIXTURE, 'pod/' + CLIENT,
                '--timeout=45s', timeout=55)
    result = lab.kubectl('exec', 'pod/' + CLIENT, '--', 'python', '-B',
                         '/fixture/stream_client.py', '--host', FIXTURE, timeout=28,
                         allow_failure=True)
    (lab.evidence / 'tokenizer-stream-client.raw.log').write_text(result.stdout + result.stderr)
    if result.returncode:
        lab.check('green', 'The separate client verifies the BPE boundary and bounded HTTP stream',
                  False, {'client_exit': result.returncode})
    try:
        observations = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        lab.block(f'The streaming fixture returned invalid observations: {error}')
    return observations, provenance
