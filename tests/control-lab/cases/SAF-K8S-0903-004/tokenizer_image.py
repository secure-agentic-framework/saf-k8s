"""Build the reviewed tokenizer fixture from two SHA-256 pinned release inputs."""
import hashlib
import json
from pathlib import Path
import shutil


HERE = Path(__file__).resolve().parent


def fetch_inputs(lab, architecture, build):
    pins = json.loads((HERE / 'tokenizer-pins.json').read_text())
    wheel = pins['wheels'].get(architecture)
    if wheel is None:
        lab.block(f'No reviewed tokenizer wheel for node architecture {architecture}')
    vocabulary = pins['vocabulary']
    for artifact in (wheel, vocabulary):
        target = build / artifact['name']
        lab.command('curl', '-fsSL', '--max-time', '45', '--retry', '1', '--output',
                    str(target), artifact['url'], timeout=55)
        if hashlib.sha256(target.read_bytes()).hexdigest() != artifact['sha256']:
            lab.block('The retrieved tokenizer artifact differs from the reviewed release digest')
    return wheel, vocabulary


def build_image(lab, architecture, build, image):
    wheel, vocabulary = fetch_inputs(lab, architecture, build)
    for filename in ('Dockerfile.tokenizer', 'encoding_fixture.py'):
        shutil.copyfile(HERE / filename, build / filename)
    lab.command('docker', 'build', '--network=none', '-f', str(build / 'Dockerfile.tokenizer'),
                '--build-arg', 'TOKENIZER_WHEEL=' + wheel['name'], '-t', image, str(build), timeout=180)
    return wheel['sha256'], vocabulary['sha256']


def load_for_kind(lab):
    architecture = lab.kubectl('get', 'node', lab.cluster + '-control-plane',
                               '-o', 'jsonpath={.status.nodeInfo.architecture}').stdout.strip()
    build = lab.kubeconfig.parent / 'tokenizer-build'
    build.mkdir()
    image = f'saf-k8s-tokenizer-0903-004:{lab.cluster}'
    wheel_digest, vocabulary_digest = build_image(lab, architecture, build, image)
    try:
        lab.command('kind', 'load', 'docker-image', image, '--name', lab.cluster, timeout=120)
    finally:
        lab.command('docker', 'image', 'rm', image, allow_failure=True, timeout=25)
    return image, {'case_node_architecture': architecture, 'wheel_sha256': wheel_digest,
                   'vocabulary_sha256': vocabulary_digest, 'tokenizer_version': '0.12.0'}
