"""Load the reviewed public encoding using only the pinned offline inputs."""
import ast
from base64 import b64decode
from hashlib import sha256
from importlib.metadata import version
from pathlib import Path

from tiktoken import Encoding


ROOT = Path('/opt/tokenizer')
VOCABULARY_SHA256 = '223921b76ee99bde995b7ff738513eef100fb51d18c93597a113bcffe865b2a7'


def load_encoding():
    if version('tiktoken') != '0.12.0':
        raise RuntimeError('The tokenizer release differs from the pinned fixture')
    data = (ROOT / 'cl100k_base.tiktoken').read_bytes()
    if sha256(data).hexdigest() != VOCABULARY_SHA256:
        raise RuntimeError('The encoding vocabulary differs from the reviewed upstream digest')
    source = ROOT / 'lib/tiktoken_ext/openai_public.py'
    definition, = [node for node in ast.parse(source.read_text()).body
                   if isinstance(node, ast.FunctionDef) and node.name == 'cl100k_base']
    pattern, = [ast.literal_eval(value) for node in ast.walk(definition) if isinstance(node, ast.Dict)
                for key, value in zip(node.keys, node.values)
                if isinstance(key, ast.Constant) and key.value == 'pat_str']
    mergeable = {}
    for line in data.splitlines():
        token, rank = line.split()
        mergeable[b64decode(token, validate=True)] = int(rank)
    return Encoding(name='cl100k_base-fixture', pat_str=pattern,
                    mergeable_ranks=mergeable, special_tokens={})
