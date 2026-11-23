#!/bin/sh
set -eu
directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
source_hash=$(python3 -B -c 'from hashlib import sha256; from pathlib import Path; import sys; print(sha256(Path(sys.argv[1]).read_bytes()).hexdigest())' "$directory/Dockerfile")
short=$(printf '%.24s' "$source_hash")
image="saf-lab-node-minimum:source-$short"
docker build --pull=false -q -t "$image" --label "org.saf.fixture.node-recipe=$source_hash" \
    -f "$directory/Dockerfile" "$directory" >&2
docker image inspect --format '{{.Id}}' "$image"
