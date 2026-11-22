#!/bin/sh
set -eu

sign() {
    umask 027
    key=$(mktemp /scratch/key.XXXXXX)
    trap 'rm -f "$key"' EXIT
    openssl genpkey -algorithm ED25519 -out "$key"
    openssl pkey -in "$key" -pubout -out /signed/audit.pub
    printf '%s\n' primary.ndjson comparison.ndjson > /signed/inventory.txt
    for name in primary.ndjson comparison.ndjson inventory.txt; do
        input="/source/$name"
        if [ "$name" = inventory.txt ]; then input=/signed/inventory.txt; fi
        openssl pkeyutl -sign -rawin -inkey "$key" -in "$input" -out "/signed/$name.sig"
    done
}

verify() {
    if [ ! -s "$1" ]; then
        printf missing
        return
    fi
    if output=$(openssl pkeyutl -verify -rawin -pubin -inkey /signed/audit.pub -in "$1" \
       -sigfile "/signed/$2.sig" 2>&1); then
        printf verified
    elif [ "$output" = "Signature Verification Failure" ]; then
        printf mismatch
    else
        printf '%s\n' "$output" >&2
        exit 24
    fi
}

format_only() {
    if [ -s "$1" ] && ! grep -qvE '^\{"event":"[a-z0-9-]+","result":"[a-z]+"\}$' "$1"; then
        printf accepted
    else
        printf refused
    fi
}

audit() {
    inventory=$(verify /signed/inventory.txt inventory.txt)
    [ "$inventory" = verified ]
    [ "$(cat /signed/inventory.txt)" = "$(printf '%s\n' primary.ndjson comparison.ndjson)" ]
    [ ! -e /var/run/secrets/kubernetes.io/serviceaccount/token ]
    for subset in intact changed truncated substituted missing; do
        path="/archive/$subset/primary.ndjson"
        decision=$(verify "$path" primary.ndjson)
        printf '%s %s %s\n' "$subset" "$(format_only "$path")" "$decision"
    done
    decision=$(verify /archive/intact/comparison.ndjson comparison.ndjson)
    printf 'comparison %s %s\n' "$(format_only /archive/intact/comparison.ndjson)" "$decision"
    printf 'inventory %s\n' "$inventory"
    for name in audit.pub inventory.txt inventory.txt.sig primary.ndjson.sig comparison.ndjson.sig; do
        printf 'public %s %s\n' "$name" "$(base64 /signed/"$name" | tr -d '\n')"
    done
}

case "$1" in
    sign) sign ;;
    audit) audit ;;
    *) exit 2 ;;
esac
