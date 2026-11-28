"""Check the exact signed NVIDIA measurement archives and emit a bounded receipt."""

from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess
from tempfile import TemporaryDirectory

from lxml import etree
from signxml import SignatureConfiguration, XMLVerifier
from signxml.algorithms import DigestAlgorithm, SignatureMethod
from signxml.exceptions import InvalidDigest

HERE = Path(__file__).resolve().parent
DS = "{http://www.w3.org/2000/09/xmldsig#}"
SWID = "{http://standards.iso.org/iso/19770/-2/2015/schema.xsd}"
HASH = "{http://www.w3.org/2001/04/xmlenc#sha384}"
HISTORICAL = datetime(2026, 11, 23, tzinfo=timezone.utc)
CONFIG = SignatureConfiguration(location="./", expect_references=1,
                                signature_methods=frozenset({SignatureMethod.ECDSA_SHA384}),
                                digest_algorithms=frozenset({DigestAlgorithm.SHA384}))
REFERENCES = {
    "driver": ("580.159.03", "8837324e2491e8e7898ffe1f7f8d3d5f6e364d7e563dea0bc0ba2c2547bb0acb", 22),
    "vbios": ("96.00.74.00.20", "d9bfa0ae2efb2ce981b59bfb87c0a9012eb319560a63f42ee13f17a91a27541a", 12),
}


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def trusted_signer(raw):
    xml = etree.fromstring(raw, etree.XMLParser(resolve_entities=False, no_network=True))
    certs = xml.findall(f"./{DS}Signature/{DS}KeyInfo/{DS}X509Data/{DS}X509Certificate")
    require(len(certs) == 4, "The reference does not contain the expected signer chain")
    pem = [f"-----BEGIN CERTIFICATE-----\n{cert.text.strip()}\n-----END CERTIFICATE-----\n".encode()
           for cert in certs]
    with TemporaryDirectory(prefix="rim-signer-") as temp:
        path = Path(temp)
        leaf = path / "leaf.pem"
        untrusted = path / "untrusted.pem"
        leaf.write_bytes(pem[0])
        untrusted.write_bytes(b"".join(pem[1:]))
        result = subprocess.run(["openssl", "verify", "-no-CApath", "-no-CAstore",
                                 "-attime", str(int(HISTORICAL.timestamp())),
                                 "-CAfile", str(HERE / "nvidia-rim-root.pem"), "-untrusted", str(untrusted),
                                 str(leaf)], capture_output=True, timeout=8)
        require(result.returncode == 0, "NVIDIA reference signer chain failed at the fixed evaluation time")
    return pem[0]


def verify_reference(raw, cert):
    return XMLVerifier().verify(raw, x509_cert=cert, expect_config=CONFIG).signed_xml


def active_measurements(reference):
    values = {}
    payload = reference.find(f"./{SWID}Payload")
    require(payload is not None and len(payload) == 64, "Unexpected NVIDIA reference payload structure")
    for row in payload:
        if row.get("active") == "False":
            continue
        require(row.get("active") == "True" and row.get("size") == "48", "Unexpected active reference row")
        # NVIDIA's reference uses zero-based indices. SPDM numbers the blocks from one.
        index = int(row.get("index")) + 1
        size = int(row.get("alternatives"))
        require(1 <= index <= 64 and 1 <= size <= 8 and index not in values, "Invalid reference row index or shape")
        hashes = [row.get(f"{HASH}Hash{i}", "").lower() for i in range(size)]
        require(all(re.fullmatch(r"[0-9a-f]{96}", item) for item in hashes), "Malformed reference digest")
        values[index] = hashes
    return values


def matches(reference, measured):
    return all(measured.get(str(index)) in alternatives for index, alternatives in reference.items())


def altered_reference_denied(raw, cert, reference):
    digest = next(iter(reference.values()))[0].encode()
    prefix = b'Hash0="'
    old = prefix + digest + b'"'
    if old not in raw:
        old = prefix + digest.upper() + b'"'
    require(old in raw, "Cannot isolate the expected signed reference digest")
    changed = prefix + (b"1" if old[len(prefix):len(prefix)+1] == b"0" else b"0") + old[len(prefix)+1:]
    try:
        verify_reference(raw.replace(old, changed, 1), cert)
    except InvalidDigest:
        return True
    return False


def main():
    process = subprocess.run([str(HERE / "spdm-check")], capture_output=True, timeout=8)
    require(process.returncode == 0 and len(process.stdout) < 16384, "Archived SPDM verifier failed")
    result = json.loads(process.stdout)
    measured = result.pop("measurement_values")
    seen = {}
    for part, (version, digest, count) in REFERENCES.items():
        raw = (HERE / (part + "-rim.xml")).read_bytes()
        require(sha256(raw).hexdigest() == digest, "NVIDIA reference manifest pin differs")
        signer = trusted_signer(raw)
        signed = verify_reference(raw, signer)
        require(signed.tag == f"{SWID}SoftwareIdentity", "Unexpected signed reference document")
        version_info = signed.find(f"./{SWID}Meta")
        require(version_info is not None and version_info.get("colloquialVersion") == version,
                "Signed reference version differs from the pinned report version")
        expected = active_measurements(signed)
        require(len(expected) == count and not seen.keys() & expected.keys(), "Unexpected active reference indices")
        require(matches(expected, measured), "A measured block did not match its signed reference")
        seen.update(expected)
        result[f"{part}_rim_active_measurements_matched"] = len(expected)
        result[f"altered_{part}_rim_denied"] = altered_reference_denied(raw, signer, expected)
    changed = {**measured, str(next(iter(seen))): "f" * 96}
    result["altered_measurement_values_fail_reference_comparison"] = not matches(seen, changed)
    result["certificate_revocation_evaluated"] = False
    result["signed_reference_manifests_verified"] = True
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
