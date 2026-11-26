"""Attach exact generated CycloneDX bytes to an OCI image in the owned registry."""
import hashlib
import json
import os
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request


OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json"
EMPTY_CONFIG = "application/vnd.oci.empty.v1+json"
CYCLONEDX = "application/vnd.cyclonedx+json"
REQUEST_TIMEOUT_SECONDS = 30


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, new_url):
        return None


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def retain_exact_bom(lab, registry, host_port, repository, layout, subject_digest, subject_manifest,
                     bom_bytes):
    """Publish and independently read back exact local subject and CycloneDX bytes."""
    base = f"https://127.0.0.1:{host_port}"
    context = ssl.create_default_context(cafile=registry.registry_ca)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                         urllib.request.HTTPSHandler(context=context))
    expected_host = urllib.parse.urlsplit(base).netloc
    evidence_path = lab.evidence / "wheel-sbom-retention.json"
    evidence = {
        "scope": "one exact generated CycloneDX file attached to and read back from the case-owned registry",
        "state": "in_progress",
        "stage": "initialize",
        "subject_digest": subject_digest,
        "repository_role": "wheel-image-repository",
        "request_timeout_seconds": REQUEST_TIMEOUT_SECONDS,
        "events": [],
        "readback": {},
        "limitations": ["one case-owned Distribution registry and one local OCI image",
                        "no production registry retention, replication, access policy, or backup claim"],
    }

    def persist():
        temporary = evidence_path.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n")
        os.replace(temporary, evidence_path)

    def block(stage, reason):
        evidence["state"] = "blocked"
        evidence["stage"] = stage
        evidence["failure"] = {"reason": reason}
        persist()
        lab.block(f"SBOM retention {stage}: {reason}")

    def transport_failure(role, stage, method, error):
        timeout = isinstance(error, TimeoutError) or isinstance(
            getattr(error, "reason", None), TimeoutError)
        evidence["events"].append({
            "role": role, "stage": stage, "method": method,
            "outcome": "timeout" if timeout else "transport_error",
            "error_type": type(error).__name__,
        })
        block(stage, "bounded local registry request timed out" if timeout
              else "bounded local registry request failed")

    def request(role, stage, method, path, body=None, content_type=None, accept=None, expected=(200,)):
        evidence["stage"] = stage
        persist()
        headers = {}
        if content_type:
            headers["Content-Type"] = content_type
        if accept:
            headers["Accept"] = accept
        req = urllib.request.Request(base + path, data=body, method=method, headers=headers)
        try:
            with opener.open(req, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                status, response_headers, payload = response.status, response.headers, response.read()
        except urllib.error.HTTPError as error:
            status, response_headers = error.code, error.headers
            try:
                payload = error.read()
            except (urllib.error.URLError, TimeoutError, OSError) as read_error:
                transport_failure(role, stage, method, read_error)
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            transport_failure(role, stage, method, error)
        event = {"role": role, "stage": stage, "method": method,
                 "outcome": "response", "http_status": status,
                 "response_bytes": len(payload)}
        evidence["events"].append(event)
        if status not in expected:
            event["outcome"] = "unexpected_status"
            evidence["state"] = "blocked"
            evidence["stage"] = stage
            evidence["failure"] = {"reason": "unexpected HTTP status", "http_status": status,
                                   "role": role, "method": method}
            persist()
            lab.block(f"SBOM retention {stage}: local registry returned HTTP {status}")
        return status, response_headers, payload

    def upload_blob(role, raw, media_type):
        blob_digest = digest(raw)
        status, headers, _ = request(role, "blob-upload-start", "POST",
                                     f"/v2/{repository}/blobs/uploads/", b"", expected=(202,))
        location = headers.get("Location", "")
        target = urllib.parse.urlsplit(urllib.parse.urljoin(base, location))
        upload_prefix = f"/v2/{repository}/blobs/uploads/"
        if target.scheme != "https" or target.netloc != expected_host or not target.path.startswith(upload_prefix):
            block("blob-upload-location", "registry upload location escaped the owned repository endpoint")
        query = [(key, value) for key, value in urllib.parse.parse_qsl(target.query)
                 if key != "digest"]
        query.append(("digest", blob_digest))
        path = target.path + "?" + urllib.parse.urlencode(query)
        _, upload_headers, _ = request(role, "blob-upload-finish", "PUT", path, raw,
                                       "application/octet-stream", expected=(201,))
        if upload_headers.get("Docker-Content-Digest") != blob_digest:
            evidence["state"] = "blocked"
            evidence["stage"] = "blob-upload-acknowledgement"
            evidence["failure"] = {"reason": "registry blob digest acknowledgement mismatch",
                                   "role": role, "expected_digest": blob_digest}
            persist()
            lab.block("SBOM retention blob-upload-acknowledgement: registry digest did not match")
        return {"mediaType": media_type, "digest": blob_digest, "size": len(raw)}

    if not re.fullmatch(r"fixture/wheel-native", repository):
        block("repository-scope", "repository is outside the fixed wheel fixture")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", subject_digest):
        block("subject-descriptor", "scanned subject digest is not SHA-256 qualified")
    if not isinstance(bom_bytes, bytes) or not bom_bytes:
        block("sbom-input", "generated CycloneDX input is empty or not bytes")
    evidence["subject_digest"] = subject_digest
    evidence["sbom_input"] = {"sha256": digest(bom_bytes), "size": len(bom_bytes)}
    evidence["referrers_fallback_tag"] = "sha256-" + subject_digest.split(":", 1)[1]
    persist()

    subject_path = layout / "blobs" / "sha256" / subject_digest.split(":", 1)[1]
    subject_bytes = subject_path.read_bytes()
    if digest(subject_bytes) != subject_digest:
        block("local-subject-validation", "local OCI subject bytes do not match the scanned manifest digest")
    if subject_manifest.get("mediaType") not in (OCI_MANIFEST, DOCKER_MANIFEST):
        block("local-subject-validation", "scanned subject does not use a supported platform manifest media type")
    subject = {"mediaType": subject_manifest["mediaType"],
               "digest": subject_digest, "size": len(subject_bytes)}
    evidence["subject_descriptor"] = subject
    empty_config = b"{}"
    config_digest = digest(empty_config)
    config_descriptor = {"mediaType": EMPTY_CONFIG, "digest": config_digest,
                         "size": len(empty_config)}
    bom_descriptor = {"mediaType": CYCLONEDX, "digest": digest(bom_bytes),
                      "size": len(bom_bytes)}
    evidence["sbom_blob"] = bom_descriptor
    persist()

    if upload_blob("empty-config", empty_config, EMPTY_CONFIG) != config_descriptor:
        block("empty-config-upload", "registry config blob descriptor differs from exact config bytes")
    if upload_blob("cyclonedx-sbom", bom_bytes, CYCLONEDX) != bom_descriptor:
        block("sbom-upload", "registry SBOM blob descriptor differs from exact CycloneDX bytes")

    artifact = {"schemaVersion": 2, "mediaType": OCI_MANIFEST, "artifactType": CYCLONEDX,
                "config": config_descriptor, "layers": [bom_descriptor], "subject": subject}
    artifact_bytes = json.dumps(artifact, sort_keys=True, separators=(",", ":")).encode("utf-8")
    artifact_digest = digest(artifact_bytes)
    artifact_descriptor = {"mediaType": OCI_MANIFEST, "artifactType": CYCLONEDX,
                           "digest": artifact_digest, "size": len(artifact_bytes)}
    evidence["artifact_manifest"] = artifact_descriptor
    persist()
    _, manifest_headers, _ = request(
        "artifact-manifest", "artifact-manifest-publish", "PUT",
        f"/v2/{repository}/manifests/{artifact_digest}", artifact_bytes,
        OCI_MANIFEST, expected=(201,))
    if manifest_headers.get("Docker-Content-Digest") != artifact_digest:
        evidence["state"] = "blocked"
        evidence["stage"] = "artifact-manifest-acknowledgement"
        evidence["failure"] = {"reason": "registry artifact manifest digest acknowledgement mismatch",
                               "expected_digest": artifact_digest}
        persist()
        lab.block("SBOM retention artifact-manifest-acknowledgement: registry digest did not match")

    if manifest_headers.get("OCI-Subject") is not None:
        block("referrers-profile", "the pinned registry announced native referrers support")
    request("subject-referrers-api", "referrers-api-fallback", "GET",
            f"/v2/{repository}/referrers/{subject_digest}", accept=OCI_INDEX, expected=(404,))

    referrers_tag = evidence["referrers_fallback_tag"]
    evidence["stage"] = "referrers-index-read"
    persist()
    status, _, existing = request("subject-referrers-index", "referrers-index-read", "GET",
                                  f"/v2/{repository}/manifests/{referrers_tag}",
                                  accept=OCI_INDEX, expected=(200, 404))
    try:
        manifests = [] if status == 404 else json.loads(existing).get("manifests", [])
        if not isinstance(manifests, list):
            raise ValueError
    except (TypeError, ValueError, json.JSONDecodeError):
        block("referrers-index-parse", "existing referrers fallback index is malformed")
    if not any(row.get("digest") == artifact_digest for row in manifests):
        manifests.append(artifact_descriptor)
    referrers_index = {"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": manifests}
    index_bytes = json.dumps(referrers_index, sort_keys=True, separators=(",", ":")).encode("utf-8")
    request("subject-referrers-index", "referrers-index-publish", "PUT",
            f"/v2/{repository}/manifests/{referrers_tag}", index_bytes,
            OCI_INDEX, expected=(201,))

    evidence["stage"] = "registry-readback"
    persist()
    _, _, stored_subject = request("image-subject", "subject-readback", "GET",
                                   f"/v2/{repository}/manifests/{subject_digest}",
                                   accept=subject_manifest["mediaType"], expected=(200,))
    _, _, stored_manifest = request("artifact-manifest", "artifact-manifest-readback", "GET",
                                    f"/v2/{repository}/manifests/{artifact_digest}",
                                    accept=OCI_MANIFEST, expected=(200,))
    try:
        stored_artifact = json.loads(stored_manifest)
    except (TypeError, ValueError, json.JSONDecodeError):
        block("artifact-manifest-parse", "read-back artifact manifest is malformed")
    _, _, stored_bom = request("cyclonedx-sbom", "sbom-readback", "GET",
                               f"/v2/{repository}/blobs/{bom_descriptor['digest']}", expected=(200,))
    _, _, stored_index = request("subject-referrers-index", "referrers-index-readback", "GET",
                                 f"/v2/{repository}/manifests/{referrers_tag}",
                                 accept=OCI_INDEX, expected=(200,))
    try:
        readback_entries = json.loads(stored_index).get("manifests", [])
        if not isinstance(readback_entries, list):
            raise ValueError
    except (TypeError, ValueError, json.JSONDecodeError):
        block("referrers-index-readback-parse", "read-back referrers index is malformed")
    readback = {
        "subject_manifest_bytes_identical": stored_subject == subject_bytes,
        "subject_manifest_digest_matches": digest(stored_subject) == subject_digest,
        "manifest_digest_matches": digest(stored_manifest) == artifact_digest,
        "manifest_bytes_identical": stored_manifest == artifact_bytes,
        "subject_descriptor_matches": stored_artifact.get("subject") == subject,
        "referrers_index_contains_exact_artifact_descriptor": any(
            row == artifact_descriptor for row in readback_entries),
        "sbom_blob_bytes_identical": stored_bom == bom_bytes,
        "sbom_blob_digest_matches": digest(stored_bom) == bom_descriptor["digest"],
    }
    verified = all(readback.values()) and stored_artifact.get("artifactType") == CYCLONEDX \
        and stored_artifact.get("config") == config_descriptor \
        and stored_artifact.get("layers") == [bom_descriptor]
    evidence["readback"] = readback
    evidence["state"] = "passed" if verified else "failed"
    evidence["stage"] = "complete"
    if not verified:
        evidence["failure"] = {"reason": "registry readback did not match exact digest, bytes, or subject"}
    persist()
    return verified, evidence
