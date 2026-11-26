"""Set up the separate manifest publisher and test a second signer counterfactual."""
PUBLISHER = "dataset-approved-publisher"
OTHER_SIGNATURE = "dataset-manifest-other-signature"


def prepare(lab, image, consumer):
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount",
                "metadata": {"name": PUBLISHER, "namespace": consumer.NS},
                "automountServiceAccountToken": False})
    job = consumer._job(PUBLISHER, "consumer-approved", image)
    pod = job["spec"]["template"]["spec"]
    container = pod["containers"][0]
    container["command"] = ["python", "/fixture/manifest_auth.py"]
    container["volumeMounts"] = [
        mount for mount in container["volumeMounts"] if mount["name"] in {"code", "manifest"}
    ]
    pod["volumes"] = [volume for volume in pod["volumes"] if volume["name"] in {"code", "manifest"}]
    pod["serviceAccountName"] = PUBLISHER
    complete, public = consumer._observe_job(lab, PUBLISHER, job)
    if complete != "1" or public["authorized_signature"] == public["unrelated_signature"]:
        lab.block("The independent fixture publisher did not produce distinct signatures")
    for name, signature in ((consumer.TRUST, public["authorized_signature"]),
                            (OTHER_SIGNATURE, public["unrelated_signature"])):
        lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                    "metadata": {"name": name, "namespace": consumer.NS},
                    "immutable": True, "data": {
                        "public.pem": public["authorized_key"], "manifest.sig": signature,
                    }})


def check(lab, image, consumer):
    complete, denied = consumer._run_consumer(
        lab, "dataset-consumer-untrusted-manifest", "consumer-approved", image, trust=OTHER_SIGNATURE
    )
    expected = {"decision": "denied", "reason": "manifest_untrusted", "consumer_started": False,
                "consumed_bytes": 0, "consumed_partitions": 0}
    lab.check("green", "The approved dataset with an unrelated signature yields zero downstream consumption",
              complete == "1" and denied == expected, denied)
