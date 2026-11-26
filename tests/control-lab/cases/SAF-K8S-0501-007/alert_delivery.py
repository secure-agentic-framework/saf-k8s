from http.client import HTTPSConnection
import hashlib, json, ssl

with open("/fixture/alert.json", encoding="utf-8") as f:
    alert = json.load(f)
context = ssl.create_default_context(cafile="/trust/ca.crt")
results = []
fingerprints = []
digests = []
for host in ("alert-receiver-a.saf-0501-007-alerts.svc.cluster.local", "alert-receiver-b.saf-0501-007-alerts.svc.cluster.local"):
    payload = json.dumps(alert, sort_keys=True, separators=(",", ":")).encode()
    conn = HTTPSConnection(host, 8443, context=context, timeout=5)
    conn.connect()
    peer = conn.sock.getpeercert() if conn.sock else {}
    san = dict(peer.get("subjectAltName", ()))
    fingerprints.append(hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest() if conn.sock else "")
    conn.request("POST", "/event", body=payload, headers={"Content-Type":"application/json", "Connection":"close"})
    response = conn.getresponse()
    status = response.status
    ack = json.loads(response.read())
    conn.close()
    readback = HTTPSConnection(host, 8443, context=context, timeout=5)
    readback.request("GET", "/receipt", headers={"Connection":"close"})
    receipt_response = readback.getresponse()
    state = json.loads(receipt_response.read())
    readback.close()
    receipt = state.get("receipts", {}).get(alert["event_id"], {})
    digest = receipt.get("sha256", "")
    digests.append(digest)
    results.append({"host":host,"post_status":status,"ack_matches":ack=={"accepted":True,"event_id":alert["event_id"]},
                    "san_matches":san.get("DNS") == host,"receipt_count":receipt.get("count",0),
                    "receipt_digest_matches_payload":digest==hashlib.sha256(payload).hexdigest()})
print(json.dumps({"receivers":results,"receiver_certificates_distinct":len(fingerprints)==2 and bool(fingerprints[0]) and bool(fingerprints[1]) and fingerprints[0]!=fingerprints[1],
                  "payload_digests_equal":len(digests)==2 and bool(digests[0]) and digests[0]==digests[1]},sort_keys=True))
