"""Call one known fixture HTTP path from the selected Kubernetes Pod."""
import json
import urllib.error
import urllib.request

request = json.loads(__CASE_REQUEST__)
body = request["body"]
payload = None if body is None else json.dumps(body).encode()
query = urllib.request.Request(request["url"], data=payload, headers={"Content-Type": "application/json"})
try:
    with urllib.request.urlopen(query, timeout=2) as response:
        result = {"status": response.status, "body": json.load(response)}
except urllib.error.HTTPError as error:
    with error:
        result = {"status": error.code, "body": json.load(error)}
except TimeoutError:
    result = {"transport": "timeout"}
except urllib.error.URLError as error:
    if not isinstance(error.reason, TimeoutError):
        raise
    result = {"transport": "timeout"}
print(json.dumps(result, sort_keys=True, separators=(",", ":")))
