import json
import sys
from urllib.error import URLError
from urllib.request import ProxyHandler, build_opener

opener = build_opener(ProxyHandler({}))
try:
    with opener.open(f"http://{sys.argv[1]}:8080/", timeout=2) as response:
        print(json.dumps({"status": response.status, "body": response.read(64).decode()}))
except TimeoutError:
    print(json.dumps({"error": "TimeoutError"}))
except URLError as error:
    if not isinstance(error.reason, TimeoutError):
        raise
    print(json.dumps({"error": "TimeoutError"}))
