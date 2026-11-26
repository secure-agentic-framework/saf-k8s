"""Check that the owned HTTPS receiver refuses a fixed wrong credential."""
import base64
import json
import ssl
import sys
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

user = Path("/sink-wrong-auth/username").read_text().strip()
password = Path("/sink-wrong-auth/password").read_text().strip()
wrong = base64.b64encode(f"{user}:{password}".encode()).decode()
request = Request(sys.argv[1], data=b"{}", headers={"Authorization": "Basic " + wrong}, method="POST")
context = ssl.create_default_context(cafile="/sink-ca/ca.pem")
try:
    with urlopen(request, context=context, timeout=4) as response:
        status = response.status
except HTTPError as error:
    status = error.code
print(json.dumps({"unauthorized_rejected": status == 401, "status": status}, sort_keys=True))
