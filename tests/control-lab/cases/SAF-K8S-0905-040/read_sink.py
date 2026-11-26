"""Read only the fixture receiver corpus; print data rows, never credentials."""
import base64
import ssl
import sys
from pathlib import Path
from urllib.request import Request, urlopen

user = Path("/sink-auth/username").read_text().strip()
password = Path("/sink-auth/password").read_text().strip()
authorization = base64.b64encode(f"{user}:{password}".encode()).decode()
request = Request(sys.argv[1], headers={"Authorization": "Basic " + authorization})
context = ssl.create_default_context(cafile="/sink-ca/ca.pem")
with urlopen(request, context=context, timeout=4) as response:
    sys.stdout.write(response.read().decode())
