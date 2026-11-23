"""Case-owned CA, short-lived keys and validating TLS workload fixtures."""
from hashlib import sha256
import json
from pathlib import Path
import ssl

from fixtures import container, pod, ready

HERE = Path(__file__).resolve().parent
PYTHON = ("docker.io/library/python:3.13.2-alpine@sha256:"
          "323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352")
CODE = "fixture-pki-code"
TRUST = "fixture-pki-trust"
CLIENT = "fixture-pki-client"
HOST = "fixture-pki.saf-test.svc"


class CA:
    def __init__(self, lab):
        self.lab = lab
        self.folder = lab.kubeconfig.parent / "authority"
        self.folder.mkdir(mode=0o700)
        self.cert, key = self.folder / "ca.crt", self.folder / "ca.key"
        lab.command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                    "-subj", "/CN=Owned fixture authority", "-addext", "basicConstraints=critical,CA:TRUE",
                    "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-addext", "subjectKeyIdentifier=hash",
                    "-keyout", str(key), "-out", str(self.cert))
        self.config = self.folder / "ca.conf"
        self.config.write_text(f"""[ca]
default_ca = fixture
[fixture]
certificate = {self.cert}
private_key = {key}
database = {self.folder / "index.txt"}
new_certs_dir = {self.folder}
serial = {self.folder / "serial"}
crlnumber = {self.folder / "crlnumber"}
default_md = sha256
default_days = 1
default_crl_days = 1
policy = fixture_subject
unique_subject = no
[fixture_subject]
commonName = supplied
""")
        (self.folder / "index.txt").touch()
        (self.folder / "serial").write_text("11\n")
        (self.folder / "crlnumber").write_text("01\n")

    def run(self, *args):
        return self.lab.command("openssl", "ca", "-config", str(self.config), "-batch", *args)

    def issue(self, name, san, purpose):
        key, csr, cert, conf = (self.folder / f"{name}.{suffix}" for suffix in ("key", "csr", "crt", "ext"))
        conf.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                        "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n"
                        f"extendedKeyUsage={purpose}\nsubjectAltName={san}\n")
        self.lab.command("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={name}",
                         "-keyout", str(key), "-out", str(csr))
        self.run("-in", str(csr), "-out", str(cert), "-notext", "-extfile", str(conf))
        self.lab.kubectl("create", "secret", "tls", "fixture-identity-" + name,
                         "--cert=" + str(cert), "--key=" + str(key), "-o", "name")
        return cert

    def revoke(self, certificate):
        self.run("-revoke", str(certificate), "-crl_reason", "keyCompromise")

    def revocation_list(self):
        path = self.folder / "current.crl"
        self.run("-gencrl", "-out", str(path))
        return path

    def key_hash(self, certificate):
        key = self.lab.command("openssl", "x509", "-in", str(certificate), "-pubkey", "-noout").stdout
        return sha256(key.encode()).hexdigest()

    def fingerprint(self, certificate):
        return sha256(ssl.PEM_cert_to_DER_cert(certificate.read_text())).hexdigest()


def bundle(lab, ca, crl, initial=False):
    data = {"ca.crt": ca.cert.read_text(), "checked.pem": ca.cert.read_text() + crl.read_text()}
    if initial:
        lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": TRUST}, "data": data})
    else:
        lab.kubectl("patch", "configmap", TRUST, "--type=merge", "-p", json.dumps({"data": data}), "-o", "name")


def common(lab, ca):
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": CODE},
                "data": {"tls.py": (HERE / "tls.py").read_text()}})
    bundle(lab, ca, ca.revocation_list(), initial=True)


def workload(lab, name, keys=(), *, server_mode=None):
    mounts = [{"name": "code", "mountPath": "/code", "readOnly": True},
              {"name": "trust", "mountPath": "/trust", "readOnly": True}]
    volumes = [{"name": "code", "configMap": {"name": CODE}},
               {"name": "trust", "configMap": {"name": TRUST}}]
    for key in keys:
        mounts.append({"name": key, "mountPath": f"/identity/{key}", "readOnly": True})
        volumes.append({"name": key, "secret": {"secretName": "fixture-identity-" + key, "defaultMode": 0o440}})
    command = ["python3", "/code/tls.py", "server", keys[0], server_mode] if server_mode else ["sleep", "560"]
    unit = container("guest", image=PYTHON, command=command, volumeMounts=mounts)
    spec = pod(name, [unit], volumes=volumes, automountServiceAccountToken=False, securityContext={"fsGroup": 65534})
    if server_mode:
        unit["readinessProbe"] = {"tcpSocket": {"port": 8443}, "periodSeconds": 1}
        spec["metadata"]["labels"] = {"saf-k8s.example/pki-backend": name}
    lab.create(spec)


def service(lab, name, target):
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": name},
                "spec": {"selector": {"saf-k8s.example/pki-backend": target},
                         "ports": [{"port": 8443, "targetPort": 8443}]}})


def route(lab, name, target):
    lab.kubectl("patch", "service", name, "--type=merge", "-p", json.dumps({
        "spec": {"selector": {"saf-k8s.example/pki-backend": target}}}), "-o", "name")


def call(lab, host, *, client="none", policy="chain"):
    output = lab.kubectl("exec", CLIENT, "--", "python3", "/code/tls.py", "probe",
                         host, client, policy).stdout
    return json.loads(output)
