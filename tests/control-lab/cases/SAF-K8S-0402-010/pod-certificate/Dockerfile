FROM docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90
WORKDIR /opt/fixture
COPY requirements.txt .
RUN pip install --no-cache-dir --only-binary=:all: -r requirements.txt
COPY signer.py workload.py peer_client.py peer_server.py peer_wrong_subject.py peer_foreign_issuer.py ./
USER 65532:65532
