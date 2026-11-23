FROM docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90
RUN apt-get update \
    && apt-get install -y --no-install-recommends strace=6.13+ds-1 \
    && rm -rf /var/lib/apt/lists/*
