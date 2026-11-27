FROM docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90
COPY *.whl /wheelhouse/
RUN pip install --no-index --no-deps --no-cache-dir /wheelhouse/*.whl && rm -r /wheelhouse
USER 1000:1000
