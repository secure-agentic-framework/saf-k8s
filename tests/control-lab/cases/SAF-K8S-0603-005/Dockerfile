FROM docker.io/library/buildpack-deps:bookworm@sha256:f53cd4c58cdb96a467b98696cd510a949ef4ccd7d23e07b75107de754773007a AS compile
ADD --checksum=sha256:603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a https://github.com/openssl/openssl/releases/download/openssl-3.5.9/openssl-3.5.9.tar.gz /tmp/openssl.tar.gz
RUN mkdir /src && tar -xzf /tmp/openssl.tar.gz -C /src --strip-components=1
WORKDIR /src
RUN ./Configure enable-fips no-tests --prefix=/opt/saf-openssl --openssldir=/opt/saf-openssl/etc --libdir=lib && \
    make -j2 && make install_sw install_fips

FROM docker.io/library/buildpack-deps:bookworm@sha256:f53cd4c58cdb96a467b98696cd510a949ef4ccd7d23e07b75107de754773007a
COPY --from=compile /opt/saf-openssl /opt/saf-openssl
ENV PATH="/opt/saf-openssl/bin:${PATH}" \
    LD_LIBRARY_PATH=/opt/saf-openssl/lib \
    OPENSSL_MODULES=/opt/saf-openssl/lib/ossl-modules
COPY provider.cnf /opt/saf-openssl/etc/provider.cnf
RUN OPENSSL_CONF=/dev/null openssl fipsinstall \
    -module /opt/saf-openssl/lib/ossl-modules/fips.so \
    -out /opt/saf-openssl/etc/fipsmodule.cnf -section_name fips_sect
