#!/bin/sh
set -eu
umask 077
party=${1:?party index required}
case "$party" in
    0|1|2) ;;
    *) exit 2 ;;
esac
cd /work
mkdir Player-Data
ln -s /opt/mp-spdz/Programs Programs
cp -L /trust/*.pem /trust/*.0 Player-Data/
cp -L "/identity/P${party}.key" Player-Data/
input_file="Player-Data/Input-P${party}-0"
awk 'NF != 1 || $1 !~ /^[01]$/ { exit 1 } END { if (NR != 8) exit 1 }' /identity/input-bits
cp /identity/input-bits "$input_file"
test "$(wc -l < "$input_file" | tr -d ' ')" = 8
run_protocol() {
    timeout --signal=TERM 45s /opt/mp-spdz/x86_64/ld-2.31.so \
      --library-path /opt/mp-spdz/x86_64 /opt/mp-spdz/malicious-rep-bin-party.x \
      -p "$party" -ip "$1" -OF . "$2"
}
run_protocol /trust/calibration-addresses saf_quantized_median_calibration
exec timeout --signal=TERM 45s /opt/mp-spdz/x86_64/ld-2.31.so \
  --library-path /opt/mp-spdz/x86_64 /opt/mp-spdz/malicious-rep-bin-party.x \
  -p "$party" -ip /trust/update-addresses -OF . quantized_median
