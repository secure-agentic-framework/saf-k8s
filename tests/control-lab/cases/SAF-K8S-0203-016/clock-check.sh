#!/bin/sh
set -eu
umask 077
work=$(mktemp -d)
primary_pid=
secondary_pid=
client_pid=
cleanup() {
    if [ -n "$primary_pid" ]; then kill "$primary_pid" 2>/dev/null || true; fi
    if [ -n "$secondary_pid" ]; then kill "$secondary_pid" 2>/dev/null || true; fi
    if [ -n "$client_pid" ]; then kill "$client_pid" 2>/dev/null || true; fi
    rm -rf "$work"
}
trap cleanup EXIT
cd "$work"

server_config() {
    cat <<CONF
port $2
bindaddress $1
cmdport 0
bindcmdaddress /
pidfile $work/$3.pid
local stratum 8
allow 127.0.0.0/8
CONF
}
server_config 127.0.0.1 12123 primary >primary.conf
server_config 127.0.0.2 12124 secondary >secondary.conf
chronyd -n -x -U -f primary.conf >primary.log 2>&1 &
primary_pid=$!
chronyd -n -x -U -f secondary.conf >secondary.log 2>&1 &
secondary_pid=$!
sleep 1
if ! kill -0 "$primary_pid" "$secondary_pid" 2>/dev/null; then
    cat primary.log secondary.log >&2
    exit 1
fi
cat >client.conf <<CONF
server 127.0.0.1 port 12123 minpoll 0 maxpoll 0 iburst prefer
server 127.0.0.2 port 12124 minpoll 0 maxpoll 0 iburst
maxdistance 0.1
maxclockerror 20000
cmdport 13230
bindcmdaddress /
bindcmdaddress 127.0.0.1
pidfile $work/client.pid
CONF
chronyd -n -x -U -f client.conf >client.log 2>&1 &
client_pid=$!
wait_for() {
    target="$1"
    tick=0
    while [ "$tick" -lt 24 ]; do
        if ! kill -0 "$client_pid" 2>/dev/null; then break; fi
        # Require a working loopback status listener before evaluating each source-selection state.
        if chronyc -h 127.0.0.1 -p 13230 -n -c sources >sources.log 2>&1; then
            selected=$(awk -F, '$2=="*" {print $3}' sources.log)
            if [ "$selected" = "$target" ]; then return 0; fi
        fi
        sleep 1
        tick=$((tick + 1))
    done
    cat client.log sources.log >&2
    exit 1
}
wait_for 127.0.0.1
echo preferred_reference_selected

kill "$primary_pid"
wait "$primary_pid" || true
primary_pid=
wait_for 127.0.0.2
echo alternate_reference_selected

kill "$secondary_pid"
wait "$secondary_pid" || true
secondary_pid=
wait_for ''
echo absent_reference_reported
