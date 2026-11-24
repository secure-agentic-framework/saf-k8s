#!/bin/sh
set -eu
umask 077
b=/bin/busybox
here=/fixture
probe=/bin/saf-record
work=$("$b" mktemp -d)
trap '"$b" rm -rf "$work"' EXIT HUP INT TERM

observe() {
    label=$1
    operation=$2
    if ! "$probe" observe "$operation" >"$work/$label.events" 2>"$work/$label.err"; then
        "$b" cat "$work/$label.err" >&2
        echo "SAF-SECCOMP-COVERAGE: user-notification collection was unavailable in this case process; require Linux 5.5+, seccomp filter support, and SECCOMP_RET_USER_NOTIF" >&2
        exit 2
    fi
    test "$("$b" wc -l <"$work/$label.events" | "$b" tr -d ' ')" -eq 1
    "$b" grep -Fxq "OBSERVED $operation" "$work/$label.events"
}

derive() {
    output=$1
    shift
    "$b" cat "$@" | "$b" sed -n 's/^OBSERVED //p' | "$b" sort -u >"$work/observed"
    while IFS= read -r operation; do
        if "$b" grep -Fxq "$operation" "$here/seccomp-approved.txt"; then
            printf '%s\n' "$operation"
        fi
    done <"$work/observed" >"$output"
}

observe startup getpid
observe incidental getppid
"$b" cat "$work/startup.events" "$work/incidental.events" | "$b" sed -n 's/^OBSERVED //p' | "$b" sort -u >"$work/first-observed"
derive "$work/initial.rules" "$work/startup.events" "$work/incidental.events"
"$b" grep -Fxq getpid "$work/first-observed"
"$b" grep -Fxq getppid "$work/first-observed"
"$b" grep -Fxq getpid "$work/initial.rules"
if "$b" grep -Fxq getppid "$work/initial.rules" || "$b" grep -Fxq getuid "$work/initial.rules"; then exit 1; fi
echo 'SAF-SECCOMP: first capture observed getpid and incidental getppid; approval retained getpid only'

if ! "$probe" enforce "$work/initial.rules" initial; then
    echo 'SAF-SECCOMP: initial enforcement matrix failed' >&2
    exit 1
fi
echo 'SAF-SECCOMP: initial policy allowed getpid and denied getppid and unobserved recovery getuid'

observe recovery getuid
derive "$work/final.rules" "$work/startup.events" "$work/incidental.events" "$work/recovery.events"
"$b" grep -Fxq getpid "$work/final.rules"
"$b" grep -Fxq getuid "$work/final.rules"
if "$b" grep -Fxq getppid "$work/final.rules"; then exit 1; fi
if ! "$probe" enforce "$work/final.rules" expanded; then
    echo 'SAF-SECCOMP: final enforcement matrix failed' >&2
    exit 1
fi
echo 'SAF-SECCOMP: exercised recovery added approved getuid; final policy allowed getpid and getuid and denied incidental getppid'

"$probe" rollback | "$b" grep -Fxq 'ROLLBACK fresh process is unrestricted'
echo 'SAF-SECCOMP: rollback discarded the filtered process and verified a fresh unfiltered fixture process'
printf 'SAF-SECCOMP-POLICIES: %s %s\n' \
    "$("$b" sha256sum "$work/initial.rules" | "$b" cut -d' ' -f1)" \
    "$("$b" sha256sum "$work/final.rules" | "$b" cut -d' ' -f1)"
