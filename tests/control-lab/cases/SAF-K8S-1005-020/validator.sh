#!/bin/sh
set -eu

# Read a single fictional record set and compare closure with and without checks.
awk -F ' *[|] *' '
  /^#/ || NF == 0 { next }
  NF != 5 || $1 !~ /^[a-z-]+$/ || seen[$1]++ {
    print "INVALID|malformed-fixture"
    exit 2
  }
  {
    bypass = $5 == "-" ? "open" : "approved_closure"
    if ($2 == "-") enforced = "missing_owner"
    else if ($3 == "-") enforced = "missing_escalation"
    else if ($4 == "-") enforced = "unacknowledged_handoff"
    else enforced = bypass
    printf "OBSERVATION|bypass|%s|%s\n", $1, bypass
    printf "OBSERVATION|enforced|%s|%s\n", $1, enforced
  }
' "$1"
