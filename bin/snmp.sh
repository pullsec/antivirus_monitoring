#!/usr/bin/env bash

# Centreon/Nagios SNMP entrypoint for NET-SNMP-EXTEND-MIB.
# The textual extend token is converted to its numeric OID index before querying output and return code.

set -euo pipefail


HOST="${1:?missing host}"
COMMUNITY="${2:?missing community}"
TOKEN="${3:?missing extend token}"

OID_OUTPUT_BASE=".1.3.6.1.4.1.8072.1.3.2.3.1.2"
OID_RESULT_BASE=".1.3.6.1.4.1.8072.1.3.2.3.1.4"

# Convert a textual Net-SNMP extend token to its numeric OID index suffix.
token_to_oid_suffix() {
  local s="$1"
  local len="${#s}"
  local out="$len"
  local i c
  for (( i=0; i<len; i++ )); do
    c=$(printf '%d' "'${s:i:1}")
    out="${out}.${c}"
  done
  printf '%s\n' "$out"
}

SUFFIX="$(token_to_oid_suffix "$TOKEN")"

OUTPUT="$(snmpget -v2c -c "$COMMUNITY" -t 10 -On "$HOST" "${OID_OUTPUT_BASE}.${SUFFIX}" -Oqv 2>/dev/null || true)"
RC="$(snmpget -v2c -c "$COMMUNITY" -t 10 -On "$HOST" "${OID_RESULT_BASE}.${SUFFIX}" -Oqv 2>/dev/null || true)"

if [[ -z "$OUTPUT" || -z "$RC" ]]; then
  echo "UNKNOWN: unable to read extend '$TOKEN' on $HOST"
  exit 3
fi

if [[ ! "$RC" =~ ^[0-3]$ ]]; then
  echo "UNKNOWN: invalid extend return code '$RC' for '$TOKEN' on $HOST"
  exit 3
fi

echo "$OUTPUT"
exit "$RC"
