#!/usr/bin/env bash

# Centreon/Nagios plugin that reads a mail-reporting check exposed through Net-SNMP extend.

OK=0
WARNING=1
CRITICAL=2
UNKNOWN=3

if [[ $# -lt 3 ]]; then
  echo "UNKNOWN - usage: $0 <IP_BASTION> <COMMUNITY> <EXTEND_NAME>"
  exit "$UNKNOWN"
fi

HOST="$1"
COMMUNITY="$2"
EXTEND_NAME="$3"

SNMP_TIMEOUT=10

OUTPUT=$(
  snmpget -v2c -c "$COMMUNITY" -t "$SNMP_TIMEOUT" -r 1 \
  "$HOST" "NET-SNMP-EXTEND-MIB::nsExtendOutputFull.\"${EXTEND_NAME}\"" \
  2>/dev/null
)

RC=$?

if [[ $RC -ne 0 || -z "$OUTPUT" ]]; then
  echo "UNKNOWN - unable to read SNMP extend ${EXTEND_NAME} on ${HOST}"
  exit "$UNKNOWN"
fi

MESSAGE=$(echo "$OUTPUT" | sed 's/^.*STRING: //; s/^"//; s/"$//')

if [[ -z "$MESSAGE" ]]; then
  echo "UNKNOWN - empty SNMP extend output for ${EXTEND_NAME}"
  exit "$UNKNOWN"
fi

case "$MESSAGE" in
  OK*)
    echo "$MESSAGE"
    exit "$OK"
    ;;
  WARNING*)
    echo "$MESSAGE"
    exit "$WARNING"
    ;;
  CRITICAL*)
    echo "$MESSAGE"
    exit "$CRITICAL"
    ;;
  UNKNOWN*)
    echo "$MESSAGE"
    exit "$UNKNOWN"
    ;;
  *)
    echo "UNKNOWN - invalid extend output: $MESSAGE"
    exit "$UNKNOWN"
    ;;
esac
