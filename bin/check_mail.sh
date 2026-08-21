#!/usr/bin/env bash

# Centreon/Nagios plugin that validates the health and freshness of the last mail report.
# Exit codes follow the standard monitoring convention: 0=OK, 1=WARNING, 2=CRITICAL, 3=UNKNOWN.

OK=0
WARNING=1
CRITICAL=2
UNKNOWN=3

STATUS_FILE="/path/to/tmp/mail.state"

MAX_AGE_HOURS=24

if [[ ! -f "$STATUS_FILE" ]]; then
  echo "CRITICAL - status file not found: $STATUS_FILE"
  exit "$CRITICAL"
fi

LAST_RUN="$(sed -n 's/^LAST_RUN="\(.*\)"$/\1/p' "$STATUS_FILE" | head -1)"
LAST_STATUS="$(sed -n 's/^LAST_STATUS="\(.*\)"$/\1/p' "$STATUS_FILE" | head -1)"
LAST_RC="$(sed -n 's/^LAST_RC="\(.*\)"$/\1/p' "$STATUS_FILE" | head -1)"
LAST_MESSAGE="$(sed -n 's/^LAST_MESSAGE="\(.*\)"$/\1/p' "$STATUS_FILE" | head -1)"

if [[ -z "${LAST_RUN:-}" || -z "${LAST_STATUS:-}" || -z "${LAST_RC:-}" ]]; then
  echo "UNKNOWN - invalid status file"
  exit "$UNKNOWN"
fi

LAST_RUN_TS=$(date -d "$LAST_RUN" +%s 2>/dev/null)
NOW_TS=$(date +%s)

if [[ -z "$LAST_RUN_TS" ]]; then
  echo "UNKNOWN - invalid LAST_RUN date: $LAST_RUN"
  exit "$UNKNOWN"
fi

AGE_HOURS=$(( (NOW_TS - LAST_RUN_TS) / 3600 ))

if (( AGE_HOURS > MAX_AGE_HOURS )); then
  echo "CRITICAL - last report too old: ${AGE_HOURS}h, last_run=${LAST_RUN}"
  exit "$CRITICAL"
fi

if [[ "$LAST_STATUS" != "OK" ]]; then
  echo "CRITICAL - last mail failed, rc=${LAST_RC}, last_run=${LAST_RUN}, message=${LAST_MESSAGE:-N/A}"
  exit "$CRITICAL"
fi

echo "OK - last mail sent successfully, last_run=${LAST_RUN}, age=${AGE_HOURS}h"
exit "$OK"
