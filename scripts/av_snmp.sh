#!/usr/bin/env bash

######################################
# Name: av_snmp.sh
# Description:
#   SNMP-based check script used to query a remote host
#   via NET-SNMP-EXTEND-MIB and retrieve antivirus status.
#
#   This script is executed from the Centreon poller and:
#     - queries the jump server via SNMP
#     - retrieves the output of a remote script (extend)
#     - retrieves the associated return code
#     - returns a Centreon/Nagios-compatible result
#
#   It relies on SNMP extend mechanism to trigger remote checks.
#
# Environment:
#   Tested on RedHat / Fedora systems
#
######################################

set -euo pipefail

######################################
# Input parameters
######################################

# Target host (jump server)
HOST="${1:?missing host}"

# SNMP community string
COMMUNITY="${2:?missing community}"

# SNMP extend token (identifier of the remote script)
TOKEN="${3:?missing extend token}"

######################################
# SNMP OIDs (NET-SNMP-EXTEND-MIB)
######################################

# Base OIDs for:
# - script output (full stdout)
# - script return code
#
# These must match the SNMP extend configuration
OID_OUTPUT_BASE=".1.3.6.1.4.1.XXXX.X.X.X.X.X.X"
OID_RESULT_BASE=".1.3.6.1.4.1.XXXX.X.X.X.X.X.Y"

######################################
# Convert token to SNMP OID suffix
######################################

# SNMP does not support textual indexes directly.
# The extend token must be converted to a numeric OID suffix:
#
# Example:
#   av_snmp → 8.99.104.101.99.107.95.97.118
#
# Format:
#   <length>.<ASCII codes...>

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

######################################
# SNMP queries
######################################

# Query script output (stdout)
OUTPUT="$(snmpget -v2c -c "$COMMUNITY" -On "$HOST" "${OID_OUTPUT_BASE}.${SUFFIX}" -Oqv 2>/dev/null || true)"

# Query script return code
RC="$(snmpget -v2c -c "$COMMUNITY" -On "$HOST" "${OID_RESULT_BASE}.${SUFFIX}" -Oqv 2>/dev/null || true)"

######################################
# Validation
######################################

# If either output or return code is missing,
# return UNKNOWN (SNMP failure or misconfiguration)
if [[ -z "$OUTPUT" || -z "$RC" ]]; then
  echo "UNKNOWN: unable to retrieve extend '$TOKEN' from $HOST"
  exit 3
fi

######################################
# Output handling
######################################

# Return message for Centreon display
echo "$OUTPUT"

######################################
# Exit code handling
######################################

# Centreon determines the service state from the exit code only
exit "$RC"
