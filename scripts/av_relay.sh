#!/usr/bin/env bash

######################################
# Name: av_relay.sh
# Description:
#   SSH wrapper used to execute the antivirus supervision script
#   on a remote AV server.
#
#   This script acts as a relay between the monitoring system
#   (Centreon via SNMP) and the AV server where the actual checks
#   are performed.
#
#   It ensures:
#     - secure remote execution over SSH
#     - proper handling of stdout/stderr
#     - compliance with Centreon/Nagios return codes
#
# Environment:
#   Tested on RedHat / CentOS systems
#
######################################

set -euo pipefail

# Target AV server (can be parameterized if needed)
# TARGET="${1:?missing target host}"
TARGET="server"

# Remote script path executed on the AV server
REMOTE_SCRIPT="/path/on/av_supervision.sh"

######################################
# Remote execution
######################################

# Disable strict mode temporarily to capture exit code manually
set +e

# Execute remote supervision script via SSH
# - BatchMode: disables password prompts (required for automation)
# - ConnectTimeout: avoids hanging connections
# - stderr is redirected to stdout to ensure full output capture
OUTPUT="$(ssh -o BatchMode=yes -o ConnectTimeout=10 "$TARGET" "$REMOTE_SCRIPT" 2>&1)"

# Capture exit code from remote execution
RC=$?

# Re-enable strict mode
set -e

######################################
# Output handling
######################################

# Return output to Centreon (used for display only)
echo "$OUTPUT"

######################################
# Exit code handling
######################################

# Only standard Centreon/Nagios return codes are allowed:
#   0 = OK
#   1 = WARNING
#   2 = CRITICAL
#   3 = UNKNOWN
#
# Any unexpected value (e.g. SSH failure) is mapped to UNKNOWN

case "$RC" in
  0|1|2|3)
    exit "$RC"
    ;;
  *)
    echo "UNKNOWN: SSH execution failed on $TARGET"
    exit 3
    ;;
esac
