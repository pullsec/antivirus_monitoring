#!/usr/bin/env bash

# Diagnostic helper that runs the antivirus supervision plugin remotely and prints each return code.

SERVERS=(
    server1
    server2
    server3
)

for srv in "${SERVERS[@]}"; do


  ssh -o BatchMode=yes -o ConnectTimeout=15 "$srv" "/path/to/the/file/av_supervision.sh" >/dev/null 2>&1
  rc=$?

  case $rc in
      0)
	 echo "$srv : OK RC=$rc"
	 ;;
      1)
	 echo "$srv : WARNING RC=$rc"
	 ;;
      2)
	 echo "$srv : CRITICAL RC=$rc"
	 ;;
      3)
	 echo "$srv : UNKNOWN RC=$rc"
	 ;;
      *)
         echo "$srv : TECHNICAL_ERROR RC=$rc"
         ;;
   esac
done
