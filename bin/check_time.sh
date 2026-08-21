#!/bin/bash

# Diagnostic helper that measures the remote execution time of the antivirus supervision plugin.

SERVERS=(
    server1
    server2
    server3
)

for srv in "${SERVERS[@]}"; do
echo "$srv":
	time ssh \
		-o BatchMode=yes \
		-o ConnectTimeout=15 \
		"$srv" \
		"/path/to/the/av_supervision.sh" >/dev/null 2>&1
	echo
done
