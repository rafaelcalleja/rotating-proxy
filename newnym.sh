#!/bin/bash

set -x

CONTROLPORT=$1
HEALTHCHECK_URL="http://127.0.0.1:$((CONTROLPORT + 10000))"

if [[ "$NEWNYM_ON_HEALTHCHECK" == "true" || "$NEWNYM_ON_HEALTHCHECK" == "1" ]]; then
  response=$(timeout "${HEALTHCHECK_TIMEOUT:-10}" curl -s -o /dev/null -w "%{http_code}" "${HEALTHCHECK_URL}")
  if [[ -n "$response" && $response -eq 200 ]]; then
    echo "healthcheck is ok, skipping newnym ${CONTROLPORT}"
    exit 0
  fi
fi


cat <<'EOF' | nc localhost $CONTROLPORT
authenticate ""
signal newnym
quit
EOF
