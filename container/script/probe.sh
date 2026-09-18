#!/usr/bin/env bash
__dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

export CURL_OPTS="-s -o /dev/null -w %{http_code}"
RESPONSE_HTTP_CODE=$(${__dir}/server_discover.sh)

case "${RESPONSE_HTTP_CODE}" in
    200|401)
        exit 0
        ;;
    *)
        exit 1
        ;;
esac