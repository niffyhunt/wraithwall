#!/bin/bash
set -e

# If mitmproxy CA is available and HTTP_PROXY is set, configure the sandbox
# to route all traffic through the mitmproxy sidecar for egress control.
if [ -n "$HTTP_PROXY" ] && [ -f /usr/local/share/ca-certificates/mitm-ca.crt ]; then
    export HTTPS_PROXY="$HTTP_PROXY"
    export HTTP_PROXY="$HTTP_PROXY"
    export NO_PROXY="localhost,127.0.0.1"
    export CURL_CA_BUNDLE=/usr/local/share/ca-certificates/mitm-ca.crt
    export REQUESTS_CA_BUNDLE=/usr/local/share/ca-certificates/mitm-ca.crt
    export NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/mitm-ca.crt
fi

python3 /sandbox/detonate.py "$@"
