#!/usr/bin/env bash
# Smoke test: run the agent binary behind a real Zentinel (fail-closed) with
# the shared harness from zentinelproxy/.github (agent-smoke/smoke.py).
#
#   AGENT_SMOKE=<path to smoke.py> scripts/smoke-test.sh [<agent-binary> <zentinel-binary>]
#
# The binaries default to $AGENT_BIN and $ZENTINEL_BIN, which the shared
# release workflow sets. Run by that workflow on every platform before any
# asset is published, and by CI on every push and pull request.
#
# With the default configuration (no config file), over the Unix socket and
# over gRPC, the agent subscribed to request headers and bodies:
#   * the v2 handshake works and a GET is forwarded (200);
#   * a POST that is not SOAP (application/json) is forwarded untouched;
#   * with the agent stopped the clean request is refused (agent on the path).
#
# With SOAP_SMOKE_BODIES=1 it also sends envelopes:
#   * a valid SOAP 1.1 envelope (with its SOAPAction) is forwarded;
#   * a malformed envelope and one with a DOCTYPE (XXE) get the agent's SOAP
#     Fault (500, as the SOAP HTTP binding requires).
# They are off by default because no Zentinel passes them today:
#   * releases up to 26.10_7 send request bodies to agents only when the
#     config has a `waf` block (fixed on main by zentinelproxy/zentinel#609),
#     which the harness does not write, so the envelopes are never checked;
#   * main (3bcfe23) checks them and answers the Fault, but has already sent
#     the request headers to the upstream (only the body is held back), and
#     the harness counts that as the blocked request reaching the upstream.
# Turn them on here once a Zentinel release passes them.

set -euo pipefail

AGENT_BIN=${1:-${AGENT_BIN:?usage: smoke-test.sh <agent-binary> <zentinel-binary>}}
ZENTINEL_BIN=${2:-${ZENTINEL_BIN:?usage: smoke-test.sh <agent-binary> <zentinel-binary>}}
AGENT_SMOKE=${AGENT_SMOKE:?set AGENT_SMOKE to agent-smoke/smoke.py from zentinelproxy/.github}

valid='<?xml version=\"1.0\"?><soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><GetUser xmlns=\"http://example.org/users\"><id>1</id></GetUser></soap:Body></soap:Envelope>'
xxe='<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><GetUser>&xxe;</GetUser></soap:Body></soap:Envelope>'

cases=(
    --clean '{"name": "GET", "path": "/smoke"}'
    --case '{"name": "non-SOAP POST", "method": "POST", "path": "/smoke", "headers": {"Content-Type": "application/json"}, "body": "{\"a\": 1}", "expect": 200}'
)
if [[ ${SOAP_SMOKE_BODIES:-0} == 1 ]]; then
    cases+=(
        --case "{\"name\": \"valid SOAP envelope\", \"method\": \"POST\", \"path\": \"/soap\", \"headers\": {\"Content-Type\": \"text/xml; charset=utf-8\", \"SOAPAction\": \"\\\"GetUser\\\"\"}, \"body\": \"$valid\", \"expect\": 200}"
        --case '{"name": "malformed envelope", "method": "POST", "path": "/soap", "headers": {"Content-Type": "text/xml"}, "body": "<soap:Envelope><broken", "expect": 500}'
        --case "{\"name\": \"XXE (DOCTYPE)\", \"method\": \"POST\", \"path\": \"/soap\", \"headers\": {\"Content-Type\": \"text/xml\"}, \"body\": \"$xxe\", \"expect\": 500}"
    )
fi

for transport in uds grpc; do
    echo "=== soap agent over $transport"
    python3 "$AGENT_SMOKE" --agent "$AGENT_BIN" --zentinel "$ZENTINEL_BIN" \
        --name soap --transport "$transport" \
        --events request_headers,request_body \
        "${cases[@]}"
done
