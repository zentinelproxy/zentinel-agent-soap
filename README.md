<p align="center">
  <a href="https://zentinelproxy.io">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-dark.svg">
      <img alt="Zentinel" src="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-light.svg" height="52">
    </picture>
  </a>
</p>

<h3 align="center">SOAP agent</h3>

<p align="center">Checks SOAP request bodies for XXE patterns, envelope structure, allowed operations, WS-Security headers and size limits before they reach the service.</p>

<p align="center">
  <a href="https://github.com/zentinelproxy/zentinel-agent-soap/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/zentinelproxy/zentinel-agent-soap/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="Agent protocol: v2" src="https://img.shields.io/badge/agent%20protocol-v2-f68d31?style=flat&labelColor=1f161e">
</p>

<p align="center">
  <a href="https://registry.zentinelproxy.io/soap/">Registry</a> &middot;
  <a href="https://docs.zentinelproxy.io">Docs</a> &middot;
  <a href="https://github.com/zentinelproxy">All repositories</a>
</p>

For SOAP services behind Zentinel. Requests whose `Content-Type` matches
`settings.allowed_content_types` are held until the body arrives; the agent
then rejects any `DOCTYPE`, `ENTITY` or `SYSTEM`/`PUBLIC` declaration,
parses the envelope and runs the enabled checks. A violation is answered with
a `500` and a SOAP 1.1 or 1.2 Fault listing each violation code; with
`settings.fail_action: allow` it is logged and the request passes. Requests
with any other content type pass unchecked. If the agent is unreachable, the
filter's `failure-mode` decides.

## Quick start

```bash
zentinel bundle install soap

cat > soap.yaml <<'EOF'
operations:
  enabled: true
  mode: allowlist
  actions: ["GetUser", "List*"]
EOF

zentinel-soap-agent --config soap.yaml --grpc-address 127.0.0.1:50051
```

The agent speaks gRPC only. Zentinel sends request bodies to agents only when
the top-level `waf { body-inspection { inspect-request-body #true } }` is set,
so the config needs that block (with `mode "off"` it enables nothing else):

```kdl
system {
    worker-threads 0
}

listeners {
    listener "http" {
        address "127.0.0.1:8080"
        protocol "http"
    }
}

waf {
    mode "off"
    body-inspection {
        inspect-request-body #true
        max-inspection-bytes 1048576
        content-types "text/xml" "application/soap+xml"
    }
}

agents {
    agent "soap" type="custom" {
        grpc "http://127.0.0.1:50051"
        events "request_headers" "request_body"
        timeout-ms 200
        request-body-mode "buffer"
    }
}

filters {
    filter "soap" {
        type "agent"
        agent "soap"
        failure-mode "closed"
    }
}

routes {
    route "default" {
        matches {
            path-prefix "/"
        }
        upstream "backend"
        filters "soap"
    }
}

upstreams {
    upstream "backend" {
        target "127.0.0.1:3000"
    }
}
```

`request-body-mode "buffer"` matters: the agent parses each body chunk on its
own, so a streamed multi-chunk body would fail to parse.

## Install

```bash
zentinel bundle install soap
```

Or from the repository (the crate is not on crates.io):

```bash
cargo install --git https://github.com/zentinelproxy/zentinel-agent-soap
```

Release binaries (`zentinel-soap-agent-<version>-<platform>.tar.gz`) for
`linux-x86_64`, `linux-aarch64` and `darwin-aarch64` are on the
[releases page](https://github.com/zentinelproxy/zentinel-agent-soap/releases).
From source: `cargo build --release`.

## Configuration

| Option | Default | Meaning |
|---|---|---|
| `--config`, `-c` | `config.yaml` | YAML file; if it does not exist, the defaults below apply |
| `--grpc-address` | none, required | gRPC listen address, e.g. `127.0.0.1:50051` |
| `--socket`, `-s` | `/tmp/zentinel-soap.sock` | Not implemented: without `--grpc-address` the agent exits with an error |
| `--log-level`, `-l` | `info` | Log level |

The file is read once at startup. The proxy does not forward an agent block's
`config { }` to the agent, so use the file.

| Key | Default | Meaning |
|---|---|---|
| `settings.max_body_size` | `1048576` | Larger bodies are a violation |
| `settings.fail_action` | `block` | `block` or `allow` (log only) |
| `settings.allowed_content_types` | `text/xml`, `application/soap+xml`, `application/xml` | Substring match on `Content-Type`; other requests pass unchecked |
| `settings.debug_headers` | `false` | `X-SOAP-*` metric headers on the response (see Limitations) |
| `envelope.enabled` | `true` | Envelope checks below |
| `envelope.allowed_versions` | `["1.1", "1.2"]` | SOAP versions accepted |
| `envelope.require_header` | `false` | Require a `soap:Header` |
| `envelope.max_body_depth` | `20` | Maximum element nesting in the body |
| `body_validation.enabled` | `true` | Body checks below |
| `body_validation.max_elements` | `1000` | Maximum elements in the body |
| `body_validation.max_text_length` | `65536` | Maximum text length per element |
| `body_validation.block_cdata`, `block_comments` | `false` | Reject CDATA sections / comments |
| `body_validation.required_namespaces` | `[]` | The body must declare at least one of these namespaces |
| `operations.enabled` | `false` | Operation control below |
| `operations.mode` | `allowlist` | `allowlist` or `denylist` |
| `operations.actions` | `[]` | Glob patterns matched against the operation (first element in the body, else the `SOAPAction` header) |
| `ws_security.enabled` | `false` | WS-Security checks below |
| `ws_security.require_security_header` | `false` | Require `wsse:Security` |
| `ws_security.require_timestamp` | `false` | Require `wsu:Timestamp`; a `Created` older than `max_timestamp_age_secs` (`300`) or a past `Expires` is rejected |
| `ws_security.require_username_token` | `false` | Require a `UsernameToken`; a password type not in `allowed_password_types` (`[PasswordDigest]`) is rejected |
| `ws_security.require_saml` | `false` | Require a SAML assertion |

WS-Security checks are structural: the agent checks that the elements are
present and well-formed, and does not verify signatures, digests or
passwords.

## Limitations

- XXE checks always run; `xxe_prevention.*` (including `enabled`,
  `max_entity_expansions`) and `envelope.require_valid_envelope` are read but
  change nothing, and processing instructions are not checked.
- `operations.require_soap_action_header` blocks **every** request and
  `operations.validate_action_match` never runs: the `SOAPAction` header is
  not available in the body phase where the checks happen. Leave both off.
- `operations.rate_limits` is not implemented.
- The `X-SOAP-Validated`, `X-SOAP-Operation` and `ws_security.identity_header`
  request headers and the debug response headers are set from the body phase,
  which Zentinel 0.6.50 does not apply, so they do not reach the service or
  the client.

## Development

```bash
cargo test
cargo clippy --all-targets -- -D warnings
```

## Related

- [Registry page](https://registry.zentinelproxy.io/soap/)
- [Agent configuration](https://docs.zentinelproxy.io/configuration/agents/)
- [Agent protocol v2](https://docs.zentinelproxy.io/agents/v2/)
- [Zentinel](https://github.com/zentinelproxy/zentinel)

## License

Apache-2.0, as declared in `Cargo.toml`. The repository has no `LICENSE` file yet.

---

<p align="center">
  <sub>Part of <a href="https://zentinelproxy.io">Zentinel</a>, the security-first reverse proxy. The shisa guards the gate.</sub>
</p>
