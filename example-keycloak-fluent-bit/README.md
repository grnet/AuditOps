# Keycloak Fluent Bit example

Example Fluent Bit pipeline for collecting Keycloak events and
mapping them to the Accounting/Auditing event model.

## Requirements

- Keycloak 26 or later
- Fluent Bit 2.x or later
- Keycloak running as a systemd service
- Keycloak console logging configured as ECS JSON
- `jboss-logging` enabled as an event listener for the relevant realms

Successful Keycloak events must be logged at `INFO` level.

Example Keycloak configuration:

```properties
log=console,file
log-console-output=json
log-console-json-format=ecs

spi-events-listener--jboss-logging--success-level=info
spi-events-listener--jboss-logging--error-level=warn
```

## Files

- `etc/fluent-bit/fluent-bit.conf` — Fluent Bit input, filtering and output configuration.
- `etc/fluent-bit/parsers.conf` — parser for Keycloak ECS JSON records.
- `etc/fluent-bit/keycloak-audit.lua` — mapping from Keycloak events to the Accounting/Auditing event model.

## Configuration

### Subject identifier

For brokered users, the pipeline uses the Keycloak `username` as the
accounting `subject`.

The Keycloak Identity Provider configuration should therefore map the
upstream `voperson_id` claim to the Keycloak `username`.

### Identity Provider protocols

Keycloak broker events contain the Identity Provider alias but do not
include its protocol. Configure the protocol for each broker alias in
`keycloak-audit.lua`:

```lua
local IDP_ALIAS_PROTOCOL = {
    ["example-oidc"] = "oidc",
    ["example-saml"] = "saml",
}
```

An unknown broker protocol is reported as `unknown_to_oidc` or
`unknown_to_saml` when the downstream protocol can be determined.

### Source

The default accounting event source is:

```lua
local SOURCE = "keycloak"
```

It can be changed when different Keycloak services need distinct source
identifiers.

## Testing

The example configuration sends processed records to `stdout`:

```bash
fluent-bit -c /etc/fluent-bit/fluent-bit.conf
```

After validation, replace or disable the `stdout` output and enable the
OpenSearch output configuration.

The original Keycloak log can optionally be retained as `raw_log` for
debugging. It may contain sensitive identifiers and should normally be
disabled in production.

## Example output

The following example shows a brokered Keycloak OIDC login after mapping to the
Accounting/Auditing event model.

```json
{
  "timestamp": "2026-10-05T00:03:41.517Z",
  "source": "keycloak",
  "subject": "0123456789abcdef@community.example.org",
  "object": "example-client",
  "operation": "LOGIN",
  "outcome": "success",
  "origin_system": "example-oidc-idp",
  "destination_system": "example-client",
  "connection_protocol": "oidc_to_oidc",
  "ip_address": "192.0.2.10",
  "correlation_id": "example-session-id",
  "context": {
    "client_id": "example-client",
    "response_type": "code",
    "response_mode": "query",
    "redirect_uri": "https://service.example.org/callback",
    "subject_info": {
      "keycloak_user_id": "00000000-0000-0000-0000-000000000000",
      "keycloak_username": "0123456789abcdef@community.example.org",
      "identity_provider_identity": "example-user"
    },
    "origin_system_info": {
      "broker_session_id": "example-oidc-idp.example-session"
    },
    "keycloak": {
      "event_sequence": 1234,
      "realm_id": "00000000-0000-0000-0000-000000000001",
      "realm_name": "example-realm",
      "auth_session_parent_id": "example-session-id",
      "auth_session_tab_id": "example-tab-id",
      "host": "keycloak.example.org",
      "version": "26.7.1",
      "environment": "prod"
    }
  }
}
```
