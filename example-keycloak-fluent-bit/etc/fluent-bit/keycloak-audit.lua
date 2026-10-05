--
-- Keycloak -> Accounting/Auditing mapping for Fluent Bit.
--
-- Input:
--   ECS JSON emitted by Keycloak's jboss-logging event listener and read
--   from the systemd journal.
--
-- Subject:
--   For brokered users, configure Keycloak so that "username" contains the
--   upstream voperson_id. Events without username use best-effort in-memory
--   lookup by sessionId and then userId.
--
-- Protocol:
--   - Brokered LOGIN: <upstream>_to_<downstream>
--   - Unknown IdP alias: unknown_to_<downstream>
--   - Local interactive login: oidc or saml
--   - OIDC authorization-code token exchange: oidc
--   - Other OAuth2 grants: oauth2
--   - Insufficient protocol information: unknown
--

-- Identifier of the system/component generating the Accounting/Auditing events.
-- Override it when separate Keycloak services need distinct source identifiers.
local SOURCE = "keycloak"

-- Retain the original ECS JSON only when troubleshooting.
-- Raw logs may contain sensitive identifiers.
local INCLUDE_RAW_LOG = false

-- Map Keycloak Identity Provider aliases to their upstream protocol.
-- Keycloak broker events expose the alias but not the provider protocol.
local IDP_ALIAS_PROTOCOL = {
    -- ["my-oidc-idp"] = "oidc",
    -- ["my-saml-idp"] = "saml",
}

-- Optional fallback for events that contain clientId but no protocol hint.
local CLIENT_ID_PROTOCOL = {
    -- ["my-oidc-client"] = "oidc",
    -- ["my-saml-sp"] = "saml",
}

local SESSION_SUBJECT = {}
local USER_SUBJECT = {}

local function clean(value)
    if value == nil or value == "" or value == "null" then
        return nil
    end
    return value
end

local function parse_message(message)
    local fields = {}
    if message == nil then
        return fields
    end

    for key, value in string.gmatch(message, '([%w_]+)="([^"]*)"') do
        fields[key] = value
    end
    return fields
end

-- Normalise timestamps to UTC millisecond precision.
local function timestamp_ms(value)
    if value == nil then
        return nil
    end

    local base, fraction =
        string.match(value,
            "^(%d%d%d%d%-%d%d%-%d%dT%d%d:%d%d:%d%d)%.(%d+)Z$")

    if base ~= nil then
        fraction = string.sub(fraction .. "000", 1, 3)
        return base .. "." .. fraction .. "Z"
    end

    base = string.match(value,
        "^(%d%d%d%d%-%d%d%-%d%dT%d%d:%d%d:%d%d)Z$")
    if base ~= nil then
        return base .. ".000Z"
    end

    return value
end

-- Check whether an OAuth/OIDC scope is present.
local function scope_contains(scope, value)
    scope = clean(scope)
    if scope == nil then
        return false
    end

    return string.find(
        " " .. scope .. " ",
        " " .. value .. " ",
        1,
        true
    ) ~= nil
end

-- Infer the client-facing protocol from event fields.
local function infer_downstream_protocol(k)
    local auth_method = clean(k["auth_method"])

    if auth_method == "openid-connect" then
        return "oidc"
    end

    if auth_method == "saml" then
        return "saml"
    end

    -- Brokered OIDC LOGIN events can omit auth_method but include response_type.
    if clean(k["response_type"]) ~= nil then
        return "oidc"
    end

    return CLIENT_ID_PROTOCOL[clean(k["clientId"])]
end

-- Derive the Accounting/Auditing connection_protocol value.
local function infer_connection_protocol(k)
    local operation = clean(k["type"]) or clean(k["operationType"])
    local grant = clean(k["grant_type"])

    -- UserInfo is an OpenID Connect endpoint.
    if operation == "USER_INFO_REQUEST"
       and k["auth_method"] == "validate_access_token" then
        return "oidc"
    end

    -- Authorization-code exchange is OIDC when openid is in scope.
    if grant == "authorization_code" then
        if scope_contains(k["scope"], "openid") then
            return "oidc"
        end
        return "oauth2"
    end

    -- Other token grants are classified as OAuth2.
    if grant ~= nil then
        return "oauth2"
    end

    local downstream = infer_downstream_protocol(k)
    local idp_alias = clean(k["identity_provider"])

    if idp_alias ~= nil then
        if downstream == nil then
            return "unknown"
        end

        local upstream = IDP_ALIAS_PROTOCOL[idp_alias] or "unknown"
        return upstream .. "_to_" .. downstream
    end

    if downstream ~= nil then
        return downstream
    end

    return "unknown"
end

-- Resolve the Accounting/Auditing subject from username or cached identifiers.
local function resolve_subject(k)
    local username = clean(k["username"])
    local user_id = clean(k["userId"])
    local user_session_id = clean(k["sessionId"])
    local auth_session_parent_id = clean(k["authSessionParentId"])

    if username ~= nil then
        if user_session_id ~= nil then
            SESSION_SUBJECT[user_session_id] = username
        end
        if auth_session_parent_id ~= nil then
            SESSION_SUBJECT[auth_session_parent_id] = username
        end
        if user_id ~= nil then
            USER_SUBJECT[user_id] = username
        end
        return username
    end

    if user_session_id ~= nil
       and SESSION_SUBJECT[user_session_id] ~= nil then
        return SESSION_SUBJECT[user_session_id]
    end

    if auth_session_parent_id ~= nil
       and SESSION_SUBJECT[auth_session_parent_id] ~= nil then
        return SESSION_SUBJECT[auth_session_parent_id]
    end

    if user_id ~= nil and USER_SUBJECT[user_id] ~= nil then
        return USER_SUBJECT[user_id]
    end

    return "UNKNOWN"
end

function map_event(tag, timestamp, record)

    -- Only Keycloak audit/event records are mapped.
    local logger = record["log.logger"] or record["loggerName"]
    if logger ~= "org.keycloak.events" then
        return -1, timestamp, record
    end

    local k = parse_message(record["message"])

    local operation =
        clean(k["type"]) or clean(k["operationType"]) or "UNKNOWN"

    local realm = clean(k["realmName"])
    local client = clean(k["clientId"])
    local user_id = clean(k["userId"])
    local session_id = clean(k["sessionId"])

    local source = SOURCE

    local subject = resolve_subject(k)

    -- Use the affected client as the object by default; for session deletion
    -- use the session ID, and for admin events use the affected resource path.
    local object = client
    if operation == "USER_SESSION_DELETED" then
        object = clean(k["sessionId"])
    elseif clean(k["operationType"]) ~= nil
       and clean(k["resourcePath"]) ~= nil then
        object = k["resourcePath"]
    end

    -- Keycloak uses event types ending in "_ERROR" for failed operations;
    -- the presence of an error field also indicates failure.
    local outcome = "success"
    if string.match(operation, "_ERROR$") ~= nil
       or clean(k["error"]) ~= nil then
        outcome = "failure"
    end

    local reason = clean(k["reason"]) or clean(k["error"])

    -- For brokered authentication the IdP alias is the origin.
    local idp_alias = clean(k["identity_provider"])
    local origin_system = idp_alias or source

    local subject_info = {
        keycloak_user_id = user_id,
        keycloak_username = clean(k["username"]),
        identity_provider_identity =
            clean(k["identity_provider_identity"])
    }

    local context = {
        client_id = client,
        grant_type = clean(k["grant_type"]),
        scope = clean(k["scope"]),
        auth_method = clean(k["auth_method"]),
        auth_type = clean(k["auth_type"]),
        client_auth_method = clean(k["client_auth_method"]),
        response_type = clean(k["response_type"]),
        response_mode = clean(k["response_mode"]),
        redirect_uri = clean(k["redirect_uri"]),

        resource_type = clean(k["resourceType"]),
        resource_path = clean(k["resourcePath"]),

        -- Keycloak-specific event and deployment metadata.
        keycloak = {
            event_sequence = record["event.sequence"],
            realm_id = clean(k["realmId"]),
            realm_name = realm,
            auth_session_parent_id = clean(k["authSessionParentId"]),
            auth_session_tab_id = clean(k["authSessionTabId"]),
            host = record["host.hostname"],
            version = record["service.version"],
            environment = record["service.environment"]
        },

        error = clean(k["error"])
    }

    -- Add subject context only when at least one identifier is available.
    if next(subject_info) ~= nil then
        context["subject_info"] = subject_info
    end

    -- Add broker-specific origin context only when available.
    local broker_session_id =
        clean(k["identity_provider_broker_session_id"])
    if broker_session_id ~= nil then
        context["origin_system_info"] = {
            broker_session_id = broker_session_id
        }
    end

    local out = {
        timestamp =
            timestamp_ms(record["@timestamp"] or record["timestamp"]),

        source = source,
        subject = subject,
        object = object,
        operation = operation,
        outcome = outcome,
        reason = reason,

        origin_system = origin_system,
        destination_system = client,
        connection_protocol = infer_connection_protocol(k),

        ip_address = clean(k["ipAddress"]),

        -- Use the Keycloak user session ID to correlate events from the same session.
        -- This is Keycloak source-local and is not a cross-system correlation identifier.
        correlation_id = session_id,

        context = context
    }

    if INCLUDE_RAW_LOG then
        out["raw_log"] = record["MESSAGE"] or record["log"]
    end

    return 2, timestamp, out
end
