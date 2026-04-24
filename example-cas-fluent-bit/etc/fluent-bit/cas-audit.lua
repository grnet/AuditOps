local function parse_required_attributes(str)
    local result = {}
    -- Handle "key":["val1","val2"] array values
    for key, value in str:gmatch('"([^"]+)"%s*:%s*(%b[])') do
        local items = {}
        for item in value:gmatch('"([^"]+)"') do
            items[#items + 1] = item
        end
        result[key] = items
    end
    -- Handle "key":"string_value" scalar values
    for key, value in str:gmatch('"([^"]+)"%s*:%s*"([^"]+)"') do
        if result[key] == nil then
            result[key] = value
        end
    end
    return result
end

function parse_audit(tag, timestamp, record)
    local log = record["log"]

    -- skip if no log file is present
    if log == nil then return -1, timestamp, record end

    -- strip } character if present at the beginning of log line
    log = log:gsub("^}", "")

    -- Drop any lines that are not audit. Audit lines begin with: Audit trail record BEGIN
    if not log:find("Audit trail record BEGIN") then
        return -1, timestamp, record
    end

    -- Strip any ANSI escape sequences that might be emitted into logs
    log = log:gsub("\27%[[%d;]*[A-Za-z]", "")

    -- Grab session_id from header which should match at least 8 HEX characters
    local session_id = log:match("%[([A-F0-9][A-F0-9][A-F0-9][A-F0-9][A-F0-9][A-F0-9][A-F0-9][A-F0-9]+)%]")

    -- Strip the Audit trail header pattern
    log = log:gsub("^.*Audit trail record BEGIN\n=+[\r\n]+", "")

    -- extract all audit core fields using lazy matching
    local when, who, what, action, client_ip, server_ip =
        log:match("WHEN:%s*(.-)\nWHO:%s*(.-)\nWHAT:%s*(.-)\nACTION:%s*(.-)\nCLIENT_IP:%s*(.-)\nSERVER_IP:%s*([^\r\n]+)")

    -- In case we could not extract core fields we should skip this record
    if when == nil then return -1, timestamp, record end

    -- create @timestamp
    local at_timestamp = when:sub(1, 23) .. "Z"

    -- compute outcome from action
    local outcome = "unknown"
    if action:match("SUCCESS") or action:match("CREATED") then
        outcome = "success"
    elseif action:match("FAILED") or action:match("DENIED") or action:match("NOT_FOUND") then
        outcome = "failure"
    end

    -- prepare optional fields that will be populated per action
    local origin_system, destination_system, object, context

    -- On AUTHENTICATION_SUCCESS get origin and destination systems
    if action == "AUTHENTICATION_SUCCESS" then
        origin_system = what:match("iss=(https?://[^,]+)")
                     or what:match("issuerId=(https?://[^,]+)")
        if origin_system then
            origin_system = origin_system:gsub(",$", "")
        end
        destination_system = what:match("service=(https?://[^,}]+)")
        object = destination_system
    end

    -- On SERVICE_ACCESS_ENFORCEMENT_TRIGGERED: outcome is determined by the result value inside WHAT
    if action == "SERVICE_ACCESS_ENFORCEMENT_TRIGGERED" then
        -- remove outer {} wrappers
        local what_clean = what:match("^{(.*)}$")
        if what_clean then
            -- only match real service urls
            destination_system = what_clean:match("service=(https?://[^,}]+)")
            object = destination_system

            -- parse requiredAttributes using pure Lua, no external dependencies
            local req_attr_str = what_clean:match("requiredAttributes=({.-})")
            if req_attr_str then
                local parsed = parse_required_attributes(req_attr_str)
                if next(parsed) then
                    context = { required_attributes = parsed }
                end
            end
        end

        -- Override the outcome
        if what:match("result=Service Access Granted") then
            outcome = "success"
        elseif what:match("result=") then
            outcome = "failure"
        end
    end

    -- For the following actions the destination system is found in what -> service field
    local service_actions = {
        DELEGATED_CLIENT_SUCCESS            = true,
        SERVICE_TICKET_CREATED              = true,
        SERVICE_TICKET_VALIDATE_SUCCESS     = true,
        OAUTH2_USER_PROFILE_CREATED         = true,
        OAUTH2_ACCESS_TOKEN_REQUEST_CREATED = true,
        SAML2_RESPONSE_CREATED              = true,
    }
    if service_actions[action] then
        destination_system = what:match("service=(https?://[^,}]+)")
        object = destination_system
    end

    -- Create the final output record with all the fields
    local new = {}
    new["source"]              = "cas"
    new["outcome"]             = outcome
    new["@version"]            = "1"
    new["timestamp"]           = when
    new["@timestamp"]          = at_timestamp
    new["ip_address"]          = (client_ip ~= "unknown") and client_ip or ""
    new["subject"]             = (who == "audit:unknown") and "" or who
    new["operation"]           = action
    new["server_ip"]           = server_ip or ""
    new["session_id"]          = session_id or ""
    -- We haven't decided yet how to retrieve connection_protocol so we leave it UNKNOWN
    new["connection_protocol"] = "UNKNOWN"

    -- add optional fields only when they are correctly extracted
    if destination_system then new["destination_system"] = destination_system end
    if object             then new["object"]             = object             end
    if origin_system      then new["origin_system"]      = origin_system      end
    if context            then new["context"]            = context            end

    -- Replace the original record with our new one
    return 1, timestamp, new
end
