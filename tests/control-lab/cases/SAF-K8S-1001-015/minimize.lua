-- Test-only minimizer for the exact synthetic schema in fixtures.json.
local function scrub(value)
    if type(value) ~= "string" then
        return "[INVALID_TEXT_SUPPRESSED]"
    end
    value = string.gsub(value, "PERSON_[A-Z]+_[0-9]+", "[REDACTED]")
    value = string.gsub(value, "KEY_[A-Z]+_[0-9]+", "[REDACTED]")
    return value
end

local function minimized_record(record)
    -- Tail emits unparsed text under `log` if the parser rejects the line. Discard it
    -- wholesale so malformed lines cannot bypass structured-field minimization.
    if record["log"] ~= nil then
        return {
            event_id = "saf015-malformed-001",
            direction = "malformed",
            payload_state = "malformed_record_suppressed"
        }
    end

    -- An explicit allow-list minimizes structured fields. In particular, the
    -- fixture's customer_ref and auth_fragment are never copied into the new map.
    local output = {}
    for _, key in ipairs({"event_id", "direction", "model", "status", "elapsed_ms"}) do
        local value = record[key]
        if type(value) == "string" or type(value) == "number" then
            output[key] = value
        end
    end
    for _, key in ipairs({"prompt", "completion"}) do
        if record[key] ~= nil then
            output[key] = scrub(record[key])
        end
    end
    return output
end

function minimize_payload(tag, timestamp, record)
    local ok, output = pcall(minimized_record, record)
    if not ok then
        return -1, timestamp, record
    end
    return 2, timestamp, output
end
