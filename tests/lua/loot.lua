-- =========================
-- Contract File: Loot.lua (project2)
-- =========================
function InitGlobal ()
    return {
        remote_requests = {},
    }
end

Mint = {
    metadata = {
        need_global = true,
        action      = ACTION.Mint,
    },
    ckbCost = function ()
        return 200
    end,
    call = function ()
        return {
            glossaries = {}
        }
    end
}

ComposeFrom = {
    metadata = {
        only_owner = true,
        need_global = true,
        action = ACTION.Update,
        cross_call = REMOTE.Receive,
    },
    call = function (cross_request)
        CONTEXT.Global.remote_requests[cross_request.address] = cross_request.value
    end
}

Compose = {
    metadata = {
        need_global = true,
        action = ACTION.Update,
    },
    call = function ()
        local sender = CONTEXT.Sender
        local value = assert(CONTEXT.Global.remote_requests[sender], "no remote request")
        CONTEXT.Personal.glossaries[value.name] = value.val
        return CONTEXT.Personal
    end
}