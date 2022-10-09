
function construct ()
    return {
        driver = KOC.owner,
        global = {
            nft_count = 0,
            max_nft_count = 0,
            token_id = 0,
            loot_project_id = {
                hash = '0xabcdefg',
                version = 0,
                enable = true,
            },
            request_array = { 2, 'abc', false, {1, 2, 3, {x = "liyukun"}}, {abc = 1, cba = 2} }
        }
    }
end

local function only_owner()
    assert(KOC.inputs[0].owner == KOC.owner, "only_owner assert failed")
end

local function only_empty_input()
    assert(#KOC.inputs == 1 and not KOC.inputs[0].data, "no_input assert failed")
end

local function sender()
    return KOC.inputs[0].owner
end

function updateGlobal (key, value)
    only_owner()
    assert(KOC.global[key] ~= nil, "unsupported key " .. key)
    KOC.global[key] = value
    return {
        global = KOC.global
    }
end

function transferDriver()
    only_owner()
    return {
        driver = KOC.recipient
    }
end

function mint ()
    only_empty_input()
    assert(KOC.deposit(500.55), "ckb not enough")
    local global = KOC.global
    local new_count = global.nft_count + 1
    local data = nil
    if new_count <= global.max_nft_count then
        global.nft_count = new_count
        global.token_id = global.token_id + 1
        data = {
            token_id = global.token_id,
            glossaries = {}
        }
    end
    return {
        global = global,
        driver = KOC.recipient,
        outputs = {
            { owner = sender(), data = data }
        }
    }
end

function update (key, value)
    assert(KOC.inputs[0].data, "data cannot be empty")
    local data = KOC.inputs[0].data
    data.glossaries[key] = value
    return {
        outputs = {
            { owner = sender(), data = data }
        }
    }
end

function transfer ()
    assert(#KOC.inputs == 1, "only one input")
    assert(KOC.inputs[0].data, "must contain valid input data")
    assert(sender() ~= KOC.recipient, "recipient must be other one")
    return {
        outputs = {
            { owner = KOC.recipient, data = KOC.inputs[0].data }
        }
    }
end

function burn ()
    assert(KOC.personal, 'burned personal must exist')
    KOC.personal = nil
end

function wrong_code ()
    KOC.personal = {
        token_id = 0
    }
    assert(false, "it's wrong code")
end
