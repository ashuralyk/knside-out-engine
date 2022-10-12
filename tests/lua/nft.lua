
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
    assert(KOC.inputs[1].owner == KOC.owner, "only_owner assert failed")
end

local function only_empty_input()
    assert(#KOC.inputs == 1 and not KOC.inputs[1].data, "no_input assert failed")
end

local function sender()
    return KOC.inputs[1].owner
end

function updateGlobal (key, value)
    only_owner()
    assert(KOC.global[key] ~= nil, "unsupported key " .. key)
    assert(KOC.ckb_withdraw(500), "global ckb not enough")
    KOC.global[key] = value
    return {
        global = KOC.global
    }
end

function mint ()
    only_empty_input()
    assert(#KOC.candidates > 0, "no candidates")
    assert(KOC.ckb_deposit(500), "request ckb not enough")
    local global = KOC.global
    local new_count = global.minted_nft_count + 1
    local data = nil
    if new_count <= global.max_nft_count then
        global.minted_nft_count = new_count
        global.current_token_id = global.current_token_id + 1
        data = {
            token_id = global.current_token_id,
            glossaries = {}
        }
    end
    return {
        global = global,
        driver = KOC.candidates[1],
        outputs = {
            { owner = sender(), data = data },
            { owner = sender(), data = nil }
        }
    }
end

function wrong_code ()
    assert(#KOC.components > 0, "need one library")
    local f, err = load(KOC.components[1].ugc)
    if err then
        print(err)
    else
        print("ugc_print: " .. f())
    end
    assert(false, "it's wrong code")
end

function transferDriver()
    only_owner()
    return {
        driver = KOC.recipient
    }
end

function update (key, value)
    assert(KOC.inputs[1].data, "data cannot be empty")
    local data = KOC.inputs[1].data
    data.glossaries[key] = value
    return {
        outputs = {
            { owner = sender(), data = data }
        }
    }
end

function transfer ()
    assert(#KOC.inputs == 1, "only one input")
    assert(KOC.inputs[1].data, "must contain valid input data")
    assert(sender() ~= KOC.recipient, "recipient must be other one")
    return {
        outputs = {
            { owner = KOC.recipient, data = KOC.inputs[1].data }
        }
    }
end

function burn ()
    assert(KOC.personal, 'burned personal must exist')
    KOC.personal = nil
end
