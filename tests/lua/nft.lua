
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
    assert(KOC.user == KOC.owner, "only_owner assert failed")
end

local function only_empty_input()
    assert(not KOC.data and #KOC.others == 0, "no_input assert failed")
end

function updateGlobal (key, value)
    only_owner()
    assert(KOC.global[key] ~= nil, "unsupported key " .. key)
    KOC.global[key] = value
end

function transferDriver()
    only_owner()
    KOC.driver = KOC.recipient
end

function mint ()
    only_empty_input()
    assert(KOC.deposit(500.55), "ckb not enough")
    local global = KOC.global
    local new_count = global.nft_count + 1
    if new_count <= global.max_nft_count then
        global.nft_count = new_count
        global.token_id = global.token_id + 1
        KOC.data = {
            token_id = global.token_id,
            glossaries = {}
        }
    end
    KOC.driver = KOC.recipient
end

function update (key, value)
    only_empty_input()
    KOC.data.glossaries[key] = value
end

function transfer ()
    assert(KOC.personal, "must contain valid input data")
    assert(KOC.user ~= KOC.recipient, "recipient must be other one")
    KOC.user = KOC.recipient
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
