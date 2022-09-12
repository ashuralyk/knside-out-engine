
function construct ()
    return {
        driver = KOC.owner,
        global = {
            minted_nft_count = 0,
            max_nft_count = 0,
            burned_nft_count = 0,
            transfered_nft_count = 0,
            updated_nft_count = 0,
            current_token_id = 0,
            loot_project_id = {
                hash = '0xabcdefg',
                version = 0,
                enable = true,
            },
            request_array = { 2, 'abc', false, {1, 2, 3, {x = "liyukun"}}, {abc = 1, cba = 2} }
        }
    }
end

function updateGlobal (key, value)
    assert(KOC.user == KOC.owner, "sender must be owner")
    assert(KOC.global[key] ~= nil, "unsupported key " .. key)
    assert(not KOC.personal, "only accept no data request")
    KOC.global[key] = value
end

function transferDriver()
    assert(KOC.user == KOC.owner, "sender must be owner")
    assert(KOC.user ~= KOC.recipient, "recipient must be other one")
    assert(KOC.driver ~= KOC.recipient, "drvier must be different")
    KOC.driver = KOC.recipient
end

function mint ()
    assert(not KOC.personal, "can not contain any input data")
    assert(KOC.ckb_deposit(500.55), "ckb not enough")
    local global = KOC.global
    local new_count = global.minted_nft_count + 1
    if new_count <= global.max_nft_count then
        global.minted_nft_count = new_count
        global.current_token_id = global.current_token_id + 1
        KOC.personal = {
            token_id = global.current_token_id,
            glossaries = {}
        }
    end
    KOC.driver = KOC.recipient
end

function update (key, value)
    assert(KOC.personal, 'personal must be table value')
    KOC.global.updated_nft_count = KOC.global.updated_nft_count + 1
    KOC.personal.glossaries[key] = value
end

function transfer ()
    assert(KOC.personal, "must contain valid input data")
    assert(KOC.user ~= KOC.recipient, "recipient must be other one")
    KOC.global.transfered_nft_count = KOC.global.transfered_nft_count + 1
    KOC.user = KOC.recipient
end

function burn ()
    assert(KOC.personal, 'burned personal must exist')
    KOC.global.burned_nft_count = KOC.global.burned_nft_count + 1
    KOC.personal = nil
end

function wrong_code ()
    KOC.personal = {
        token_id = 0
    }
    assert(false, "it's wrong code")
end
