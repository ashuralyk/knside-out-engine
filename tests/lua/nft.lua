
-- =========================
-- Contract File: NFT.lua (project/project1)
-- =========================

--[[
    Global 数据初始化
]]
function construct ()
    return {
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
end

--[[
    定义方法
]]
function updateGlobal (key, value)
    assert(msg.sender == msg.owner, "sender must be owner")
    assert(msg.global[key] ~= nil, "unsupported key " .. key)
    assert(not msg.data, "only accept no data request")
    msg.global[key] = value
    return {
        owner = msg.sender,
        data = nil
    }
end

function mint ()
    assert(not msg.data, "can not contain any input data")
    assert(msg.ckb_cost(500.55), "ckb not enough")
    local new_count = msg.global.minted_nft_count + 1
    if new_count <= msg.global.max_nft_count then
        msg.global.minted_nft_count = new_count
        msg.global.current_token_id = msg.global.current_token_id + 1
        return {
            owner = msg.sender,
            data = {
                token_id = msg.global.current_token_id,
                glossaries = {}
            }
        }
    end
end

function update (key, value)
    msg.global.updated_nft_count = msg.global.updated_nft_count + 1
    msg.data.glossaries[key] = value
    return {
        owner = msg.sender,
        data = msg.data
    }
end

function transfer (to)
    assert(msg.data, "must contain valid input data")
    msg.global.transfered_nft_count = msg.global.transfered_nft_count + 1
    return {
        owner = to,
        data = msg.data
    }
end

function burn ()
    msg.global.burned_nft_count = msg.global.burned_nft_count + 1
    return {
        owner = msg.sender,
        data = nil
    }
end

--[[
    合约交互调用
]]
function composeTo ()
    msg.xcall(msg.global.loot_project_id.hash, "composeFrom", msg.data)
    msg.burn(msg.sender)
end
