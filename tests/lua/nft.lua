
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
        loot_project_id = '0xabcdefg',
    }
end

--[[
    定义方法
]]
function updateGlobal (key, value)
    assert(msg.sender == msg.owner, "sender must be owner")
    msg.global[key] = value
end

function mint ()
    assert(msg.ckb_cost(500), "ckb not enough")
    local new_count = msg.global.minted_nft_count + 1
    if new_count <= msg.global.max_nft_count then
        msg.global.minted_nft_count = new_count
        msg.global.current_token_id = msg.global.current_token_id + 1
        msg.mint({
            token_id = msg.global.current_token_id,
            glossaries = {}
        })
    end
end

function update (key, value)
    msg.global.updated_nft_count = msg.global.updated_nft_count + 1
    msg.data.glossaries[key] = value
    msg.update(msg.data)
end

function transfer (to)
    msg.global.transfered_nft_count = msg.global.transfered_nft_count + 1
    msg.transfer(to, msg.data)
end

function burn ()
    msg.global.burned_nft_count = msg.global.burned_nft_count + 1
    msg.burn()
end

--[[
    合约交互调用
]]
function composeTo ()
    msg.xcall(msg.global.loot_project_id, "composeFrom", msg.data)
    msg.burn(msg.sender)
end
