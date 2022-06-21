
-- =========================
-- Contract File: NFT.lua (project/project1)
-- =========================

--[[
    全局环境变量，由外部注入

    CONTEXT = {}
]] 

ACTION = {
    Mint = 1,
    Update = 2,
    Transfer = 3,
    Burn = 4,
    Readonly = 5,
}
REMOTE = {
    Send = 1,
    Receive = 2,
}

--[[
    Global 数据初始化
]]
function InitGlobal ()
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

UpdateGlobal = {
    metadata = {
        only_owner  = true,
        need_global = true,
        action      = ACTION.Update,
    },
    call = function (key, value)
        CONTEXT.Global[key] = value
    end
}

ReadConfig = {
    metadata = {
        action = ACTION.Readonly,
    },
    call = function ()
        return 5
    end
}

Mint = {
    metadata = {
        need_global = true,
        action      = ACTION.Mint,
    },
    ckbCost = function ()
        return 500
    end,
    call = function ()
        local new_count = CONTEXT.Global.minted_nft_count + 1
        if new_count <= CONTEXT.Global.max_nft_count then
            CONTEXT.Global.minted_nft_count = new_count
            CONTEXT.Global.current_token_id = CONTEXT.Global.current_token_id + 1
            return {
                token_id = CONTEXT.Global.current_token_id,
                glossaries = {}
            }
        end
    end
}

Update = {
    metadata = {
        need_global = true,
        action      = ACTION.Update,
    },
    call = function (key, value)
        CONTEXT.Global.updated_nft_count = CONTEXT.Global.updated_nft_count + 1
        CONTEXT.Personal.glossaries[key] = value
    end
}

Transfer = {
    metadata = {
        need_global = true,
        action      = ACTION.Transfer,
    },
    call = function ()
        CONTEXT.Global.transfered_nft_count = CONTEXT.Global.transfered_nft_count + 1
    end
}

Burn = {
    metadata = {
        need_global = true,
        action      = ACTION.Burn
    },
    call = function ()
        CONTEXT.Global.burned_nft_count = CONTEXT.Global.burned_nft_count + 1
    end
}

--[[
    合约交互调用
]]

ComposeTo = {
    metadata = {
        need_global = true,
        action = ACTION.Burn,
        cross_call = REMOTE.Send,
    },
    call = function ()
        CONTEXT.RemoteContractCall(CONTEXT.Global.loot_project_id, "ComposeFrom", CONTEXT.Personal)
    end
}
