#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult,
};
use cw2::set_contract_version;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

use crate::byte_utils::{extend_address_to_32, ByteUtils};
use crate::error::ContractError;
use crate::helpers::keys_equal;
use crate::msg::{
    ExecuteMsg, GetAddressHexResponse, GuardianSetInfoResponse, InstantiateMsg, QueryMsg,
};
use crate::state::{
    ConfigInfo, GovernancePacket, GuardianSetUpgrade, ParsedVAA, CONFIG, CONSUMED_VAA_ARCHIVE,
    GUARDIAN_SET,
};

type HumanAddr = String;

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:wormhole";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    // Save general wormhole info
    let config = ConfigInfo {
        gov_chain: msg.gov_chain,
        gov_address: msg.gov_address.as_slice().to_vec(),
        guardian_set_index: 0,
        guardian_set_expirity: msg.guardian_set_expirity,
        chain_id: msg.chain_id,
    };

    CONFIG.save(deps.storage, &config)?;
    GUARDIAN_SET.save(
        deps.storage,
        config.guardian_set_index,
        &msg.initial_guardian_set,
    )?;
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::SubmitVAA { vaa } => handle_submit_vaa(deps, env, info, vaa.as_slice()),
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GuardianSetInfo {} => to_json_binary(&query_guardian_set_info(deps)?),
        QueryMsg::VerifyVAA { vaa, block_time } => {
            to_json_binary(&parse_and_verify_vaa(deps, vaa.as_slice(), block_time)?)
        }
        QueryMsg::QueryAddressHex { address } => {
            to_json_binary(&query_address_hex(deps, &address)?)
        }
    }
}

/// Process VAA message signed by quardians
fn handle_submit_vaa(
    deps: DepsMut,
    env: Env,
    _info: MessageInfo,
    data: &[u8],
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;

    let vaa = parse_and_verify_vaa(deps.as_ref(), data, env.block.time.seconds())?;
    CONSUMED_VAA_ARCHIVE.save(deps.storage, vaa.hash.as_slice(), &true)?;

    if config.gov_chain == vaa.emitter_chain && config.gov_address == vaa.emitter_address {
        if config.guardian_set_index != vaa.guardian_set_index {
            return Err(ContractError::InvalidGovernanceVaa {});
        }

        return handle_governance_payload(deps, env, &vaa.payload);
    }

    Err(ContractError::InvalidVAAAction {})
}

fn handle_governance_payload(
    deps: DepsMut,
    env: Env,
    data: &[u8],
) -> Result<Response, ContractError> {
    let gov_packet = GovernancePacket::deserialize(data)?;
    let config = CONFIG.load(deps.storage)?;

    let module = String::from_utf8(gov_packet.module).unwrap();
    let module: String = module.chars().filter(|c| c != &'\0').collect();

    if module != "Core" {
        return Err(ContractError::InvalidModule {});
    }

    if gov_packet.chain != 0 && gov_packet.chain != config.chain_id {
        return Err(ContractError::InvalidGovernanceVaa {});
    }

    match gov_packet.action {
        // 1u8 => vaa_update_contract(deps, env, &gov_packet.payload),
        2u8 => vaa_update_guardian_set(deps, env, &gov_packet.payload),
        // #[cfg(feature = "full")]
        // 3u8 => handle_set_fee(deps, env, &gov_packet.payload),
        // #[cfg(feature = "full")]
        // 4u8 => handle_transfer_fee(deps, env, &gov_packet.payload),
        _ => Err(ContractError::InvalidVAAAction {}),
    }
}

/// Parses raw VAA data into a struct and verifies whether it contains sufficient signatures of an
/// active guardian set i.e. is valid according to Wormhole consensus rules
fn parse_and_verify_vaa(deps: Deps, data: &[u8], block_time: u64) -> StdResult<ParsedVAA> {
    let vaa = ParsedVAA::deserialize(data)?;

    if vaa.version != 1 {
        Err(StdError::generic_err("Invalid Version".to_string()))?
    }

    // first check guardian set index exist
    if !GUARDIAN_SET.has(deps.storage, vaa.guardian_set_index) {
        Err(StdError::generic_err(
            "Invalid guardian set index".to_string(),
        ))?
    }

    // Load and check guardian set
    let guardian_set = GUARDIAN_SET.load(deps.storage, vaa.guardian_set_index)?;

    if guardian_set.expiration_time != 0 && guardian_set.expiration_time < block_time {
        Err(StdError::generic_err("Guardian set expired".to_string()))?
    }

    if (vaa.len_signers as usize) < guardian_set.quorum() {
        Err(StdError::generic_err("No quorum".to_string()))?
    }

    // Verify guardian signatures
    let mut last_index: i32 = -1;
    let mut pos = ParsedVAA::HEADER_LEN;

    for _ in 0..vaa.len_signers {
        if pos + ParsedVAA::SIGNATURE_LEN > data.len() {
            Err(StdError::generic_err("Invalid VAA".to_string()))?
        }

        let index = data.get_u8(pos) as i32;
        if index <= last_index {
            Err(StdError::generic_err(
                "Wrong guardian index order".to_string(),
            ))?
        }

        last_index = index;

        let signature = Signature::try_from(
            &data[pos + ParsedVAA::SIG_DATA_POS
                ..pos + ParsedVAA::SIG_DATA_POS + ParsedVAA::SIG_DATA_LEN],
        )
        .map_err(|_| StdError::generic_err("Cannot decode signature".to_string()))?;

        let recovery_id = RecoveryId::try_from(data.get_u8(pos + ParsedVAA::SIG_RECOVERY_POS))
            .map_err(|_| StdError::generic_err("Cannot decode signature".to_string()))?;

        let verify_key =
            VerifyingKey::recover_from_prehash(vaa.hash.as_slice(), &signature, recovery_id)
                .map_err(|_| StdError::generic_err("Cannot recover key".to_string()))?;

        let index = index as usize;
        if index >= guardian_set.addresses.len() {
            Err(StdError::generic_err("Too many signatures".to_string()))?
        }

        if !keys_equal(&verify_key, &guardian_set.addresses[index]) {
            Err(StdError::generic_err(
                "Guardian signature error".to_string(),
            ))?
        }
        pos += ParsedVAA::SIGNATURE_LEN;
    }

    Ok(vaa)
}

fn vaa_update_guardian_set(
    deps: DepsMut,
    env: Env,
    data: &[u8],
) -> Result<Response, ContractError> {
    /* Payload format
    0   uint32 new_index
    4   uint8 len(keys)
    5   [][20]uint8 guardian addresses
    */

    let mut config = CONFIG.load(deps.storage)?;

    let GuardianSetUpgrade {
        new_guardian_set_index,
        new_guardian_set,
    } = GuardianSetUpgrade::deserialize(data)?;

    if new_guardian_set_index != config.guardian_set_index + 1 {
        return Err(ContractError::GuardianSetIndexIncreaseError {});
    }

    let old_guardian_set_index = config.guardian_set_index;

    config.guardian_set_index = new_guardian_set_index;

    GUARDIAN_SET.save(deps.storage, config.guardian_set_index, &new_guardian_set)?;
    CONFIG.save(deps.storage, &config)?;

    GUARDIAN_SET.update(deps.storage, old_guardian_set_index, |op| match op {
        None => Err(ContractError::InvalidGuardianSetIndex {}),
        Some(mut old_gs) => {
            old_gs.expiration_time = env.block.time.seconds() + config.guardian_set_expirity;

            Ok(old_gs)
        }
    })?;

    Ok(Response::new()
        .add_attribute("action", "guardian_set_change")
        .add_attribute("old", old_guardian_set_index.to_string())
        .add_attribute("new", config.guardian_set_index.to_string()))
}

pub fn query_guardian_set_info(deps: Deps) -> StdResult<GuardianSetInfoResponse> {
    let config = CONFIG.load(deps.storage)?;
    let guardian_set = GUARDIAN_SET.load(deps.storage, config.guardian_set_index)?;

    let res = GuardianSetInfoResponse {
        guardian_set_index: config.guardian_set_index,
        addresses: guardian_set.addresses,
    };

    Ok(res)
}

pub fn query_address_hex(deps: Deps, address: &HumanAddr) -> StdResult<GetAddressHexResponse> {
    Ok(GetAddressHexResponse {
        hex: hex::encode(extend_address_to_32(&deps.api.addr_canonicalize(address)?)),
    })
}

#[cfg(test)]
mod tests {}
