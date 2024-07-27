use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::Binary;

use crate::state::{GuardianAddress, GuardianSetInfo};

type HumanAddr = String;

#[cw_serde]
pub struct InstantiateMsg {
    pub gov_chain: u16,
    pub gov_address: Binary,

    /// Guardian set to initialise the contract with.
    pub initial_guardian_set: GuardianSetInfo,
    pub guardian_set_expirity: u64,

    pub chain_id: u16,
}

#[cw_serde]
pub enum ExecuteMsg {
    SubmitVAA { vaa: Binary },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(GuardianSetInfoResponse)]
    GuardianSetInfo {},

    #[returns(VerifyVAAResponse)]
    VerifyVAA { vaa: Binary, block_time: u64 },

    #[returns(GetAddressHexResponse)]
    QueryAddressHex { address: HumanAddr },
}

#[cw_serde]
pub struct GuardianSetInfoResponse {
    pub guardian_set_index: u32,         // Current guardian set index
    pub addresses: Vec<GuardianAddress>, // List of querdian addresses
}

#[cw_serde]
pub struct VerifyVAAResponse {
    pub version: u8,
    pub guardian_set_index: u32,
    pub timestamp: u32,
    pub nonce: u32,
    pub len_signers: u8,

    pub emitter_chain: u16,
    pub emitter_address: Vec<u8>,
    pub sequence: u64,
    pub consistency_level: u8,
    pub payload: Vec<u8>,

    pub hash: Vec<u8>,
}

#[cw_serde]
pub struct GetAddressHexResponse {
    pub hex: String,
}
