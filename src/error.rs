use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unauthorized")]
    Unauthorized {},

    /// Invalid VAA version
    #[error("InvalidVersion")]
    InvalidVersion {},

    /// Guardian set with this index does not exist
    #[error("InvalidGuardianSetIndex")]
    InvalidGuardianSetIndex {},

    /// Guardian set expiration date is zero or in the past
    #[error("GuardianSetExpired")]
    GuardianSetExpired {},

    /// Not enough signers on the VAA
    #[error("NoQuorum")]
    NoQuorum {},

    /// Wrong guardian index order, order must be ascending
    #[error("WrongGuardianIndexOrder")]
    WrongGuardianIndexOrder {},

    /// Some problem with signature decoding from bytes
    #[error("CannotDecodeSignature")]
    CannotDecodeSignature {},

    /// Some problem with public key recovery from the signature
    #[error("CannotRecoverKey")]
    CannotRecoverKey {},

    /// Recovered pubkey from signature does not match guardian address
    #[error("GuardianSignatureError")]
    GuardianSignatureError {},

    /// VAA action code not recognized
    #[error("InvalidVAAAction")]
    InvalidVAAAction {},

    /// VAA guardian set is not current
    #[error("NotCurrentGuardianSet")]
    NotCurrentGuardianSet {},

    /// Not a valid module
    #[error("InvalidModule")]
    InvalidModule {},

    /// Wrong governance vaa chain
    #[error("InvalidGovernanceVaa")]
    InvalidGovernanceVaa {},

    /// Guardian set must increase in steps of 1
    #[error("GuardianSetIndexIncreaseError")]
    GuardianSetIndexIncreaseError {},

    /// VAA was already executed
    #[error("VaaAlreadyExecuted")]
    VaaAlreadyExecuted {},

    /// Message sender not permitted to execute this operation
    #[error("PermissionDenied")]
    PermissionDenied {},

    /// More signatures than active guardians found
    #[error("TooManySignatures")]
    TooManySignatures {},

    /// Generic error when there is a problem with VAA structure
    #[error("InvalidVAA")]
    InvalidVAA {},
}
