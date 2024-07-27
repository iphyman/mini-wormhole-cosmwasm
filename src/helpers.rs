use k256::{
    ecdsa::VerifyingKey,
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
    AffinePoint, EncodedPoint,
};
use sha3::{Digest, Keccak256};

use crate::state::GuardianAddress;

pub fn keys_equal(a: &VerifyingKey, b: &GuardianAddress) -> bool {
    let mut hasher = Keccak256::new();

    let affine_point_option = AffinePoint::from_encoded_point(&EncodedPoint::from(a));
    let affine_point = if affine_point_option.is_some().into() {
        affine_point_option.unwrap()
    } else {
        return false;
    };

    let decompressed_point = affine_point.to_encoded_point(false);

    hasher.update(&decompressed_point.as_bytes()[1..]);
    let a = &hasher.finalize()[12..];

    let b = &b.bytes;
    if a.len() != b.len() {
        return false;
    }

    for (ai, bi) in a.iter().zip(b.as_slice().iter()) {
        if ai != bi {
            return false;
        }
    }
    true
}
