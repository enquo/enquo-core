use aes_gcm_siv::{aead::Aead, aead::Payload, Aes256GcmSiv, KeyInit, Nonce};
use ciborium::{cbor, value::Value};
use ore_rs::{ORECipher, OREEncrypt, CipherText, scheme::bit2::OREAES128};
use rand_chacha::{ChaChaRng, rand_core::{RngCore, SeedableRng}};
use serde::{Serialize, Deserialize};
use std::cmp::Ordering;

use crate::Field;

#[derive(Debug, Serialize, Deserialize)]
pub struct ORE64v1 {
    // The ciphertext containing the actual (CBOR-encoded) 64-bit uint value, encrypted with AES-256-GCM-SIV
    pub ct: Vec<u8>,
    // Technically the "nonce", but "iv" is shorter to encode as a key in the CBOR map
    pub iv: Vec<u8>,
    // The ORE ciphertext for querying/sorting/etc, as an OREAES128 64/8
    pub ore: Vec<u8>,
}

impl Ord for ORE64v1 {
    fn cmp(&self, other: &Self) -> Ordering {
        let self_ore = CipherText::<OREAES128, 8>::from_bytes(&self.ore).expect("LHS ORE64v1 value did not contain a valid ORE ciphertext");
        let other_ore = CipherText::<OREAES128, 8>::from_bytes(&other.ore).expect("RHS ORE64v1 value did not contain a valid ORE ciphertext");

        self_ore.cmp(&other_ore)
    }
}

impl PartialOrd for ORE64v1 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for ORE64v1 {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for ORE64v1 { }

#[allow(non_upper_case_globals)]
const ORE64v1_PRF_KEY_IDENTIFIER: &[u8] = b"OREv1.prf_key";
#[allow(non_upper_case_globals)]
const ORE64v1_PRP_KEY_IDENTIFIER: &[u8] = b"OREv1.prp_key";
#[allow(non_upper_case_globals)]
const ORE64v1_AES_KEY_IDENTIFIER: &[u8] = b"OREv1.aes_key";

impl ORE64v1 {
    pub fn new(plaintext: u64, context: &[u8], field: &Field) -> ORE64v1 {
        let mut prf_key: [u8; 16] = Default::default();
        let mut prp_key: [u8; 16] = Default::default();

        prf_key.clone_from_slice(&field.subkey(ORE64v1_PRF_KEY_IDENTIFIER)[0..16]);
        prp_key.clone_from_slice(&field.subkey(ORE64v1_PRP_KEY_IDENTIFIER)[0..16]);

        let ore = Self::ore_encrypt(plaintext, &prf_key, &prp_key);

        let (ct, iv) = Self::aes_encrypt(plaintext, &field.subkey(ORE64v1_AES_KEY_IDENTIFIER), context);

        ORE64v1 { ct, iv, ore }
    }

    pub fn decrypt(&self, context: &[u8], field: &Field) -> Result<u64, String> {
        let key: &[u8] = &field.subkey(b"OREv1.aes_key");
        let cipher = Aes256GcmSiv::new(key.into());

        let pt_s = cipher.decrypt(&Nonce::from_slice(&self.iv), Payload{msg: &self.ct, aad: context}).map_err(|e| format!("AES decryption failed: {:?}", e))?;

        let v = ciborium::de::from_reader(&*pt_s).map_err(|e| format!("Could not decode decrypted value: {}", e))?;
        match v {
            Value::Integer(i) => {
                Ok(i.try_into().map_err(|_e| format!("Decoded value is not a valid u64"))?)
            },
            _ => {
                Err(format!("Decoded value is not an integer (got {:?})", v))
            }
        }
    }

    fn aes_encrypt(plaintext: u64, key: &[u8], context: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let cipher = Aes256GcmSiv::new(key.into());
        let mut rng = ChaChaRng::from_entropy();
        let mut nonce: Nonce = Default::default();

        rng.try_fill_bytes(&mut nonce).unwrap();

        let mut msg: Vec<u8> = Default::default();

        ciborium::ser::into_writer(&cbor!(plaintext).unwrap(), &mut msg).unwrap();

        let ct = cipher.encrypt(&nonce, Payload{msg: &msg, aad: context}).unwrap();

        (ct, nonce.to_vec())
    }

    fn ore_encrypt(plaintext: u64, prf_key: &[u8; 16], prp_key: &[u8; 16]) -> Vec<u8> {
        let seed: [u8; 8] = [0, 1, 2, 3, 4, 5, 6, 7];
        let mut cipher: OREAES128 = ORECipher::init(*prf_key, *prp_key, &seed).unwrap();
        plaintext.encrypt(&mut cipher).expect("ORE encryption failed").to_bytes()
    }
}

#[derive(Ord, PartialOrd, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum EncryptedValue {
    ORE64v1(ORE64v1),
}
