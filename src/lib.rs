use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jint, jstring, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;

use bip39::{Language, Mnemonic};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use zeroize::Zeroize;

use falcon_rust::falcon512::{
    keygen, sign as falcon_sign, verify as falcon_verify, PublicKey, SecretKey, Signature,
};

type HmacSha256 = Hmac<Sha3_256>;

const SIGNING_DOMAIN: &[u8] = b"QUANTA_TX_V1:";

// ---------------------------------------------------------------------------
// JS-visible data structures (returned as JSON strings to Android Kotlin)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
pub struct WalletInfo {
    pub mnemonic: String,
    pub address: String,
    pub public_key: String, // hex — 897 bytes
    pub secret_key: String, // hex — caller must zeroize after storing
}

#[derive(Serialize, Deserialize)]
pub struct KeypairInfo {
    pub address: String,
    pub public_key: String,
    pub secret_key: String,
}

// ---------------------------------------------------------------------------
// Internal helpers (Identical to wasm implementation for consensus safety)
// ---------------------------------------------------------------------------

fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha3_256::digest(data));
    out
}

fn canonical_signing_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(SIGNING_DOMAIN);
    hasher.update(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

fn address_from_pubkey(pubkey: &[u8]) -> String {
    let hash = sha3_256(pubkey);
    format!("0x{}", hex::encode(&hash[..20]))
}

fn derive_master_key(seed: &[u8]) -> [u8; 32] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(b"Quanta HD Wallet Master Key").expect("HMAC key init");
    mac.update(seed);
    let mut out = [0u8; 32];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

fn derive_account_key(master_key: &[u8], index: u32) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(master_key).expect("HMAC key init");
    mac.update(&index.to_be_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

// ---------------------------------------------------------------------------
// Native JNI Bridge Methods for Android (com.quanta.mobile.crypto.NativeCrypto)
// ---------------------------------------------------------------------------

/// Generate a fresh Falcon-512 keypair deterministically from a new BIP39 mnemonic.
#[no_mangle]
pub extern "system" fn Java_com_quanta_mobile_crypto_NativeCrypto_generateWallet<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jstring {
    let mut entropy = [0u8; 32];
    if getrandom::getrandom(&mut entropy).is_err() {
        return env.new_string("").unwrap().into_raw();
    }

    let mnemonic = match Mnemonic::from_entropy_in(Language::English, &entropy) {
        Ok(m) => m,
        Err(_) => return env.new_string("").unwrap().into_raw(),
    };

    let seed = mnemonic.to_seed("");
    let master = derive_master_key(&seed);
    let account_key = derive_account_key(&master, 0);
    let (sk, pk) = keygen(account_key);

    let pk_bytes = pk.to_bytes();
    let mut sk_bytes = sk.to_bytes();
    let address = address_from_pubkey(&pk_bytes);

    let info = WalletInfo {
        mnemonic: mnemonic.to_string(),
        address,
        public_key: hex::encode(&pk_bytes),
        secret_key: hex::encode(&sk_bytes),
    };
    sk_bytes.zeroize();

    let json = serde_json::to_string(&info).unwrap_or_else(|_| "".to_string());
    env.new_string(json).expect("Couldn't create java string!").into_raw()
}

/// Restore a wallet deterministically from a BIP39 mnemonic phrase.
#[no_mangle]
pub extern "system" fn Java_com_quanta_mobile_crypto_NativeCrypto_importWallet<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    mnemonic_jstring: JString<'local>,
    passphrase_jstring: JString<'local>,
    index: jint,
) -> jstring {
    let mnemonic_phrase: String = match env.get_string(&mnemonic_jstring) {
        Ok(s) => s.into(),
        Err(_) => return env.new_string("").unwrap().into_raw(),
    };
    let passphrase: String = match env.get_string(&passphrase_jstring) {
        Ok(s) => s.into(),
        Err(_) => return env.new_string("").unwrap().into_raw(),
    };

    let mnemonic = match Mnemonic::parse_in_normalized(Language::English, &mnemonic_phrase) {
        Ok(m) => m,
        Err(_) => return env.new_string("").unwrap().into_raw(),
    };

    let seed = mnemonic.to_seed(&passphrase);
    let master = derive_master_key(&seed);
    let account_key = derive_account_key(&master, index as u32);

    let (sk, pk) = keygen(account_key);
    let pk_bytes = pk.to_bytes();
    let mut sk_bytes = sk.to_bytes();
    let address = address_from_pubkey(&pk_bytes);

    let info = KeypairInfo {
        address,
        public_key: hex::encode(&pk_bytes),
        secret_key: hex::encode(&sk_bytes),
    };
    sk_bytes.zeroize();

    let json = serde_json::to_string(&info).unwrap_or_else(|_| "".to_string());
    env.new_string(json).expect("Couldn't create java string!").into_raw()
}

/// Sign transaction data with a Falcon-512 secret key.
#[no_mangle]
pub extern "system" fn Java_com_quanta_mobile_crypto_NativeCrypto_signTransaction<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    tx_data_jstring: JString<'local>,
    secret_key_jstring: JString<'local>,
) -> jstring {
    let tx_data_hex: String = match env.get_string(&tx_data_jstring) {
        Ok(s) => s.into(),
        Err(_) => return env.new_string("").unwrap().into_raw(),
    };
    let secret_key_hex: String = match env.get_string(&secret_key_jstring) {
        Ok(s) => s.into(),
        Err(_) => return env.new_string("").unwrap().into_raw(),
    };

    let tx_bytes = match hex::decode(&tx_data_hex) {
        Ok(b) => b,
        Err(_) => return env.new_string("").unwrap().into_raw(),
    };
    let mut sk_bytes = match hex::decode(&secret_key_hex) {
        Ok(b) => b,
        Err(_) => return env.new_string("").unwrap().into_raw(),
    };

    let sk = match SecretKey::from_bytes(&sk_bytes) {
        Ok(k) => k,
        Err(_) => {
            sk_bytes.zeroize();
            return env.new_string("").unwrap().into_raw();
        }
    };
    sk_bytes.zeroize();

    let hash = canonical_signing_hash(&tx_bytes);
    let sig: Signature = falcon_sign(&hash, &sk);
    let sig_bytes = sig.to_bytes();

    let mut out = Vec::with_capacity(sig_bytes.len() + 32);
    out.extend_from_slice(&sig_bytes);
    out.extend_from_slice(&hash);

    let result_hex = hex::encode(out);
    env.new_string(result_hex).expect("Couldn't create java string!").into_raw()
}

/// Verify a Falcon-512 signature.
#[no_mangle]
pub extern "system" fn Java_com_quanta_mobile_crypto_NativeCrypto_verifySignature<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    hash_jstring: JString<'local>,
    signed_msg_jstring: JString<'local>,
    pubkey_jstring: JString<'local>,
) -> jboolean {
    let hash_hex: String = match env.get_string(&hash_jstring) {
        Ok(s) => s.into(),
        Err(_) => return JNI_FALSE,
    };
    let signed_msg_hex: String = match env.get_string(&signed_msg_jstring) {
        Ok(s) => s.into(),
        Err(_) => return JNI_FALSE,
    };
    let pubkey_hex: String = match env.get_string(&pubkey_jstring) {
        Ok(s) => s.into(),
        Err(_) => return JNI_FALSE,
    };

    let hash_bytes = match hex::decode(&hash_hex) {
        Ok(b) => b,
        Err(_) => return JNI_FALSE,
    };
    let signed_bytes = match hex::decode(&signed_msg_hex) {
        Ok(b) => b,
        Err(_) => return JNI_FALSE,
    };
    let pk_bytes = match hex::decode(&pubkey_hex) {
        Ok(b) => b,
        Err(_) => return JNI_FALSE,
    };

    if signed_bytes.len() <= 32 {
        return JNI_FALSE;
    }
    let sig_part = &signed_bytes[..signed_bytes.len() - 32];
    let msg_part = &signed_bytes[signed_bytes.len() - 32..];

    if msg_part != hash_bytes.as_slice() {
        return JNI_FALSE;
    }

    let pk = match PublicKey::from_bytes(&pk_bytes) {
        Ok(p) => p,
        Err(_) => return JNI_FALSE,
    };
    let sig = match Signature::from_bytes(sig_part) {
        Ok(s) => s,
        Err(_) => return JNI_FALSE,
    };

    if falcon_verify(&hash_bytes, &sig, &pk) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}
