use bip32::{Mnemonic, XPrv};
use josekit::jwt::JwtPayload;
use k256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};

use crate::KeyringError;

pub struct Key {
    /// The key's name
    pub name: String,
    /// The secp256k1 private key
    sk: SigningKey,
}

impl Key {
    /// Create a new key instance from a given name and BIP-32 mnemonic phrase
    pub fn from_mnemonic(
        name: impl ToString,
        mnemonic: &Mnemonic,
        coin_type: u32,
    ) -> Result<Self, KeyringError> {
        // The `to_seed` function takes a password to generate salt. Here we just use an empty str.
        // For reference, both Terra Station and Keplr use an empty string as well:
        // - https://github.com/terra-money/terra.js/blob/v3.1.7/src/key/MnemonicKey.ts#L79
        // - https://github.com/chainapsis/keplr-wallet/blob/b6062a4d24f3dcb15dda063b1ece7d1fbffdbfc8/packages/crypto/src/mnemonic.ts#L63
        let seed = mnemonic.to_seed("");
        let path = format!("m/44'/{coin_type}'/0'/0/0");
        let xprv = XPrv::derive_from_path(&seed, &path.parse()?)?;
        Ok(Self {
            name: name.to_string(),
            sk: xprv.into(),
        })
    }

    /// Create a new key instance from a given name and private key bytes
    pub fn from_privkey_bytes(name: impl ToString, sk_bytes: &[u8]) -> Result<Self, KeyringError> {
        let sk = SigningKey::from_bytes(sk_bytes)?;
        Ok(Self {
            name: name.to_string(),
            sk,
        })
    }

    /// Return a reference to the private key
    pub fn privkey(&self) -> &SigningKey {
        &self.sk
    }

    /// Return the pubkey
    pub fn pubkey(&self) -> VerifyingKey {
        self.sk.verifying_key()
    }

    /// Sign an arbitrary byte array. The bytes are SHA-256 hashed before signing
    pub fn sign(&self, bytes: &[u8]) -> Signature {
        self.sk.sign(bytes)
    }
}

impl TryFrom<&Key> for JwtPayload {
    type Error = KeyringError;

    fn try_from(key: &Key) -> Result<Self, Self::Error> {
        let sk_str = hex::encode(key.sk.to_bytes().as_slice());
        let mut payload = JwtPayload::new();
        payload.set_claim("name", Some(key.name.clone().into()))?;
        payload.set_claim("sk", Some(sk_str.into()))?;
        Ok(payload)
    }
}

impl TryFrom<JwtPayload> for Key {
    type Error = KeyringError;

    fn try_from(payload: JwtPayload) -> Result<Self, Self::Error> {
        let name = payload
            .claim("name")
            .ok_or_else(|| KeyringError::malformed_payload("key `name` not found"))?
            .as_str()
            .ok_or_else(|| KeyringError::malformed_payload("incorrect JSON value type for `name`"))?;
        let sk_str = payload
            .claim("sk")
            .ok_or_else(|| KeyringError::malformed_payload("key `sk` not found"))?
            .as_str()
            .ok_or_else(|| KeyringError::malformed_payload("incorrect JSON value type for `sk`"))?;
        let sk_bytes = hex::decode(sk_str)?;
        Key::from_privkey_bytes(name, &sk_bytes)
    }
}
