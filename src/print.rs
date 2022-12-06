use serde::Serialize;

use crate::{Key, KeyringError};

pub(crate) fn mnemonic(phrase: &str) {
    let words = phrase.split(' ').collect::<Vec<_>>();
    let word_amount = words.len();
    let mut start = 0usize;
    while start < word_amount {
        let end = (start + 4).min(word_amount);
        let slice = words[start..end]
            .iter()
            .map(|word| format!("{word: >8}"))
            .collect::<Vec<_>>()
            .join(" ");
        println!("{: >2} - {end: >2}  {slice}", start + 1);
        start = end;
    }
}

pub(crate) fn key(key: &Key) -> Result<(), KeyringError> {
    json(PrintableKey::from(key))
}

pub(crate) fn keys(keys: &[Key]) -> Result<(), KeyringError> {
    json(keys
        .iter()
        .map(PrintableKey::from)
        .collect::<Vec<_>>())
}

fn json(data: impl serde::Serialize) -> Result<(), KeyringError> {
    let data_str = serde_json::to_string_pretty(&data)?;
    println!("{data_str}");
    Ok(())
}

#[derive(Serialize)]
struct PrintableKey<'a> {
    pub name: &'a str,
    pub pubkey: String, // hex-encoded bytearray
}

impl<'a> From<&'a Key> for PrintableKey<'a> {
    fn from(key: &'a Key) -> Self {
        Self {
            name: &key.name,
            pubkey: hex::encode(key.pubkey().to_bytes().as_slice()),
        }
    }
}
