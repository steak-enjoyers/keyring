use std::path::PathBuf;

use bip32::{Language, Mnemonic};
use clap::Subcommand;
use rand::rngs::OsRng;

use crate::{print, prompt, Key, Keyring, KeyringError};

#[derive(Subcommand)]
pub enum KeysSubcmd {
    /// Add or recover a private key and save it to an encrypted file
    Add {
        /// A human-readable name of the key
        name: String,

        /// Provide seed phrase to recover an existing key instead of creating
        #[arg(long, default_value_t = false, action = clap::ArgAction::SetTrue)]
        recover: bool,

        /// BIP-44 coin type for HD derivation
        #[arg(long, default_value_t = 118)]
        coin_type: u32,
    },

    /// Delete a given key
    #[command(alias = "rm")]
    Delete {
        /// Name of the key to delete
        name: String,
    },

    /// Display details of a key
    Show {
        /// Name of the key to show
        name: String,
    },

    /// List all keys
    #[command(alias = "ls")]
    List,
}

impl KeysSubcmd {
    pub fn run(self, dir: PathBuf) -> Result<(), KeyringError> {
        let keyring = Keyring::new(dir)?;

        match self {
            KeysSubcmd::Add {
                name,
                recover,
                coin_type,
            } => {
                let mnemonic = if recover {
                    let phrase: String = prompt::input("enter your BIP-39 mnemonic")?;
                    println!("\n");
                    Mnemonic::new(phrase, Language::English)?
                } else {
                    Mnemonic::random(OsRng, Language::English)
                };

                let key = Key::from_mnemonic(name, &mnemonic, coin_type)?;
                keyring.set(&key)?;

                println!();
                print::key(&key)?;

                if !recover {
                    println!("\n**Important** write this mnemonic phrase in a safe place!");
                    println!("It is the only way to recover your account if you ever forget your password.");
                    println!();
                    print::mnemonic(mnemonic.phrase());
                }
            },

            KeysSubcmd::Show {
                name,
            } => {
                let key = keyring.get(&name)?;
                print::key(&key)?;
            },

            KeysSubcmd::List => {
                let keys = keyring.list()?;
                print::keys(&keys)?;
            },

            KeysSubcmd::Delete {
                name,
            } => keyring.delete(&name)?,
        }

        Ok(())
    }
}
