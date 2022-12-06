use std::{fs, path::PathBuf};

use colored::Colorize;
use josekit::{jwe, jwt};

use crate::{prompt, Key, KeyringError};

pub struct Keyring {
    /// Path to the directory where encrypted key files are stored.
    pub dir: PathBuf,
}

impl Keyring {
    /// Create a new keyring under the given directory.
    pub fn new(dir: PathBuf) -> Result<Self, KeyringError> {
        if !dir.exists() {
            fs::create_dir_all(&dir)?;
        }
        Ok(Self {
            dir,
        })
    }

    /// Return the string representation of the keys directory.
    pub fn dir(&self) -> Result<String, KeyringError> {
        self.dir
            .clone()
            .into_os_string()
            .into_string()
            .map_err(|_| KeyringError::StringifyPathFailed)
    }

    /// Return the path to the key file corresponding to the key's name.
    pub fn filename(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{name}.key"))
    }

    /// Return the path to the password hash file.
    pub fn password_hash(&self) -> PathBuf {
        self.dir.join("password_hash")
    }

    /// Unlock the keyring, return the password.
    /// Firstly, check whether a password hash file already exists:
    /// - If yes, prompt the user to enter the password, and check against the hash file;
    /// - If not, prompt the user to enter a new password, and save the hash to the file;
    pub fn unlock(&self) -> Result<String, KeyringError> {
        let password_hash_path = self.password_hash();
        if password_hash_path.exists() {
            let password = prompt::password(format!(
                "{} `{}`",
                "🔑 Enter the password to unlock keyring".bold(),
                self.dir()?,
            ))?;

            let password_hash_bytes = fs::read(&password_hash_path)?;
            let password_hash = String::from_utf8(password_hash_bytes)?;

            if bcrypt::verify(&password, &password_hash)? {
                Ok(password)
            } else {
                Err(KeyringError::IncorrectPassword)
            }
        } else {
            let password = prompt::password(format!(
                "{} `{}`",
                "🔑 Enter a password to encrypt the keyring".bold(),
                self.dir()?,
            ))?;

            let repeated_password = prompt::password(format!(
                "{}",
                "🔑 Repeat the password".bold(),
            ))?;

            if password != repeated_password {
                return Err(KeyringError::MismatchedPassword);
            }

            // Go SDK uses a difficult of 2
            // We use 4 here which is smallest value allowed by the bcrypt library
            let password_hash = bcrypt::hash(&password, 4)?;
            fs::write(&password_hash_path, password_hash)?;

            Ok(password)
        }
    }

    /// Save a key in the keyring
    pub fn set(&self, key: &Key) -> Result<(), KeyringError> {
        let filename = self.filename(&key.name);
        if filename.exists() {
            return Err(KeyringError::key_already_exists(&key.name));
        }

        // header
        // these are copied from the tutorial. not sure if i'm using the correct values
        let mut header = jwe::JweHeader::new();
        header.set_token_type("JWT");
        header.set_algorithm("PBES2-HS256+A128KW");
        header.set_content_encryption("A128CBC-HS256");

        // cast key into JWT payload
        let payload = key.try_into()?;

        // encrypt { header, payload } into token
        let password = self.unlock()?;
        let encrypter = jwe::PBES2_HS256_A128KW.encrypter_from_bytes(password)?;
        let token = jwt::encode_with_encrypter(&payload, &header, &encrypter)?;

        // save the token to file
        fs::write(filename, token)?;

        Ok(())
    }

    /// Read binary data stored in the keyring with the given name
    pub fn get(&self, name: &str) -> Result<Key, KeyringError> {
        // load the file
        let token = {
            let filename = self.filename(name);
            if !filename.exists() {
                return Err(KeyringError::key_not_found(name));
            }
            fs::read(&filename)?
        };

        // decrypt { header, payload } from token
        let password = self.unlock()?;
        let decrypter = jwe::PBES2_HS256_A128KW.decrypter_from_bytes(password.as_bytes())?;
        let (payload, _) = jwt::decode_with_decrypter(token, &decrypter)?;

        // recover key from payload
        payload.try_into().map_err(KeyringError::from)
    }

    /// Read binary data of all keys stored in the keyring
    pub fn list(&self) -> Result<Vec<Key>, KeyringError> {
        let password = self.unlock()?;
        let decrypter = jwe::PBES2_HS256_A128KW.decrypter_from_bytes(password.as_bytes())?;

        self.dir
            .read_dir()?
            .map(|entry| {
                let entry = entry?;
                let token = fs::read(entry.path())?;
                let (payload, _) = jwt::decode_with_decrypter(token, &decrypter)?;
                payload.try_into().map_err(KeyringError::from)
            })
            .filter(|res| res.is_ok())
            .collect()
    }

    /// Delete a key
    pub fn delete(&self, name: &str) -> Result<(), KeyringError> {
        let filename = self.filename(name);
        if filename.exists() {
            fs::remove_file(filename).map_err(KeyringError::from)
        } else {
            Err(KeyringError::key_not_found(name))
        }
    }
}
