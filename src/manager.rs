use crate::encryption::EncryptionManager;

pub struct PasswordManager<State = Locked> {
    master_pass: String,
    encryption_manager: EncryptionManager,
    passwords: Vec<PasswordEntryBytes>,
    state: std::marker::PhantomData<State>,
}

pub struct Locked;

pub struct Unlocked;

impl PasswordManager<Locked> {
    pub fn new(master_pass: impl Into<String>) -> Self {
        Self {
            master_pass: master_pass.into(),
            encryption_manager: EncryptionManager::new(),
            passwords: Vec::with_capacity(512),
            state: std::marker::PhantomData::<Locked>,
        }
    }
    pub fn unlock(self) -> Option<PasswordManager<Unlocked>> {
        Some(PasswordManager {
            master_pass: self.master_pass,
            encryption_manager: self.encryption_manager,
            passwords: self.passwords,
            state: std::marker::PhantomData::<Unlocked>,
        })
    }
}

impl PasswordManager<Unlocked> {
    pub fn list_passwords(&self) -> Vec<PasswordEntry> {
        self.passwords
            .iter()
            .map(|x| {
                let username = self
                    .encryption_manager
                    .decrypt(x.username.as_ref())
                    .expect("");
                let password = self
                    .encryption_manager
                    .decrypt(x.password.as_ref())
                    .expect("");
                PasswordEntry {
                    username: String::from_utf8(username).expect(""),
                    password: String::from_utf8(password).expect(""),
                }
            })
            .collect()
    }
    pub fn add_password(&mut self, entry: PasswordEntry) {
        let entry_bytes = PasswordEntryBytes {
            username: self
                .encryption_manager
                .encrypt(entry.username.as_bytes())
                .expect(""),
            password: self
                .encryption_manager
                .encrypt(entry.password.as_bytes())
                .expect(""),
        };

        self.passwords.push(entry_bytes);
    }
    pub fn lock(mut self) -> PasswordManager<Locked> {
        PasswordManager {
            master_pass: self.master_pass,
            encryption_manager: self.encryption_manager,
            passwords: self.passwords,
            state: std::marker::PhantomData::<Locked>,
        }
    }
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct PasswordEntry {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Eq, Hash, PartialEq)]
pub struct PasswordEntryBytes {
    username: Vec<u8>,
    password: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_succeed() {
        let manager = PasswordManager::new("balls");
        let mut manager = manager.unlock();

        let entry = PasswordEntry {
            username: "user".to_string(),
            password: "pass".to_string(),
        };
        manager.add_password(entry.clone());

        let entries = manager.list_passwords();
        assert_eq!(entries[0], entry);
        let _ = manager.lock();
    }
}
