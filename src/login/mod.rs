use crate::error::*;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

mod ldap;

pub use ldap::LdapAuthenticator;

pub trait Authenticator {
    fn login(&self, user: &str, password: &str) -> Result<User>;
}

#[derive(Default, Debug, Serialize, Deserialize, Clone)]
pub struct User {
    username: String,
    attributes: Vec<(String, Vec<String>)>,
}

lazy_static! {
    static ref AUTH: RwLock<LdapAuthenticator> = Default::default();
}

pub fn set_authenticator(new: LdapAuthenticator) {
    let mut old = AUTH.write();
    *old = new;
}

pub fn login(path: &str, password: &str) -> Result<User> {
    AUTH.read().login(path, password)
}
