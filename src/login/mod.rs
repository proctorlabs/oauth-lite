use crate::error::*;
use serde::{Deserialize, Serialize};

mod ldap;

pub use crate::args::LdapAuthenticator;

pub trait Authenticator {
    fn login(&self, user: &str, password: &str) -> Result<User>;
}

#[derive(Default, Debug, Serialize, Deserialize, Clone)]
pub struct User {
    username: String,
    attributes: Vec<(String, Vec<String>)>,
}

lazy_static! {
    static ref AUTH: &'static LdapAuthenticator = &crate::CONFIG.login;
}

pub fn login(path: &str, password: &str) -> Result<User> {
    AUTH.login(path, password)
}
