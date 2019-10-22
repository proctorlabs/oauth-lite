use crate::login::LdapAuthenticator;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Default, Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub login: LdapAuthenticator,
    pub oauth: OauthOptions,
}

#[derive(Default, Debug, Serialize, Deserialize, Clone)]
pub struct OauthOptions {
    pub clients: HashMap<String, Client>,
}

#[derive(Default, Debug, Serialize, Deserialize, Clone)]
pub struct Client {
    pub url: String,
    pub scope: Option<String>,
}
