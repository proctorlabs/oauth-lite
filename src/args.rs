use clap::AppSettings::*;
use log::Level;
use std::error::Error;
use structopt::StructOpt;

lazy_static! {
    pub static ref CONFIG: Config = { Config::from_args() };
}

#[derive(Default, StructOpt, Debug, Clone)]
#[structopt(
    name = "oauth-lite",
    about = "Lightweight OAuth2 provider for simple use cases",
    author,
    about,
    rename_all = "kebab-case",
    settings = &[UnifiedHelpMessage, NextLineHelp, DeriveDisplayOrder]
)]
pub struct Config {
    #[structopt(flatten)]
    pub general: GeneralOptions,
    #[structopt(flatten)]
    pub oauth: OauthOptions,
    #[structopt(flatten)]
    pub login: LdapAuthenticator,
}

#[derive(Debug, Clone, StructOpt)]
#[structopt(rename_all = "kebab-case")]
pub struct GeneralOptions {
    /// Logging level to use
    #[structopt(short, long, default_value = "Info")]
    pub log: Level,
}

impl Default for GeneralOptions {
    fn default() -> Self {
        GeneralOptions { log: Level::Info }
    }
}

#[derive(Default, Debug, Clone, StructOpt)]
#[structopt(rename_all = "kebab-case")]
pub struct OauthOptions {
    /// Enable the pass-through URL for direct usage with a reverse proxy
    #[structopt(
        short,
        long = "oauth-enable-passthrough",
        env = "OAUTH_ENABLE_PASSTHROUGH"
    )]
    pub enable_passthrough: bool,

    /// Enable the pass-through URL for direct usage with a reverse proxy
    #[structopt(long = "oauth-passthrough-domains", env = "OAUTH_PASSTHROUGH_DOMAINS")]
    pub pass_through_domains: Vec<String>,

    /// Define the client IDs and their redirect URLs
    #[structopt(
        short,
        long = "oauth-client-ids",
        parse(try_from_str = parse_key_val),
        number_of_values = 1,
        env = "OAUTH_CLIENT_IDS"
    )]
    pub client_ids: Vec<(String, String)>,
}

#[derive(Default, Debug, Clone, StructOpt)]
#[structopt(rename_all = "kebab-case")]
pub struct LdapAuthenticator {
    /// Set the URL string for the LDAP server
    #[structopt(
        long = "ldap-url",
        default_value = "ldap://localhost:389",
        env = "LDAP_URL"
    )]
    pub url: String,

    /// Set the LDAP group/domain to search for users under    
    #[structopt(
        long = "ldap-bind-dn",
        default_value = "ou=users,dc=example,dc=com",
        env = "LDAP_BIND_DN"
    )]
    pub bind_dn: String,

    /// Set the LDAP DN to set the username under when attempting to authenticate
    #[structopt(long = "ldap-user-dn", default_value = "cn", env = "LDAP_USER_DN")]
    pub user_dn: String,

    /// List of user's LDAP attributes to store in the user session
    #[structopt(long = "ldap-attrs", env = "LDAP_ATTRIBUTES")]
    pub attrs: Vec<String>,
}

fn parse_key_val<T, U>(s: &str) -> std::result::Result<(T, U), Box<dyn Error>>
where
    T: std::str::FromStr,
    T::Err: Error + 'static,
    U: std::str::FromStr,
    U::Err: Error + 'static,
{
    let pos = s
        .find('=')
        .ok_or_else(|| format!("invalid KEY=value: no `=` found in `{}`", s))?;
    Ok((s[..pos].parse()?, s[pos + 1..].parse()?))
}
