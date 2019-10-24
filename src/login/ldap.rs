use super::*;
use crate::args::LdapAuthenticator;
use ldap3::{LdapConn, Scope, SearchEntry};

impl Authenticator for LdapAuthenticator {
    fn login(&self, path: &str, password: &str) -> Result<User> {
        // The ldap3 library is based on a deprecated version of tokio
        // As a result, it must be run in a different thread
        // This could be optimized by using channels, but this works for now
        let path = path.to_string();
        let password = password.to_string();
        let zelf = self.clone();
        std::thread::spawn(move || {
            let ldap = LdapConn::new(&zelf.url)?;
            let login_path = format!("{}={},{}", zelf.user_dn, path, zelf.bind_dn);
            ldap.simple_bind(&login_path, &password)?.success()?;
            let (rs, _) = ldap
                .search(&login_path, Scope::Base, "(objectClass=*)", vec!["*"])?
                .success()?;
            let mut user = User {
                username: path,
                attributes: Default::default(),
            };
            for item in rs.into_iter() {
                let entry = SearchEntry::construct(item);
                for attr in entry.attrs.into_iter() {
                    if zelf.attrs.contains(&attr.0) {
                        user.attributes.push((attr.0, attr.1));
                    }
                }
            }
            Ok(user)
        })
        .join()
        .unwrap()
    }
}
