use {super::*, crate::data::Persistable, chrono::prelude::*};

#[derive(Clone)]
pub struct AuthorizationRegistry;

impl Authorizer for AuthorizationRegistry {
    fn authorize(&mut self, grant: Grant) -> Result<String, ()> {
        let mut token = Tokens::from(&grant.owner_id)?;
        let new_token = Tokens::gen_id();
        token.authorizations.push((
            new_token.to_string(),
            Utc::now()
                .checked_add_signed(chrono::Duration::seconds(3600))
                .unwrap(),
        ));
        token.save()?;
        UserGrant::from(grant).save()?;
        Ok(new_token)
    }

    fn extract(&mut self, token: &str) -> Result<Option<Grant>, ()> {
        let t = Tokens::authorize(token)?;
        let res = match t {
            Some(t) => t.grant()?,
            None => None,
        };
        Ok(res)
    }
}
