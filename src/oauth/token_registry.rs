use {
    super::UserGrant,
    crate::data::Persistable,
    chrono::prelude::*,
    oxide_auth::{
        endpoint::*,
        primitives::{grant::Grant, issuer::*},
    },
    serde::{Deserialize, Serialize},
};

#[derive(Clone)]
pub struct TokenRegistry;

impl Issuer for TokenRegistry {
    fn issue(&mut self, grant: Grant) -> Result<IssuedToken, ()> {
        let mut t = Tokens::from(&grant.owner_id)?;
        let new_token = IssuedToken {
            token: Tokens::gen_id(),
            refresh: Tokens::gen_id(),
            until: Utc::now()
                .checked_add_signed(chrono::Duration::seconds(3600))
                .unwrap(),
        };
        t.tokens.push((
            new_token.token.clone(),
            new_token.refresh.clone(),
            new_token.until,
        ));
        t.save()?;
        Ok(new_token)
    }

    fn recover_token<'a>(&'a self, token: &'a str) -> Result<Option<Grant>, ()> {
        let t = Tokens::access(token)?;
        let grant = match t {
            Some(t) => t.grant()?,
            None => None,
        };
        Ok(grant)
    }

    fn refresh(&mut self, refresh: &str, grant: Grant) -> Result<RefreshedToken, ()> {
        let mut t = Tokens::from(&grant.owner_id)?;
        let mut refreshed = Err(());
        for t in t.tokens.iter_mut() {
            if t.1 == refresh {
                t.0 = Tokens::gen_id();
                t.2 = Utc::now()
                    .checked_add_signed(chrono::Duration::seconds(3600))
                    .unwrap();
                refreshed = Ok(RefreshedToken {
                    token: t.0.to_string(),
                    refresh: Some(t.1.to_string()),
                    until: t.2,
                });
            }
        }
        t.save()?;
        refreshed
    }

    fn recover_refresh<'a>(&'a self, token: &'a str) -> Result<Option<Grant>, ()> {
        let t = Tokens::refresh(token)?;
        let grant = match t {
            Some(t) => t.grant()?,
            None => None,
        };
        debug!("{:?}", grant);
        Ok(grant)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Tokens {
    pub owner_id: String,
    pub authorizations: Vec<(String, DateTime<Utc>)>,
    pub tokens: Vec<(String, String, DateTime<Utc>)>,
}

impl Persistable for Tokens {
    type ID = String;

    fn tree_name() -> &'static str {
        "tokens"
    }

    fn id(&self) -> Self::ID {
        self.owner_id.to_string()
    }
}

impl Tokens {
    pub fn from(owner: &str) -> crate::Result<Self> {
        let t = Self::get(owner.to_string())?;
        Ok(match t {
            Some(t) => t.clean(),
            None => Tokens {
                owner_id: owner.to_string(),
                authorizations: vec![],
                tokens: vec![],
            },
        })
    }

    fn clean(mut self) -> Self {
        let now = Utc::now();
        self.authorizations.retain(|t| now < t.1);
        self
    }

    pub fn grant(&self) -> crate::Result<Option<Grant>> {
        let ug = UserGrant::get(self.id())?;
        Ok(ug.map(|u| u.into()))
    }

    pub fn authorize(token: &str) -> crate::Result<Option<Tokens>> {
        let t = Tokens::find(|t| {
            for t in t.authorizations.iter() {
                if t.0 == token {
                    return true;
                }
            }
            false
        });
        t.map(|t| {
            t.map(|t| {
                t.delete().unwrap_or_default();
                t
            })
        })
    }

    pub fn access(token: &str) -> crate::Result<Option<Tokens>> {
        let now = Utc::now();
        Tokens::find(|t| {
            for t in t.tokens.iter() {
                if t.0 == token && now < t.2 {
                    return true;
                }
            }
            false
        })
    }

    pub fn refresh(token: &str) -> crate::Result<Option<Tokens>> {
        Tokens::find(|t| {
            for t in t.tokens.iter() {
                if t.1 == token {
                    return true;
                }
            }
            false
        })
    }
}
