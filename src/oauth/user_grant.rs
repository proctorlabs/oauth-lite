use {
    super::*,
    crate::data::Persistable,
    chrono::prelude::*,
    oxide_auth::primitives::scope::Scope,
    serde::{Deserialize, Serialize},
    std::str::FromStr,
    url::Url,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct UserGrant {
    pub owner_id: String,
    pub client_id: String,
    pub scope: String,
    pub redirect_uri: Url,
    pub until: DateTime<Utc>,
}

impl Persistable for UserGrant {
    type ID = String;

    fn tree_name() -> &'static str {
        "grants"
    }

    fn id(&self) -> Self::ID {
        self.owner_id.to_string()
    }
}

impl From<Grant> for UserGrant {
    fn from(grant: Grant) -> Self {
        UserGrant {
            owner_id: grant.owner_id,
            client_id: grant.client_id,
            scope: grant.scope.to_string(),
            redirect_uri: grant.redirect_uri.to_string().parse().unwrap(),
            until: grant.until,
        }
    }
}

impl From<UserGrant> for Grant {
    fn from(grant: UserGrant) -> Self {
        Grant {
            owner_id: grant.owner_id,
            client_id: grant.client_id,
            scope: Scope::from_str(&grant.scope).unwrap(),
            redirect_uri: grant.redirect_uri.to_string().parse().unwrap(),
            until: grant.until,
            extensions: Default::default(),
        }
    }
}
