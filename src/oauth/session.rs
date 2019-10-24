use {
    crate::{data::*, login::User, *},
    serde::{Deserialize, Serialize},
    std::time::SystemTime,
};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SessionData {
    pub id: String,
    pub user: Option<User>,
    pub ts: u128,
}

impl Default for SessionData {
    fn default() -> Self {
        SessionData {
            id: Self::gen_id(),
            user: Default::default(),
            ts: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        }
    }
}

impl Persistable for SessionData {
    type ID = String;

    fn tree_name() -> &'static str {
        "sessions"
    }

    fn id(&self) -> Self::ID {
        self.id.to_string()
    }
}

impl SessionData {
    pub fn logged_in(&self) -> bool {
        self.user.is_some()
    }

    pub fn get_cookie(c: &'_ str) -> Result<Option<Self>> {
        debug!("Raw cookie: {}", c);
        let c = percent_encoding::percent_decode_str(c)
            .decode_utf8()
            .unwrap()
            .to_string();
        let parts: Vec<&str> = c.split('.').collect();
        if parts.len() != 2 {
            return Ok(None);
        }

        let (id, signature) = (parts[0], parts[1]);
        let result = Self::get(id.to_string())?;
        if let Some(ref r) = result {
            debug!("Using existing cookie: {:?}", r);
            if let Err(e) = r.verify(signature) {
                warn!("Cookie validation failed for {:?}", parts);
                return Err(e);
            }
        } else {
            debug!("No session found matching cookie!");
        }
        Ok(result)
    }

    pub fn new(user: Option<User>) -> Result<Self> {
        let mut res = SessionData::default();
        res.user = user;
        res.save()?;
        Ok(res)
    }

    pub fn update(&mut self) -> Result<()> {
        self.ts = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        self.save()?;
        Ok(())
    }

    pub fn cookie_string(&self) -> Result<String> {
        let val = self.signed_token()?;
        let c = cookie::Cookie::build("SID", val)
            .http_only(true)
            .path("/")
            .permanent()
            .finish();
        Ok(c.to_string())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn check_signing() -> Result<()> {
        println!("Key: {}", base64::encode(&key()?));
        let session = SessionData::new(None)?;
        let signature = session.sign()?;
        println!("Signature: {}", signature);
        session.verify(&signature)?;
        let val = format!("{}.{}", session.id, session.sign()?);
        println!("{:?}", SessionData::get_cookie(&val));
        let f = SessionData::delete_all(|sd| sd.id == session.id);
        println!("Cleaned session: {:?}", f);
        Ok(())
    }
}
