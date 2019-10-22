use {
    crate::{login::User, oauth::SessionData, *},
    hmac::crypto_mac::Mac,
    hmac::Hmac,
    rand::{rngs::OsRng, RngCore},
    serde::{de::DeserializeOwned, Serialize},
    sha2::Sha256,
    sled::Db,
    std::time::SystemTime,
};

type HmacSha256 = Hmac<Sha256>;

lazy_static! {
    static ref DB: Db = Db::open(".oauth.dat").unwrap();
    static ref KEY: Vec<u8> = { inner_key().unwrap() };
}

const SERVER_TREE: &str = "server";
const KEY_FIELD: &str = "signing";

pub fn key() -> Result<Vec<u8>> {
    Ok(KEY.clone())
}

fn inner_key() -> Result<Vec<u8>> {
    let tree = DB.open_tree(SERVER_TREE)?;
    let k = match tree.get(KEY_FIELD)? {
        Some(k) => k.to_vec(),
        None => {
            warn!("Key not found, generating new key");
            let mut key = [0u8; 32];
            OsRng.fill_bytes(&mut key);
            let key = key.to_vec();
            tree.insert(KEY_FIELD, key.clone())?;
            tree.flush()?;
            key
        }
    };

    Ok(k)
}

pub fn sign<T: Serialize>(obj: &T) -> Result<String> {
    let data = serde_json::to_vec(obj)?;
    let key = key()?;
    let mut hm = HmacSha256::new_varkey(&key)?;
    hm.input(&data);
    let res = hm.result().code();
    Ok(base64::encode(&res))
}

pub fn verify<T: Serialize>(obj: &T, code: &str) -> Result<()> {
    let data = serde_json::to_vec(obj)?;
    let key = key()?;
    let mut hm = HmacSha256::new_varkey(&key)?;
    hm.input(&data);
    let code = base64::decode(&code).unwrap_or_default();
    hm.verify(&code)?;
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn check_signing() -> Result<()> {
        println!("Key: {}", base64::encode(&key()?));
        let session = SessionData::new(None)?;
        let signature = sign(&session)?;
        println!("Signature: {}", signature);
        verify(&session, &signature)?;
        let val = format!("{}.{}", session.id, sign(&session)?);
        println!("{:?}", SessionData::get_cookie(&val));
        Ok(())
    }
}

fn get<O: DeserializeOwned, T: Serialize>(tree: &'_ str, id: T) -> Result<Option<O>> {
    let tree = DB.open_tree(tree)?;
    let key = serde_json::to_vec(&id)?;
    let data: Option<O> = tree
        .get(&key)?
        .map(|i| serde_json::from_slice(i.as_ref()).unwrap());
    Ok(data)
}

fn set<T: Serialize, U: Serialize>(tree: &'_ str, id: T, item: U) -> Result<()> {
    let tree = DB.open_tree(tree)?;
    let key = serde_json::to_vec(&id)?;
    let val = serde_json::to_vec(&item)?;
    tree.insert(key, val)?;
    tree.flush()?;
    Ok(())
}

impl SessionData {
    pub fn get_cookie(c: &'_ str) -> Result<Option<Self>> {
        info!("raw: {}", c);
        let c = percent_encoding::percent_decode_str(c)
            .decode_utf8()
            .unwrap()
            .to_string();
        let parts: Vec<&str> = c.split('.').collect();
        if parts.len() != 2 {
            return Ok(None);
        }

        let (id, signature) = (parts[0], parts[1]);
        let result = Self::get_id(id)?;
        if let Some(ref r) = result {
            if let Err(e) = verify(r, signature) {
                warn!("Cookie validation failed for {:?}", parts);
                return Err(e);
            }
        }

        info!("Retrieved: {:?}", result);
        Ok(result)
    }

    pub fn get_id(id: &'_ str) -> Result<Option<Self>> {
        let result = get("sessions", id)?;
        info!("Retrieved: {:?}", result);
        Ok(result)
    }

    pub fn new(user: Option<User>) -> Result<Self> {
        let mut res = SessionData::default();
        res.user = user;
        let data = res.clone();
        set("sessions", data.id.to_string(), data)?;
        debug!("Created: {:?}", res);
        Ok(res)
    }

    pub fn update(&mut self) -> Result<()> {
        self.ts = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        set("sessions", self.id.to_string(), self.clone())?;
        debug!("Saved: {:?}", self);
        debug!("Signature: {:?}", sign(self)?);
        Ok(())
    }

    pub fn cookie_string(&self) -> Result<String> {
        let val = format!("{}.{}", self.id, sign(self)?);
        let c = cookie::Cookie::build("SID", val).http_only(true).finish();
        Ok(c.to_string())
    }
}
