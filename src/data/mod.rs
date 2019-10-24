use {
    crate::*,
    hmac::crypto_mac::Mac,
    hmac::Hmac,
    rand::{rngs::OsRng, RngCore},
    serde::{de::DeserializeOwned, Serialize},
    sha2::Sha256,
    sled::Db,
};

type HmacSha256 = Hmac<Sha256>;

lazy_static! {
    static ref DB: Db = {
        sled::Config::default()
            .path(".oauth.dat")
            .flush_every_ms(Some(1000))
            .open()
            .unwrap()
    };
    static ref KEY: Vec<u8> = { inner_key().unwrap() };
}

const SERVER_TREE: &str = "server";
const KEY_FIELD: &str = "signing";

pub fn key() -> Result<Vec<u8>> {
    Ok(KEY.clone())
}

pub fn clean() -> Result<()> {
    DB.flush()?;
    Ok(())
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
            key
        }
    };

    Ok(k)
}

pub trait Persistable: DeserializeOwned + Serialize + std::fmt::Debug
where
    Self::ID: std::fmt::Display,
{
    type ID;

    fn tree_name() -> &'static str;
    fn id(&self) -> Self::ID;

    fn gen_id() -> String {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        base64::encode(&key)
    }

    fn get(id: Self::ID) -> Result<Option<Self>> {
        let tree = DB.open_tree(Self::tree_name())?;
        let key = id.to_string();
        let data: Option<Self> = tree
            .get(&key)?
            .map(|i| serde_json::from_slice(i.as_ref()).unwrap());
        debug!("Retrieved: {:?}", data);
        Ok(data)
    }

    fn find<F: Fn(&Self) -> bool>(q: F) -> Result<Option<Self>> {
        let tree = DB.open_tree(Self::tree_name())?;
        for val in tree.iter() {
            let (_, v) = val?;
            let obj = serde_json::from_slice(v.as_ref());
            if let Ok(o) = obj {
                if q(&o) {
                    debug!("Object found: {:?}", o);
                    return Ok(Some(o));
                }
            }
        }
        debug!("Not found");
        Ok(None)
    }

    fn find_all<F: Fn(&Self) -> bool>(q: F) -> Result<Vec<Self>> {
        let tree = DB.open_tree(Self::tree_name())?;
        let mut result = vec![];
        for val in tree.iter() {
            let (_, v) = val?;
            let obj = serde_json::from_slice(v.as_ref());
            if let Ok(o) = obj {
                if q(&o) {
                    result.push(o);
                }
            }
        }
        Ok(result)
    }

    fn save(&self) -> Result<()> {
        let tree = DB.open_tree(Self::tree_name())?;
        let id = self.id();
        let key = id.to_string();
        let val = serde_json::to_vec(self)?;
        tree.insert(key, val)?;
        tree.flush()?;
        debug!("Saved: {:?}", self);
        Ok(())
    }

    fn delete(&self) -> Result<Option<Self>> {
        let tree = DB.open_tree(Self::tree_name())?;
        let id = self.id();
        let key = id.to_string();
        let res = tree
            .remove(key)?
            .map(|i| serde_json::from_slice(i.as_ref()).unwrap());
        tree.flush()?;
        debug!("Deleted: {:?}", res);
        Ok(res)
    }

    fn delete_all<F: Fn(&Self) -> bool>(q: F) -> Result<u64> {
        let tree = DB.open_tree(Self::tree_name())?;
        let mut count = 0;
        for val in tree.iter() {
            let (k, v) = val?;
            let obj = serde_json::from_slice(v.as_ref());
            if let Ok(o) = obj {
                if q(&o) {
                    tree.remove(k)?;
                    count += 1;
                }
            } else {
                tree.remove(k)?;
                count += 1;
            }
        }
        Ok(count)
    }

    fn sign(&self) -> Result<String> {
        let data = serde_json::to_vec(self)?;
        let key = key()?;
        let mut hm = HmacSha256::new_varkey(&key)?;
        hm.input(&data);
        let res = hm.result().code();
        Ok(base64::encode(&res))
    }

    fn signed_token(&self) -> Result<String> {
        Ok(format!("{}.{}", self.id(), self.sign()?))
    }

    fn verify(&self, code: &str) -> Result<()> {
        let data = serde_json::to_vec(self)?;
        let key = key()?;
        let mut hm = HmacSha256::new_varkey(&key)?;
        hm.input(&data);
        let code = base64::decode(&code).unwrap_or_default();
        hm.verify(&code)?;
        Ok(())
    }
}
