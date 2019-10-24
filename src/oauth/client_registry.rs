use {
    oxide_auth::{
        endpoint::*,
        primitives::{prelude::*, registrar::*},
    },
    parking_lot::Mutex,
    std::sync::Arc,
};

#[derive(Clone)]
pub struct ClientRegistry(pub Arc<Mutex<ClientMap>>);

impl Registrar for ClientRegistry {
    fn bound_redirect<'a>(&self, bound: ClientUrl<'a>) -> Result<BoundClient<'a>, RegistrarError> {
        debug!("Bound redirect from client registry");
        match self.0.lock().bound_redirect(bound) {
            Ok(r) => {
                debug!("Bound redirect request: {:?}", r);
                Ok(r)
            }
            Err(e) => {
                debug!("Error from bound redirect: {:?}", e);
                Err(e)
            }
        }
    }

    fn negotiate(
        &self,
        client: BoundClient,
        scope: Option<Scope>,
    ) -> Result<PreGrant, RegistrarError> {
        debug!("Negotiation request from client registry");
        self.0.lock().negotiate(client, scope)
    }

    fn check(&self, client_id: &str, passphrase: Option<&[u8]>) -> Result<(), RegistrarError> {
        debug!("Check request from client registry");
        self.0.lock().check(client_id, passphrase)
    }
}
