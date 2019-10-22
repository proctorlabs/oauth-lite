use {
    super::*,
    crate::Error,
    oxide_auth::{
        endpoint::*, frontends::simple::endpoint::*, primitives::authorizer::*,
        primitives::issuer::*, primitives::prelude::*, primitives::registrar::*,
    },
    parking_lot::Mutex,
    std::{collections::HashMap, sync::Arc},
    warp::http::Uri,
};

pub use oxide_auth::primitives::grant::Grant;

lazy_static! {
    static ref CLIENT_MAP: ClientReg = ClientReg(Arc::new(Mutex::new(ClientMap::new())));
    static ref AUTH_MAP: AuthReg =
        AuthReg(Arc::new(Mutex::new(AuthMap::new(RandomGenerator::new(16)))));
    static ref ISSUER: TokenReg = TokenReg(Arc::new(Mutex::new(TokenMap::new(
        RandomGenerator::new(32)
    ))));
}

pub struct OAuthEndpoint {
    auth_map: AuthReg,
    issuer: TokenReg,
    solicitor: Box<dyn OwnerSolicitor<AuthRequest>>,
}

impl OAuthEndpoint {
    fn new() -> Self {
        OAuthEndpoint {
            auth_map: AUTH_MAP.clone(),
            issuer: ISSUER.clone(),
            solicitor: Box::new(FnSolicitor(solicitor)),
        }
    }

    pub fn access_token(req: AuthRequest) -> Result<AuthResponse, Error> {
        let mut ep = Self::new();
        access_token_flow(&*CLIENT_MAP, &mut ep.auth_map, &mut ep.issuer)
            .execute(req.clone())
            .map_err(|_| Error::Authentication("Authentication failure occurred".into()))
            .map(|r| r.with_request(req))
    }

    pub fn resource(req: AuthRequest) -> Result<Grant, Error> {
        let mut ep = Self::new();
        resource_flow(&mut ep.issuer, &[])
            .execute(req.clone())
            .map_err(|_| Error::Authentication("Authentication failure occurred".into()))
        //.map(|r| r.with_request(req))
    }

    pub fn authorize(req: AuthRequest) -> Result<AuthResponse, Error> {
        let mut ep = Self::new();
        authorization_flow(&*CLIENT_MAP, &mut ep.auth_map, &mut ep.solicitor)
            .execute(req.clone())
            .map_err(|_| Error::Authentication("Authentication failure occurred".into()))
            .map(|r| r.with_request(req))
    }

    pub fn refresh(req: AuthRequest) -> Result<AuthResponse, Error> {
        let mut ep = Self::new();
        refresh_flow(&*CLIENT_MAP, &mut ep.issuer)
            .execute(req.clone())
            .map_err(|_| Error::Authentication("Authentication failure occurred".into()))
            .map(|r| r.with_request(req))
    }

    pub fn add_clients(clients: HashMap<String, crate::config::Client>) {
        for (k, v) in clients.into_iter() {
            let new_client = Client::public(
                k.as_str(),
                v.url.parse().unwrap(),
                v.scope
                    .unwrap_or_else(|| "default".to_string())
                    .parse()
                    .unwrap(),
            );
            CLIENT_MAP.0.lock().register_client(new_client);
        }
    }
}

fn solicitor(req: &mut AuthRequest, _: &PreGrant) -> OwnerConsent<AuthResponse> {
    let mut failed = false;
    let mut sd = req.0.session.lock();
    if sd.logged_in() {
        return OwnerConsent::Authorized(sd.id.clone());
    }
    if let Some(body) = &req.0.urlbody {
        if let (Some(username), Some(password)) = (body.get("login"), body.get("password")) {
            match crate::login::login(username, password) {
                Ok(user) => {
                    sd.user = Some(user);
                    return OwnerConsent::Authorized(sd.id.clone());
                }
                Err(e) => {
                    warn!("Login attempt failed! {}", e);
                    failed = true;
                }
            }
        }
    }
    drop(sd); //Drop the lock before calling this
    redirect_to_login(failed, &req)
}

fn redirect_to_login(_: bool, req: &AuthRequest) -> OwnerConsent<AuthResponse> {
    let mut builder = Uri::builder();
    let root_path = "/";
    if !req.0.query.is_empty() {
        let path = format!(
            "{}?{}",
            root_path,
            req.0
                .query
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<String>>()
                .join("&")
        );
        builder.path_and_query(path.as_str());
    } else {
        builder.path_and_query(root_path);
    }
    let response = AuthResponse {
        status: 303,
        session: None,
        body: None,
        location: Some(builder.build().unwrap().to_string()),
        content_type: None,
        www_authenticate: None,
    };
    OwnerConsent::InProgress(response)
}

#[derive(Clone)]
struct ClientReg(Arc<Mutex<ClientMap>>);

impl Registrar for ClientReg {
    fn bound_redirect<'a>(&self, bound: ClientUrl<'a>) -> Result<BoundClient<'a>, RegistrarError> {
        self.0.lock().bound_redirect(bound)
    }

    fn negotiate(
        &self,
        client: BoundClient,
        scope: Option<Scope>,
    ) -> Result<PreGrant, RegistrarError> {
        self.0.lock().negotiate(client, scope)
    }

    fn check(&self, client_id: &str, passphrase: Option<&[u8]>) -> Result<(), RegistrarError> {
        self.0.lock().check(client_id, passphrase)
    }
}

#[derive(Clone)]
struct TokenReg(Arc<Mutex<TokenMap<RandomGenerator>>>);

impl Issuer for TokenReg {
    fn issue(&mut self, grant: Grant) -> Result<IssuedToken, ()> {
        self.0.lock().issue(grant)
    }

    fn refresh(&mut self, refresh: &str, grant: Grant) -> Result<RefreshedToken, ()> {
        self.0.lock().refresh(refresh, grant)
    }

    fn recover_token<'a>(&'a self, s: &'a str) -> Result<Option<Grant>, ()> {
        self.0.lock().recover_token(s)
    }

    fn recover_refresh<'a>(&'a self, s: &'a str) -> Result<Option<Grant>, ()> {
        self.0.lock().recover_refresh(s)
    }
}

#[derive(Clone)]
struct AuthReg(Arc<Mutex<AuthMap<RandomGenerator>>>);

impl Authorizer for AuthReg {
    fn authorize(&mut self, grant: Grant) -> Result<String, ()> {
        self.0.lock().authorize(grant)
    }

    fn extract(&mut self, token: &str) -> Result<Option<Grant>, ()> {
        self.0.lock().extract(token)
    }
}
