use {
    super::*,
    crate::{data::Persistable, Error},
    oxide_auth::{frontends::simple::endpoint::*, primitives::prelude::*},
    parking_lot::Mutex,
    std::{str::FromStr, sync::Arc},
    warp::http::Uri,
};

pub use oxide_auth::primitives::grant::Grant;

lazy_static! {
    static ref CLIENT_MAP: ClientRegistry = ClientRegistry(Arc::new(Mutex::new(ClientMap::new())));
    static ref SCOPE: Vec<Scope> = vec![Scope::from_str("default").unwrap()];
}

pub struct OAuthEndpoint {
    auth_map: AuthorizationRegistry,
    issuer: TokenRegistry,
    solicitor: Box<dyn OwnerSolicitor<AuthRequest>>,
}

impl OAuthEndpoint {
    fn new() -> Self {
        OAuthEndpoint {
            auth_map: AuthorizationRegistry,
            issuer: TokenRegistry,
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

    pub fn resource(req: AuthRequest) -> Result<AuthResponse, Error> {
        let mut ep = Self::new();

        Ok(AuthResponse::from(
            resource_flow(&mut ep.issuer, &SCOPE)
                .execute(req.clone())
                .map_err(|_| Error::Authentication("Authentication failure occurred".into()))?,
        )
        .with_request(req))
    }

    pub fn authorize(req: AuthRequest) -> Result<AuthResponse, Error> {
        let mut ep = Self::new();
        authorization_flow(&*CLIENT_MAP, &mut ep.auth_map, &mut ep.solicitor)
            .execute(req.clone())
            .redirect_failure(req)
    }

    pub fn refresh(req: AuthRequest) -> Result<AuthResponse, Error> {
        let mut ep = Self::new();
        refresh_flow(&*CLIENT_MAP, &mut ep.issuer)
            .execute(req.clone())
            .map_err(|_| Error::Authentication("Authentication failure occurred".into()))
            .map(|r| r.with_request(req))
    }

    pub fn authenticate(req: AuthRequest) -> Result<AuthResponse, Error> {
        let mut resp = AuthResponse::default();
        let mut authenticated = false;
        if let Some(code) = req.0.query.get("code") {
            if let Some(t) = Tokens::authorize(code)? {
                if let Some(sd) = SessionData::get(t.owner_id)? {
                    resp.session = Some(Arc::new(Mutex::new(sd)));
                    resp.status = 302;
                    resp.location = Some("/".into());
                    authenticated = true;
                }
            }
        }
        if !authenticated && req.0.session.lock().user.is_some() {
            resp.body = Some("Authenticated".into());
        } else if !authenticated
            && req.0.query.get("client_id").is_some()
            && req.0.query.get("response_type").is_some()
        {
            let (c, r) = (
                req.0.query.get("client_id"),
                req.0.query.get("response_type"),
            );
            resp.status = 302;
            resp.location = Some(format!(
                "/#client_id={}&response_type={}",
                c.unwrap(),
                r.unwrap()
            ));
        } else if !authenticated {
            resp.status = 403;
            resp.body = Some("Authentication failed".into());
        }
        Ok(resp)
    }

    pub fn add_clients() {
        for (client_id, url) in crate::CONFIG.oauth.client_ids.iter() {
            let new_client = Client::public(
                client_id.as_str(),
                url.parse().unwrap(),
                "default".parse().unwrap(),
            );
            CLIENT_MAP.0.lock().register_client(new_client);
        }
    }
}

trait ResponseMappings {
    fn redirect_failure(self, req: AuthRequest) -> Result<AuthResponse, Error>;
}

impl ResponseMappings
    for Result<
        AuthResponse,
        oxide_auth::frontends::simple::endpoint::Error<crate::oauth::request::AuthRequest>,
    >
{
    fn redirect_failure(self, req: AuthRequest) -> Result<AuthResponse, Error> {
        Ok(match self {
            Ok(r) => r,
            Err(e) => {
                warn!("Failure occurred, redirecting: {:?}", e);
                AuthResponse {
                    status: 302,
                    location: Some(if req.0.query.is_empty() {
                        "/".into()
                    } else {
                        let mut p: String = "/#".into();
                        for (k, v) in req.0.query.iter() {
                            p.push_str(&format!("{}={}", k, v));
                        }
                        p
                    }),
                    body: None,
                    content_type: None,
                    session: None,
                    www_authenticate: None,
                }
            }
        }
        .with_request(req))
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
                    debug!("User found: {:?}", user);
                    sd.user = Some(user);
                    sd.save().unwrap_or_default();
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
            "{}#{}",
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
