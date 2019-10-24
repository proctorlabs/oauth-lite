use {super::*, oxide_auth::frontends::dev::*, parking_lot::Mutex, std::sync::Arc};

#[derive(Debug)]
pub struct AuthResponse {
    pub status: u16,
    pub session: Option<Arc<Mutex<SessionData>>>,
    pub content_type: Option<String>,
    pub www_authenticate: Option<String>,
    pub location: Option<String>,
    pub body: Option<String>,
}

impl AuthResponse {
    pub fn with_request(mut self, req: AuthRequest) -> Self {
        debug!("Response: {:?}", self);
        let mut sd = req.0.session.lock();
        if let Err(e) = sd.update() {
            warn!("Error updating session -> {}", e);
        }
        self.session = Some(req.0.session.clone());
        self
    }
}

impl From<Grant> for AuthResponse {
    fn from(grant: Grant) -> Self {
        let user_grant: UserGrant = grant.into();
        AuthResponse {
            status: 200,
            session: None,
            content_type: Some("application/json".into()),
            www_authenticate: None,
            location: None,
            body: Some(serde_json::to_string(&user_grant).unwrap_or_default()),
        }
    }
}

impl Default for AuthResponse {
    fn default() -> Self {
        AuthResponse {
            status: 200,
            session: None,
            content_type: None,
            www_authenticate: None,
            location: None,
            body: None,
        }
    }
}

impl warp::Reply for AuthResponse {
    fn into_response(self) -> warp::reply::Response {
        debug!("{:?}", self);
        let mut builder = warp::http::Response::builder();
        builder.status(self.status);
        if let Some(loc) = self.location {
            builder.status(302);
            builder.header("Location", loc);
        }
        if let Some(auth) = self.www_authenticate {
            builder.header("WWW-Authenticate", auth);
        }
        if let Some(content) = self.content_type {
            builder.header("Content-Type", content);
        }
        if let Some(session) = self.session {
            builder.header(
                "Set-Cookie",
                session.lock().cookie_string().unwrap_or_default(),
            );
            debug!(
                "cookie sent: {:?}",
                session.lock().cookie_string().unwrap_or_default()
            );
        }
        builder
            .body(match self.body {
                Some(s) => hyper::Body::from(s),
                None => hyper::Body::empty(),
            })
            .unwrap()
    }
}

impl WebResponse for AuthResponse {
    type Error = OAuthError;

    fn ok(&mut self) -> Result<(), OAuthError> {
        self.status = 200;
        self.www_authenticate = None;
        self.location = None;
        Ok(())
    }

    fn redirect(&mut self, target: Url) -> Result<(), OAuthError> {
        self.status = 302;
        self.www_authenticate = None;
        self.location = Some(target.into_string());
        Ok(())
    }

    fn client_error(&mut self) -> Result<(), OAuthError> {
        self.status = 400;
        self.www_authenticate = None;
        self.location = None;
        Ok(())
    }

    fn unauthorized(&mut self, www_authenticate: &str) -> Result<(), OAuthError> {
        self.status = 401;
        self.www_authenticate = Some(www_authenticate.to_string());
        self.location = None;
        Ok(())
    }

    fn body_text(&mut self, text: &str) -> Result<(), OAuthError> {
        self.body = Some(text.to_string());
        self.content_type = Some("text/plain".to_string());
        Ok(())
    }

    fn body_json(&mut self, json: &str) -> Result<(), OAuthError> {
        self.body = Some(json.to_string());
        self.content_type = Some("application/json".to_string());
        Ok(())
    }
}
