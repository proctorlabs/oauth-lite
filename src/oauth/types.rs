use super::SessionData;
use oxide_auth::frontends::dev::*;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use url::form_urlencoded;
use warp::http::HeaderMap;

#[derive(Debug, Clone)]
pub struct AuthRequest(pub Arc<InnerAuthRequest>);

#[derive(Debug)]
pub struct InnerAuthRequest {
    pub query: HashMap<String, String>,
    pub authorization_header: Option<String>,
    pub urlbody: Option<HashMap<String, String>>,
    pub cookie: Option<String>,
    pub session: Arc<Mutex<SessionData>>,
}

impl AuthRequest {
    pub fn new(
        query: String,
        headers: HeaderMap,
        body: Option<HashMap<String, String>>,
        cookie: Option<String>,
    ) -> Self {
        let session = if let Some(ref c_string) = cookie {
            SessionData::get_cookie(c_string)
                .unwrap_or_else(|_| Some(SessionData::new(None).unwrap()))
                .unwrap_or_else(|| SessionData::new(None).unwrap())
        } else {
            SessionData::new(None).unwrap()
        };
        let res = AuthRequest(Arc::new(InnerAuthRequest {
            query: Self::parse_query(query),
            authorization_header: Self::parse_headers(headers),
            urlbody: body,
            cookie,
            session: Arc::new(Mutex::new(session)),
        }));
        debug!("{:?}", res);
        res
    }

    fn parse_query(query: String) -> HashMap<String, String> {
        let mut result = HashMap::new();
        let res = form_urlencoded::parse(query.as_bytes());
        for q in res {
            result.insert(q.0.to_string(), q.1.to_string());
        }
        result
    }

    fn parse_headers(headers: HeaderMap) -> Option<String> {
        let search_header = Some("Authorization".parse().unwrap());
        for h in headers.into_iter() {
            if h.0 == search_header {
                return Some(h.1.to_str().unwrap().into());
            }
        }
        None
    }
}

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
        let mut sd = req.0.session.lock();
        if let Err(e) = sd.update() {
            warn!("Error updating session -> {}", e);
        }
        self.session = Some(req.0.session.clone());
        self
    }
}

impl Default for AuthResponse {
    fn default() -> Self {
        AuthResponse {
            status: 303,
            session: None,
            content_type: None,
            www_authenticate: None,
            location: Some("/unknown.html".into()),
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

impl WebRequest for AuthRequest {
    type Response = AuthResponse;
    type Error = OAuthError;

    fn query(&mut self) -> Result<Cow<dyn QueryParameter + 'static>, OAuthError> {
        Ok(Cow::Borrowed(&self.0.query))
    }

    fn urlbody(&mut self) -> Result<Cow<dyn QueryParameter + 'static>, OAuthError> {
        self.0
            .urlbody
            .as_ref()
            .map(|body| Cow::Borrowed(body as &dyn QueryParameter))
            .ok_or(OAuthError::PrimitiveError)
    }

    fn authheader(&mut self) -> Result<Option<Cow<str>>, OAuthError> {
        Ok(self
            .0
            .authorization_header
            .as_ref()
            .map(|string| string.as_str().into()))
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
