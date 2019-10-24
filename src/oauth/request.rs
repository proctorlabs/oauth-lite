use {
    super::*,
    oxide_auth::frontends::dev::*,
    parking_lot::Mutex,
    std::{collections::HashMap, sync::Arc},
    url::form_urlencoded,
    warp::http::HeaderMap,
};

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
