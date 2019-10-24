use {
    crate::oauth::*,
    std::collections::HashMap,
    warp::{http::HeaderMap, Filter, Rejection},
};

const COOKIE_NAME: &str = "SID";

pub fn get_authorize() -> impl Filter<Extract = (AuthResponse,), Error = Rejection> + Clone {
    path!("authorize")
        .and(warp::path::end())
        .and(warp::header::headers_cloned())
        .and(warp::query::raw())
        .and(warp::cookie::optional(COOKIE_NAME))
        .map(
            |headers: HeaderMap, query: String, cookie: Option<String>| {
                let req = AuthRequest::new(query, headers, None, cookie);
                authorize(req).unwrap()
            },
        )
        .or(path!("authorize")
            .and(warp::path::end())
            .and(warp::header::headers_cloned())
            .and(warp::cookie::optional(COOKIE_NAME))
            .map(|headers: HeaderMap, cookie: Option<String>| {
                let req = AuthRequest::new(String::default(), headers, None, cookie);
                authorize(req).unwrap()
            }))
        .unify()
}

pub fn post_authorize() -> impl Filter<Extract = (AuthResponse,), Error = Rejection> + Clone {
    path!("authorize")
        .and(warp::path::end())
        .and(warp::query::raw())
        .and(warp::body::content_length_limit(1024 * 32))
        .and(warp::body::form())
        .and(warp::header::headers_cloned())
        .and(warp::cookie::optional(COOKIE_NAME))
        .map(
            |query: String,
             form: HashMap<String, String>,
             headers: HeaderMap,
             cookie: Option<String>| {
                let req = AuthRequest::new(query, headers, Some(form), cookie);
                authorize(req).unwrap()
            },
        )
        .or(path!("authorize")
            .and(warp::path::end())
            .and(warp::body::content_length_limit(1024 * 32))
            .and(warp::body::form())
            .and(warp::header::headers_cloned())
            .and(warp::cookie::optional(COOKIE_NAME))
            .map(
                |form: HashMap<String, String>, headers: HeaderMap, cookie: Option<String>| {
                    let req = AuthRequest::new(String::default(), headers, Some(form), cookie);
                    authorize(req).unwrap()
                },
            ))
        .unify()
}

pub fn get_authenticate() -> impl Filter<Extract = (AuthResponse,), Error = Rejection> + Clone {
    path!("authenticate")
        .and(warp::path::end())
        .and(warp::query::raw())
        .and(warp::cookie::optional(COOKIE_NAME))
        .map(|query: String, cookie: Option<String>| {
            let req = AuthRequest::new(query, HeaderMap::default(), None, cookie);
            authenticate(req).unwrap()
        })
}

pub fn get_userdetail() -> impl Filter<Extract = (AuthResponse,), Error = Rejection> + Clone {
    path!("resource")
        .and(warp::path::end())
        .and(warp::header::headers_cloned())
        .and(warp::cookie::optional(COOKIE_NAME))
        .map(|headers: HeaderMap, cookie: Option<String>| {
            let req = AuthRequest::new(String::default(), headers, None, cookie);
            resource(req).unwrap()
        })
}

pub fn post_token() -> impl Filter<Extract = (AuthResponse,), Error = Rejection> + Clone {
    path!("token")
        .and(warp::path::end())
        .and(warp::body::content_length_limit(1024 * 32))
        .and(warp::body::form())
        .and(warp::header::headers_cloned())
        .and(warp::cookie::optional(COOKIE_NAME))
        .map(
            |form: HashMap<String, String>, headers: HeaderMap, cookie: Option<String>| {
                let req = AuthRequest::new(String::default(), headers, Some(form), cookie);
                token(req).unwrap()
            },
        )
}

pub fn post_refresh() -> impl Filter<Extract = (AuthResponse,), Error = Rejection> + Clone {
    path!("refresh")
        .and(warp::path::end())
        .and(warp::body::content_length_limit(1024 * 32))
        .and(warp::body::form())
        .and(warp::header::headers_cloned())
        .and(warp::cookie::optional(COOKIE_NAME))
        .map(
            |form: HashMap<String, String>, headers: HeaderMap, cookie: Option<String>| {
                let req = AuthRequest::new(String::default(), headers, Some(form), cookie);
                refresh(req).unwrap()
            },
        )
}
