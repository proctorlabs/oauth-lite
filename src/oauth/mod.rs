use crate::Error;

mod endpoint;
mod session;
mod types;

pub use {endpoint::*, session::*, types::*};

pub fn token(req: AuthRequest) -> Result<AuthResponse, Error> {
    OAuthEndpoint::access_token(req)
}

pub fn resource(req: AuthRequest) -> Result<Grant, Error> {
    OAuthEndpoint::resource(req)
}

pub fn authorize(req: AuthRequest) -> Result<AuthResponse, Error> {
    OAuthEndpoint::authorize(req)
}

pub fn refresh(req: AuthRequest) -> Result<AuthResponse, Error> {
    OAuthEndpoint::refresh(req)
}
