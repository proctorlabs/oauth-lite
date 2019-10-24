use crate::Error;
use oxide_auth::endpoint::*;

mod authorization_registry;
mod client_registry;
mod endpoint;
mod request;
mod response;
mod session;
mod token_registry;
mod user_grant;

pub use {
    authorization_registry::*, client_registry::*, endpoint::*, request::*, response::*,
    session::*, token_registry::*, user_grant::*,
};

pub fn token(req: AuthRequest) -> Result<AuthResponse, Error> {
    OAuthEndpoint::access_token(req)
}

pub fn resource(req: AuthRequest) -> Result<AuthResponse, Error> {
    OAuthEndpoint::resource(req)
}

pub fn authorize(req: AuthRequest) -> Result<AuthResponse, Error> {
    OAuthEndpoint::authorize(req)
}

pub fn refresh(req: AuthRequest) -> Result<AuthResponse, Error> {
    OAuthEndpoint::refresh(req)
}

pub fn authenticate(req: AuthRequest) -> Result<AuthResponse, Error> {
    OAuthEndpoint::authenticate(req)
}
