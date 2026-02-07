//! gRPC authentication interceptor.
//!
//! Validates JWT tokens from the `authorization` metadata field on all gRPC requests.

use jsonwebtoken::{decode, DecodingKey, Validation};
use tonic::{Request, Status};

use crate::services::auth_service::Claims;

/// gRPC auth interceptor that validates JWT Bearer tokens.
#[derive(Clone)]
pub struct AuthInterceptor {
    decoding_key: DecodingKey,
}

impl AuthInterceptor {
    pub fn new(jwt_secret: &str) -> Self {
        Self {
            decoding_key: DecodingKey::from_secret(jwt_secret.as_bytes()),
        }
    }

    #[allow(clippy::result_large_err)]
    pub fn intercept(&self, req: Request<()>) -> Result<Request<()>, Status> {
        let token = req
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or_else(|| Status::unauthenticated("Missing or invalid authorization token"))?;

        let token_data = decode::<Claims>(token, &self.decoding_key, &Validation::default())
            .map_err(|e| Status::unauthenticated(format!("Invalid token: {}", e)))?;

        if token_data.claims.token_type != "access" {
            return Err(Status::unauthenticated("Invalid token type"));
        }

        Ok(req)
    }
}
