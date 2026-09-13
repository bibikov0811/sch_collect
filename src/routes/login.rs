use bcrypt::verify;
use serde::{Deserialize, Serialize};
use jsonwebtoken::{DecodingKey, EncodingKey, Validation, decode, encode};
use worker::*;

pub(crate) async fn check_authorized(req: &Request, ctx: &RouteContext<()>) -> bool {
    let Ok(user_id) = get_user_id_from_request(req, ctx) else {
        return false;
    };
    let Ok(d1) = ctx.env.d1("SCHWAB_DB") else {
        return false;
    };
    let statement = d1.prepare("SELECT count(*) FROM users WHERE email = ?1");
    let Ok(statement) = statement.bind(&[user_id.into()]) else {
        return false;
    };
    let Ok(query_result) = statement.first::<serde_json::Value>(Some("email")).await else {
        return false;
    };
    query_result.is_some_and(|x| x.as_u64().unwrap_or_default() > 0)
}

#[derive(Deserialize)]
struct LoginPayload {
    email: String,
    password_plain: String,
}

#[derive(Serialize)]
struct AuthResponse {
    token: String,
    message: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String, // User ID
    exp: usize,  // Expiry time (Timestamp)
    iat: usize,  // Issued at (as timestamp)
}

fn get_user_id_from_request(req: &Request, ctx: &RouteContext<()>) -> Result<String> {
    // 1. Pull the Authorization header
    let headers = req.headers();
    let auth_header = headers
        .get("Authorization")?
        .ok_or_else(|| worker::Error::from("Missing Authorization Header"))?;

    // Expecting format: "Bearer <token>"
    if !auth_header.starts_with("Bearer ") {
        return Err(worker::Error::from("Invalid Token Format"));
    }
    let token = auth_header.trim_start_matches("Bearer ");

    // 2. Decode and Validate JWT
    let secret = ctx.env.secret("JWT_SECRET")?.to_string();
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|_| worker::Error::from("Invalid or Expired Token"))?;

    // Return the validated User ID
    Ok(token_data.claims.sub)
}

pub(crate) async fn handle_login(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    // 1. Parse the JSON body sent from Dioxus
    let payload: LoginPayload = req.json().await?;

    // 2. Fetch the user from your database binding (e.g., Cloudflare D1)
    let d1 = ctx.env.d1("SCHWAB_DB")?; // Looks up the "SCHWAB_DB" binding in wrangler.toml
    let statement = d1.prepare("SELECT id, password_hash FROM users WHERE email = ?1");
    let query_result = statement
        .bind(&[payload.email.into()])?
        .first::<serde_json::Value>(Some("email"))
        .await?;

    let user_row = match query_result {
        Some(row) => row,
        None => return Response::error("Invalid email or password", 401),
    };

    let user_id = user_row["id"].as_str().unwrap_or("");
    let db_hash = user_row["password_hash"].as_str().unwrap_or("");

    // 3. Verify the plain password matches the hashed password
    if !verify(&payload.password_plain, db_hash).unwrap_or(false) {
        return Response::error("Invalid email or password", 401);
    }

    // 4. Generate a JWT Token
    // Fetch a secure secret key from Cloudflare secrets (configured via wrangler secret put)
    let secret = ctx.env.secret("JWT_SECRET")?.to_string();

    let issued_at = Date::now().as_millis() as usize / 1000;
    let expiration = issued_at + 86400; // Expires in 24 hours
    let claims = Claims {
        sub: user_id.to_string(),
        exp: expiration,
        iat: issued_at,
    };

    let token = encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| worker::Error::from(e.to_string()))?;

    // 5. Respond back to Dioxus
    Response::from_json(&AuthResponse {
        token,
        message: "Successfully logged in".to_string(),
    })
}

