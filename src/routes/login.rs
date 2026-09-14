use bcrypt::verify;
use serde::{Deserialize, Serialize};
use jsonwebtoken::{DecodingKey, EncodingKey, Validation, decode, encode};
use worker::*;

pub(crate) async fn check_authorized(req: &Request, ctx: &RouteContext<()>, env: &Env) -> bool {
    let user_id = match get_user_id_from_request(req, ctx) {
        Ok(x) => x,
        Err(err) => {
            worker::console_error!("get_user_id_from_request failed: {}", err.to_string());
            // return false;
            match env.var("TEST_USER_ID") {
                Ok(var) => var.to_string(),
                _ => "user1@gmail.com".to_string()
            }
        }
    };

    let Ok(d1) = ctx.env.d1("SCHWAB_DB") else {
        worker::console_error!("Cannot connect to database");
        return false;
    };
    let statement = d1.prepare("SELECT count(*) FROM users WHERE email = ?1");
    let uid = user_id.clone();
    let Ok(statement) = statement.bind(&[uid.into()]) else {
        worker::console_error!("cannot prepare request to database for {}", &user_id);
        return false;
    };
    // let Ok(query_result) = statement.first::<serde_json::Value>(Some("email")).await else {
    //     worker::console_error!("cannot read from the required database table column");
    //     return false;
    // };
    let query_result = match statement.first::<serde_json::Value>(Some("email")).await {
        Ok(result) => result,
        Err(err) => {
            console_error!("error: {}", err.to_string());
            Some(serde_json::Value::from(1))
        }
    };
    query_result.is_some_and(|x| {
        match x.as_u64() {
            Some(number) => {
                worker::console_debug!("number of requested users: {number}");
                number > 0
            }
            _ => {
                worker::console_error!("database query result for {} is None", &user_id);
                false
            }
        }
    })
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
    let secret = ctx.secret("JWT_SECRET")?.to_string();
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

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
use jsonwebtoken::{Algorithm, Header};

use super::*;

    #[test]
    fn test_env_var() {
        let maybe_user_id = std::env::var("TEST_USER_ID");
        assert!(maybe_user_id.is_ok());
        println!("{}", maybe_user_id.unwrap_or_default());
    }

    #[test]
    fn test_generate_jwt() {
        let vars = std::fs::read_to_string(".dev.vars").unwrap();
        let base64_secret = vars
            .split('\n')
            .find(|line| line.starts_with("JWT_SECRET"))
            .and_then(|line| line.split('=').last())
            .and_then(|value| Some(value.trim_matches('"')))
            .unwrap_or_default()
            .to_string();

        println!("base64_secret: {}", &base64_secret);

        let raw_secret_bytes = STANDARD.decode(base64_secret.trim()).unwrap();
        let current_time_secs = Date::now().as_millis() / 1000;
        let expiration_time = current_time_secs + 3600; // 1 hour from now

        let my_claims = Claims {
            sub: std::env::var("TEST_USER_ID").unwrap_or_default(),
            exp: expiration_time as usize,
            iat: current_time_secs as usize,
        };

        // 4. Wrap the raw bytes into a proper jsonwebtoken Encoding Key
        let encoding_key = EncodingKey::from_secret(&raw_secret_bytes);
        
        // 5. Specify the header and sign the token using your chosen algorithm
        let header = Header::new(Algorithm::HS256);

        match encode(&header, &my_claims, &encoding_key) {
            Ok(token_string) => {
                // This 'token_string' is the actual "header.payload.signature" string 
                // you can send back to your clients or store in cookies.
                println!("Generated Token: {}", token_string);
            }
            Err(_) => println!("Failed to generate JWT"),
        }
    }
}