use base64::{engine::general_purpose, Engine as _};
use worker::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// --- Serialization Structs ---
#[derive(Deserialize)]
struct SchwabTokenResponse {
    access_token: String,
    refresh_token: String,
}

// Map the specific nested payload structure returned by Schwab REST Quote API
#[derive(Deserialize)]
struct SchwabQuoteResponse {
    #[serde(flatten)]
    quotes: HashMap<String, SchwabSymbolData>,
}

#[derive(Deserialize)]
struct SchwabSymbolData {
    symbol: String,
    #[serde(rename = "lastPrice")]
    last_price: Option<f64>,
}

#[derive(Serialize, Deserialize)]
struct PreProcessedRow {
    symbol: String,
    price: Option<f64>,
    diff: Option<f64>,
    scraped_at: String,
}

#[event(fetch)]
pub async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let router = Router::new();
    let bucket = env.bucket("SCHWAB_BUCKET")?;

    router.get_async("/fetch-processed-data", |req, ctx| async move {
        // Simple API Key validation for security against unauthorized public hits
        let headers = req.headers();
        let auth_header = headers.get("X-AWS-Secret-Key")?.unwrap_or_default();
        let expected_key = ctx.secret("AWS_WORKER_SECRET")?.to_string();

        if auth_header != expected_key {
            //return Response::error("Unauthorized AWS connection", 401);
            console_log!("{auth_header} == {expected_key}");
        }

        // Access the D1 Database binding named "DB"
        let db = ctx.d1("SCHWAB_DB")?;
        
        // Fetch the 500 newest records to return to your AWS analytics environment
        let statement = db.prepare("SELECT symbol, price, diff, scraped_at FROM stock_quotes ORDER BY scraped_at,symbol DESC LIMIT 500");
        let result = statement.all().await?;
        
        let rows: Vec<PreProcessedRow> = result.results()?;
        Response::from_json(&rows)
    })
    .post_async("/symbols", |req, ctx| async move {
        // Simple API Key validation for security against unauthorized public hits
        let headers = req.headers();
        let auth_header = headers.get("X-AWS-Secret-Key")?.unwrap_or_default();
        let expected_key = ctx.secret("AWS_WORKER_SECRET")?.to_string();

        if auth_header != expected_key {
            return Response::error("Unauthorized AWS connection", 401);
        }

        // Parse the incoming JSON payload for symbols to track
        let mut req = req;
        let body: HashMap<String, String> = req.json().await?;
        if let Some(symbols) = body.get("symbols") {
            let kv = ctx.kv("SCHWAB_STORE")?;
            kv.put("symbols", symbols)?.execute().await?;
            return Response::ok("Symbols updated successfully");
        }
        Response::error("Missing 'symbols' in request body", 400)
    })
    .get_async("/symbols", |_req, ctx| async move {
        let kv = ctx.kv("SCHWAB_STORE")?;
        let symbols = kv.get("symbols").text().await?;
        Response::from_json(&symbols)
    })
    .get_async("/all_symbols", |_req, _ctx| {
        let value = bucket.clone();
        async move {
            if let Some(object) = value.get("all_tickers.txt").execute().await? {
                if let Some(body) = object.body() {
                    return Response::from_bytes(body.bytes().await?);
                }
            }
            Response::error("Object not found", 404)
        }
    })
    .run(req, env)
    .await
}

// ===================================================
// 2. BACKGROUND AUTOMATION CRONS (Tokens & Scraping)
// ===================================================
#[event(scheduled)]
pub async fn scheduled(event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
    let active = {
        if let Ok(kv) = env.kv("SCHWAB_STORE") {
            if let Ok(Some(collecting)) = kv.get("collecting").text().await {
                collecting.parse::<bool>().unwrap_or_default()
            } else {
                false
            }
        } else {
            false
        }
    };
    if !active {
        return;
    }
    match event.cron().as_str() {
        "*/20 * * * *" => {
            #[cfg(feature = "debugging")]
            console_log!("CRON: Running 20-minute Token Rotation loop...");
            if let Err(e) = execute_token_refresh(&env).await {
                console_error!("Token rotation loop failed: {:?}", e);
            }
        },
        "*/1 * * * *" => {
            #[cfg(feature = "debugging")]
            console_log!("CRON: Running 60-second Market Data Collection loop...");
            if let Err(e) = execute_market_scrape(&env).await {
                console_error!("Market data extraction loop failed: {:?}", e);
            }
        },
        _ => console_log!("Unknown Cron Schedule execution triggered.")
    }
}

// --- Background Logic Functions ---

async fn execute_token_refresh(env: &Env) -> Result<()> {
    let client_id = env.secret("SCHWAB_APP_KEY")?.to_string();
    let client_secret = env.secret("SCHWAB_APP_SECRET")?.to_string();
    let kv = env.kv("SCHWAB_STORE")?;
    
    let current_refresh_token = match kv.get("refresh_token").text().await? {
        Some(token) => token,
        None => return Ok(()),
    };

    let mut form_data = HashMap::new();
    form_data.insert("grant_type", "refresh_token");
    form_data.insert("refresh_token", &current_refresh_token);
    let encoded_body = serde_urlencoded::to_string(&form_data).map_err(|e| worker::Error::from(e.to_string()))?;

    let base64_auth = general_purpose::STANDARD.encode(format!("{}:{}", client_id, client_secret));
    let headers = worker::Headers::new();
    headers.set("Authorization", &format!("Basic {}", base64_auth))?;
    headers.set("Content-Type", "application/x-www-form-urlencoded")?;

    let init = RequestInit {
        method: Method::Post,
        headers,
        body: Some(wasm_bindgen::JsValue::from_str(&encoded_body)),
        ..Default::default()
    };

    let request = Request::new_with_init("https://schwabapi.com", &init)?;
    let mut response = Fetch::Request(request).send().await?;
    if response.status_code() == 200 {
        let token_data: SchwabTokenResponse = response.json().await?;
        kv.put("access_token", &token_data.access_token)?.execute().await?;
        kv.put("refresh_token", &token_data.refresh_token)?.execute().await?;
    }
    Ok(())
}

async fn execute_market_scrape(env: &Env) -> Result<()> {
    let kv = env.kv("SCHWAB_STORE")?;
    let target_symbols = match kv.get("symbols").text().await? {
        Some(value) => value,
        None => return Ok(()), // No symbols to track; skip this cycle
    };

    let db = env.d1("SCHWAB_DB")?;

    let access_token = match kv.get("access_token").text().await? {
        Some(token) => token,
        None => return Err(worker::Error::from("Access token missing from storage during collection cycle")),
    };

    // Symbols to track; customize this comma-separated list as required
    let target_url = format!("https://schwabapi.com{}", target_symbols);

    let headers = worker::Headers::new();
    headers.set("Authorization", &format!("Bearer {}", access_token))?;
    headers.set("Accept", "application/json")?;

    let init = RequestInit { method: Method::Get, headers, ..Default::default() };
    let request = Request::new_with_init(&target_url, &init)?;
    let mut response = Fetch::Request(request).send().await?;

    if response.status_code() == 200 {
        let raw_data: SchwabQuoteResponse = response.json().await?;
        
        // Loop through each symbol in the dictionary payload and write it down into SQL
        for (_ticker, data) in raw_data.quotes {
            let kv_key = format!("last_price_{}", data.symbol);
            let curr_price = data.last_price.unwrap_or(0.0);
            let last_price = match kv.get(&kv_key).text().await? {
                Some(value) => value.parse::<f64>().unwrap_or(curr_price),
                None => curr_price // If no previous price exists, assume price was not changed
            };
            let diff = (last_price - curr_price)/last_price * 100.0; // Calculate percentage difference
            kv.put(&kv_key, &curr_price.to_string())?.execute().await?;

            let query = db.prepare(
                "INSERT INTO stock_quotes (symbol, last_price, diff) VALUES (?1, ?2, ?3)"
            );
            // Bind parameters securely to shield against injection issues
            query.bind(&[
                data.symbol.into(),
                data.last_price.into(),
                diff.into(),
            ])?
            .run()
            .await?;
        }
        #[cfg(feature = "debugging")]
        console_log!("Data successfully normalized and saved into D1 Database storage rows.");
    }
    Ok(())
}
