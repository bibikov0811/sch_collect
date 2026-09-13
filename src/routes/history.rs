use serde::{Deserialize, Serialize};

use worker::*;

#[derive(Serialize, Deserialize)]
struct PreProcessedRow {
    symbol: String,
    last_price: Option<f64>,
    diff: Option<f64>,
    scraped_at: String,
}

pub(crate) async fn handle_history(mut _req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let db = ctx.d1("SCHWAB_DB")?;

    let Some(symbol) = ctx.param("symbol") else {
        return Response::error("Bad request parameters", 400);
    };

    let statement = db.prepare(
        r#"
        SELECT 
            symbol, last_price, diff, scraped_at 
            FROM stock_quotes  
            WHERE symbol = ? 
            ORDER BY scraped_at,symbol 
            DESC 
        LIMIT 2500"#,
    );
    let query = statement.bind(&[symbol.into()])?;
    let result = query.all().await?;
    let rows: Vec<PreProcessedRow> = result.results()?;
    let response = Response::from_json(&rows)?;
    let headers = Headers::new();
    let _ = headers.append("Content-Type", "application/json");
    let _ = headers.append("Cache-Control", "private, no-cache");
    Ok(response.with_headers(headers))
}
