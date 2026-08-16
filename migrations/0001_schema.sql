CREATE TABLE IF NOT EXISTS stock_quotes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    symbol TEXT NOT NULL,
    price REAL,
    diff REAL,
    scraped_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_symbol_time ON stock_quotes (symbol, scraped_at DESC);
