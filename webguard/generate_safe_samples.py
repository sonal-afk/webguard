# generate_safe_samples.py
# Run this ONCE before training to create safe/benign samples
# Output: datasets/safe_samples.csv  (6000 safe rows, label=0)
#
# Usage:  python generate_safe_samples.py

import pandas as pd
import random
from pathlib import Path

random.seed(42)

# ── Safe SQL queries ───────────────────────────────────────────
SAFE_SQL = [
    "SELECT * FROM users WHERE id = 1",
    "SELECT name, email FROM customers WHERE active = 1",
    "SELECT id, title FROM articles WHERE published = 1 LIMIT 20",
    "SELECT * FROM products WHERE category = 'electronics' ORDER BY price ASC",
    "INSERT INTO orders (user_id, total) VALUES (5, 99.99)",
    "UPDATE users SET last_login = NOW() WHERE id = 42",
    "DELETE FROM sessions WHERE expired = 1",
    "SELECT COUNT(*) FROM logs WHERE date = '2024-01-01'",
    "SELECT p.name, p.price FROM products p JOIN categories c ON p.cat_id = c.id",
    "SELECT * FROM inventory WHERE stock > 0 ORDER BY name LIMIT 50",
    "SELECT u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id",
    "UPDATE products SET price = 29.99 WHERE id = 101",
    "SELECT DISTINCT category FROM products WHERE active = 1",
    "SELECT * FROM posts WHERE author_id = 7 ORDER BY created_at DESC",
    "INSERT INTO comments (post_id, user_id, body) VALUES (3, 9, 'Great article!')",
]

# ── Safe HTTP GET requests ─────────────────────────────────────
SAFE_GET = [
    "GET /index.html HTTP/1.1\nHost: example.com\nUser-Agent: Mozilla/5.0",
    "GET /about HTTP/1.1\nHost: company.com\nAccept: text/html",
    "GET /images/logo.png HTTP/1.1\nHost: cdn.example.com",
    "GET /api/users?page=1&limit=10 HTTP/1.1\nHost: api.example.com",
    "GET /products?category=books&sort=price HTTP/1.1\nHost: shop.com",
    "GET /dashboard HTTP/1.1\nHost: app.com\nCookie: session=abc123xyz",
    "GET /search?q=laptop+bag&page=2 HTTP/1.1\nHost: store.com",
    "GET /favicon.ico HTTP/1.1\nHost: example.com",
    "GET /api/health HTTP/1.1\nHost: api.service.com",
    "GET /blog/how-to-bake-bread HTTP/1.1\nHost: blog.com",
    "GET /user/profile?id=55 HTTP/1.1\nHost: app.example.com",
    "GET /news?category=tech&date=2024-01-01 HTTP/1.1\nHost: news.com",
    "GET /static/css/main.css HTTP/1.1\nHost: example.com",
    "GET /api/products?min_price=10&max_price=100 HTTP/1.1\nHost: api.shop.com",
    "GET /sitemap.xml HTTP/1.1\nHost: example.com",
]

# ── Safe HTTP POST requests ────────────────────────────────────
SAFE_POST = [
    "POST /login HTTP/1.1\nHost: example.com\nContent-Type: application/x-www-form-urlencoded\nusername=alice&password=securepass",
    "POST /api/checkout HTTP/1.1\nHost: shop.com\nContent-Type: application/json\n{\"cart_id\":\"abc123\",\"user_id\":99}",
    "POST /contact HTTP/1.1\nHost: company.com\nname=John&email=john@email.com&message=Hello",
    "POST /api/users HTTP/1.1\nHost: api.com\nContent-Type: application/json\n{\"name\":\"Bob\",\"email\":\"bob@test.com\"}",
    "POST /subscribe HTTP/1.1\nHost: newsletter.com\nemail=user@example.com&list=weekly",
    "POST /api/comments HTTP/1.1\nHost: blog.com\npost_id=5&body=Great+post&user_id=12",
    "POST /upload HTTP/1.1\nHost: files.com\nContent-Type: multipart/form-data\nfilename=report.pdf",
    "POST /api/orders HTTP/1.1\nHost: shop.com\nproduct_id=42&qty=2&user_id=7",
    "POST /password/reset HTTP/1.1\nHost: app.com\nemail=user@example.com",
    "POST /api/feedback HTTP/1.1\nHost: service.com\nrating=5&comment=Excellent+service",
]

# ── Safe URLs ──────────────────────────────────────────────────
SAFE_URLS = [
    "https://example.com/home",
    "https://shop.com/product?id=42",
    "https://blog.com/post/how-to-cook-pasta",
    "https://news.site.com/article?id=1234&category=tech",
    "https://api.example.com/v1/users?page=1",
    "https://store.io/search?q=shoes&size=10",
    "https://company.com/about-us",
    "https://cdn.example.com/images/banner.jpg",
    "https://app.com/dashboard?tab=overview",
    "https://docs.site.com/api/getting-started",
    "https://forum.example.com/thread?id=99&page=2",
    "https://mail.example.com/inbox?folder=inbox&limit=25",
]

# ── Template generators ────────────────────────────────────────
DOMAINS  = ["shop.com","blog.com","api.example.com","news.io","store.example.com",
            "app.service.com","cdn.site.org","portal.company.com"]
PATHS    = ["/home","/about","/products","/search","/user/profile",
            "/api/data","/contact","/dashboard","/settings","/help"]
METHODS  = ["GET", "POST"]
CATS     = ["electronics","books","clothing","food","sports","toys","health"]
SORTS    = ["price_asc","price_desc","name_asc","newest","popular"]

def random_safe():
    """Generate a random safe HTTP request, URL, or SQL query."""
    choice = random.randint(0, 5)
    if choice == 0:
        return random.choice(SAFE_SQL)
    elif choice == 1:
        return random.choice(SAFE_GET)
    elif choice == 2:
        return random.choice(SAFE_POST)
    elif choice == 3:
        return random.choice(SAFE_URLS)
    elif choice == 4:
        # Generated URL
        domain = random.choice(DOMAINS)
        path   = random.choice(PATHS)
        page   = random.randint(1, 100)
        sort   = random.choice(SORTS)
        return f"https://{domain}{path}?page={page}&sort={sort}"
    else:
        # Generated HTTP request
        method = random.choice(METHODS)
        domain = random.choice(DOMAINS)
        path   = random.choice(PATHS)
        cat    = random.choice(CATS)
        return (f"{method} {path}?category={cat}&page={random.randint(1,20)} HTTP/1.1\n"
                f"Host: {domain}\nAccept: application/json")


# ── Build dataset ──────────────────────────────────────────────
print("Generating safe samples...")

rows = []

# First add all the handcrafted samples
for s in SAFE_SQL + SAFE_GET + SAFE_POST + SAFE_URLS:
    rows.append({"text": s, "label": 0})

# Fill up to 6000 with generated samples
while len(rows) < 6000:
    rows.append({"text": random_safe(), "label": 0})

# Shuffle
random.shuffle(rows)

# Save
Path("datasets").mkdir(exist_ok=True)
out = Path("datasets/safe_samples.csv")
pd.DataFrame(rows).to_csv(out, index=False)

print(f"Done! Created {out} with {len(rows)} safe samples (label=0)")
print(f"Now run: python train_web_model.py")
