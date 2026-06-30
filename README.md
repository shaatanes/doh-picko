# DNS-over-HTTPS (DoH) Subscription Management System

A highly polished, high-performance, and lightweight DNS over HTTPS (DoH) subscription proxy server designed to run directly on **Cloudflare Workers** using **Cloudflare D1** as the relational SQL storage database, and **Cloudflare KV** for low-latency configuration/cache distribution.

## Key Features

- **No External Framework Overhead**: Built using 100% vanilla JavaScript on the fast Cloudflare Workers V8 isolates runtime.
- **Dynamic Traffic Accounting**: Converts successful upstream DNS query counts into GB bandwidth limits instantly using customizable ratios. (Defaults to `5000 Queries = 1 GB`).
- **Subscription Enforcements**: Automatically blocks subscriptions that are either manually disabled, expired based on date/time, or have exceeded their allocated traffic limits.
- **Embedded Admin Console**: A gorgeous, single-file HTML/CSS/JS dashboard packed with rich statistics, real-time query monitoring, SVG/Chart.js graphs, custom provider configurations, and CSV exporting.
- **Secure Authentication**: Built using native Web Crypto API signing HS256 JWT tokens. Uses HttpOnly, Secure, SameSite secure cookies.
- **High DNS Fidelity**: Supports custom Cloudflare options (e.g., forcing IPv4, IPv6 resolved IP mode), customizable outgoing User-Agents, and cache optimizations (utilizing standard Cloudflare edge Cache API).

---

## Deployment & Setup Guide

### 1. Wrangler Authenticate
Log in to your Cloudflare account using the wrangler CLI:
```bash
npx wrangler login
```

### 2. Create Cloudflare D1 Database
Run the following command to provision a high-performance relational database instance:
```bash
npx wrangler d1 create doh_subscription_db
```
*Note down the `database_id` value outputted from this command.*

### 3. Create Cloudflare KV Namespace
Run the following command to provision a low-latency caching KV namespace:
```bash
npx wrangler kv:namespace create active_dns_providers
```
*Note down the KV namespace `id` value outputted from this command.*

### 4. Bind Bindings in `wrangler.toml`
Open the `wrangler.toml` file in the project root and update the bindings with the correct database and KV IDs:

```toml
[[d1_databases]]
binding = "DB"
database_name = "doh_subscription_db"
database_id = "YOUR_D1_DATABASE_ID_HERE" # Paste the D1 database ID here

[[kv_namespaces]]
binding = "KV"
id = "YOUR_KV_NAMESPACE_ID_HERE" # Paste the KV namespace ID here
```

### 5. Deploy to Cloudflare
Deploy your Worker immediately:
```bash
npx wrangler deploy
```

On first access, the worker automatically runs `initDb` to safely construct all SQL schema definitions and seed default data.

---

## Admin Portal Configurations & Operations

### 1. Administrative Login
- Access the dashboard at either `/` or `/admin` paths of your worker deployment.
- **Default Administrative Password**: `admin`
- Enter `admin` on the login overlay screen to authenticate.

### 2. Changing Password
1. Navigate to the **Settings** tab inside the Admin Dashboard.
2. Locate the **Modify Login Security Password** block.
3. Enter your next secure password, confirm it, and press **Save Configurations**. The worker uses the standard Web Crypto API to safely compute and store a SHA-256 representation of the password in the D1 settings database.

### 3. Changing Queries Per GB Ratio
1. Go to the **Settings** tab.
2. Adjust the **Queries Per GB Ratio** input field. (e.g., `5000` queries = 1 GB).
3. Click **Save Configurations**. Users' consumed traffic calculations immediately update on their next queries or upon page refreshment.

### 4. Adding DNS Providers
1. Go to the **DNS Providers** tab.
2. Click **Add Custom Provider** at the top right.
3. Supply a custom name (e.g., `Quad9 Secure`) and the full secure DoH endpoint URL (e.g., `https://dns.quad9.net/dns-query`).
4. Click **Register Resolver**. The resolver becomes immediately active and can be configured as your default system resolver or passed via client query parameters `?provider=name`.

---

## Technical Project Structure

The project has been engineered to maintain a pristine directory root structure to prevent path bundling clutter:

```
/
├── worker.js       # The core production Cloudflare Worker script
├── wrangler.toml   # The official Wrangler configuration and bindings
├── package.json    # Application scripts, dependencies & configurations
└── README.md       # Full documentation and operating manual
```
