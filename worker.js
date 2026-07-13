/**
 * DNS over HTTPS (DoH) Subscription System - Cloudflare Worker
 * Fully self-contained, plain JavaScript, production-ready.
 */

// Global in-memory cache for IP rate-limiting (resets when worker isolates restart)
const ipRequests = new Map();
const RATE_LIMIT_WINDOW_MS = 60000; // 1 minute
const MAX_REQUESTS_PER_WINDOW = 300; // Allow ample queries for DNS clients, limit abuse for API

// HIGHLY OPTIMIZED IN-MEMORY CACHES FOR ULTRA-LOW LATENCY / ULTRA-LOW PING (GAMING)
const userCache = new Map();
const USER_CACHE_TTL = 30000; // 30 seconds

let inMemorySettings = null;
let inMemorySettingsTime = 0;
const SETTINGS_CACHE_TTL = 30000; // 30 seconds

const dnsCache = new Map();
const DNS_CACHE_TTL = 300000; // 5 minutes (300 seconds Cache) for ultra-low latency

// Default list of built-in DNS Providers
const DEFAULT_DNS_PROVIDERS = [
  { name: 'Cloudflare', url: 'https://1.1.1.1/dns-query', enabled: true, is_built_in: true },
  { name: 'Google', url: 'https://8.8.8.8/dns-query', enabled: true, is_built_in: true },
  { name: 'Radar Game (رادار گیم)', url: 'https://doh.radar.game/dns-query', enabled: true, is_built_in: true },
  { name: 'Electro DNS (الکترو)', url: 'https://doh.electro.ir/dns-query', enabled: true, is_built_in: true },
  { name: '403 Online (۴۰۳ آنلاین)', url: 'https://dns.403.online/dns-query', enabled: true, is_built_in: true },
  { name: 'Shecan (شکن)', url: 'https://free.shecan.ir/dns-query', enabled: true, is_built_in: true },
  { name: 'NordVPN DNS', url: 'https://doh.nordvpn.com/dns-query', enabled: true, is_built_in: true },
  { name: 'Ali DNS (Alibaba)', url: 'https://dns.alidns.com/dns-query', enabled: true, is_built_in: true },
  { name: '114 DNS (Tencent)', url: 'https://doh.pub/dns-query', enabled: true, is_built_in: true },
  { name: 'Norton Family', url: 'https://doh.family.norton.com/dns-query', enabled: true, is_built_in: true },
  { name: 'Quad9', url: 'https://dns.quad9.net/dns-query', enabled: true, is_built_in: true },
  { name: 'AdGuard DNS', url: 'https://dns.adguard-dns.com/dns-query', enabled: true, is_built_in: true },
  { name: 'OpenDNS', url: 'https://doh.opendns.com/dns-query', enabled: true, is_built_in: true },
  { name: 'CleanBrowsing', url: 'https://doh.cleanbrowsing.org/doh/family-filter/', enabled: true, is_built_in: true },
  { name: 'ControlD', url: 'https://dns.controld.com/freedns', enabled: true, is_built_in: true },
  { name: 'NextDNS', url: 'https://dns.nextdns.io', enabled: true, is_built_in: true },
  { name: 'DNS.SB', url: 'https://doh.dns.sb/dns-query', enabled: true, is_built_in: true },
  { name: 'Yandex DNS', url: 'https://common.dns.yandex.ru/dns-query', enabled: true, is_built_in: true },
  { name: 'Comodo DNS', url: 'https://doh.securactive.net/dns-query', enabled: true, is_built_in: true }
];

// Database Initialization SQL
const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uuid TEXT UNIQUE,
  username TEXT,
  created_at TEXT,
  expire_at TEXT,
  traffic_limit_gb REAL,
  query_count INTEGER DEFAULT 0,
  used_gb REAL DEFAULT 0.0,
  remaining_gb REAL,
  enabled INTEGER DEFAULT 1,
  last_activity TEXT,
  dns_provider TEXT
);

CREATE TABLE IF NOT EXISTS traffic_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uuid TEXT,
  timestamp TEXT,
  provider TEXT,
  client_ip TEXT,
  user_agent TEXT
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT
);
`;

// Helper: Rate limiter
function checkRateLimit(ip) {
  const now = Date.now();
  if (!ipRequests.has(ip)) {
    ipRequests.set(ip, [now]);
    return false;
  }
  const timestamps = ipRequests.get(ip).filter(t => now - t < RATE_LIMIT_WINDOW_MS);
  if (timestamps.length >= MAX_REQUESTS_PER_WINDOW) {
    return true;
  }
  timestamps.push(now);
  ipRequests.set(ip, timestamps);
  return false;
}

// Helper: Secure password hashing (SHA-256)
async function sha256(message) {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// JWT Helpers (pure Web Crypto API, zero external dependencies)
function base64urlEncode(str) {
  const binary = typeof str === 'string' ? new TextEncoder().encode(str) : str;
  return btoa(String.fromCharCode(...binary))
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function base64urlDecode(str) {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  const binaryStr = atob(base64);
  const bytes = new Uint8Array(binaryStr.length);
  for (let i = 0; i < binaryStr.length; i++) {
    bytes[i] = binaryStr.charCodeAt(i);
  }
  return bytes;
}

async function signJwt(payload, secret) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const headerStr = base64urlEncode(JSON.stringify(header));
  const payloadStr = base64urlEncode(JSON.stringify(payload));
  
  const tokenInput = `${headerStr}.${payloadStr}`;
  const enc = new TextEncoder();
  
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  
  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    enc.encode(tokenInput)
  );
  
  const signatureStr = base64urlEncode(new Uint8Array(signature));
  return `${tokenInput}.${signatureStr}`;
}

async function verifyJwt(token, secret) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    
    const [headerStr, payloadStr, signatureStr] = parts;
    const tokenInput = `${headerStr}.${payloadStr}`;
    const enc = new TextEncoder();
    
    const key = await crypto.subtle.importKey(
      'raw',
      enc.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );
    
    const signature = base64urlDecode(signatureStr);
    const isValid = await crypto.subtle.verify(
      'HMAC',
      key,
      signature,
      enc.encode(tokenInput)
    );
    
    if (!isValid) return null;
    
    const payload = JSON.parse(new TextDecoder().decode(base64urlDecode(payloadStr)));
    if (payload.exp && Date.now() > payload.exp) {
      return null;
    }
    return payload;
  } catch (e) {
    return null;
  }
}

// Helper: Ensure tables exist and default settings are seeded
async function initDb(db, env) {
  // Run table creators (safe due to IF NOT EXISTS)
  const statements = SCHEMA_SQL.trim().split(';').filter(s => s.trim().length > 0);
  for (const stmt of statements) {
    await db.prepare(stmt).run();
  }

  // Dynamic schema migrations: Add dns_provider column to users table if it does not exist
  try {
    await db.prepare("ALTER TABLE users ADD COLUMN dns_provider TEXT").run();
  } catch (err) {
    // Column already exists or table is empty/created freshly
  }

  // Check if admin password hash is configured
  const adminCheck = await db.prepare("SELECT value FROM settings WHERE key = 'admin_password_hash'").first();
  if (!adminCheck) {
    // Default admin password is 'admin' (hashed via SHA-256)
    const defaultHash = await sha256('admin');
    await db.prepare("INSERT INTO settings (key, value) VALUES ('admin_password_hash', ?)").bind(defaultHash).run();
  }

  // Check and seed default config settings
  const configs = [
    { key: 'queries_per_gb', value: '5000' },
    { key: 'default_dns', value: 'Cloudflare' },
    { key: 'cloudflare_mode', value: 'Automatic' },
    { key: 'dns_cache_enabled', value: 'true' }
  ];

  for (const conf of configs) {
    const check = await db.prepare("SELECT value FROM settings WHERE key = ?").bind(conf.key).first();
    if (!check) {
      await db.prepare("INSERT INTO settings (key, value) VALUES (?, ?)").bind(conf.key, conf.value).run();
    }
  }

  // Ensure and synchronize all built-in DNS Providers so upgrades don't leave them out
  const checkProviders = await db.prepare("SELECT value FROM settings WHERE key = 'dns_providers'").first();
  if (checkProviders) {
    try {
      const existing = JSON.parse(checkProviders.value);
      if (Array.isArray(existing)) {
        // Keep user's custom DNS providers (where is_built_in is false or missing)
        const customProviders = existing.filter(p => !p.is_built_in);
        // Combine our updated built-in ones with their custom ones
        const merged = [...DEFAULT_DNS_PROVIDERS];
        for (const cust of customProviders) {
          if (!merged.some(p => p.name.toLowerCase() === cust.name.toLowerCase())) {
            merged.push(cust);
          }
        }
        await db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)").bind('dns_providers', JSON.stringify(merged)).run();
      } else {
        await db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)").bind('dns_providers', JSON.stringify(DEFAULT_DNS_PROVIDERS)).run();
      }
    } catch (e) {
      await db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)").bind('dns_providers', JSON.stringify(DEFAULT_DNS_PROVIDERS)).run();
    }
  } else {
    await db.prepare("INSERT INTO settings (key, value) VALUES (?, ?)").bind('dns_providers', JSON.stringify(DEFAULT_DNS_PROVIDERS)).run();
  }

  // Invalidate KV Caches on cold-starts
  if (env && env.KV) {
    await env.KV.delete('active_settings_map');
    await env.KV.delete('active_dns_providers');
  }
}

// CORS Headers
function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
  };
}

// Response helper
function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...corsHeaders()
    }
  });
}

// Authenticate Admin Request via JWT Header or Cookie
async function authenticateAdmin(request, secret) {
  const authHeader = request.headers.get('Authorization');
  let token = null;

  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.substring(7);
  } else {
    // Try extraction from Cookie header
    const cookieHeader = request.headers.get('Cookie');
    if (cookieHeader) {
      const match = cookieHeader.match(/token=([^;]+)/);
      if (match) token = match[1];
    }
  }

  if (!token) return null;
  return await verifyJwt(token, secret);
}

// Helper to detect private or loopback IP addresses
function isPrivateIp(ipStr) {
  if (!ipStr) return true;
  if (ipStr === '127.0.0.1' || ipStr === '::1' || ipStr === 'localhost') return true;
  if (ipStr.startsWith('10.')) return true;
  if (ipStr.startsWith('192.168.')) return true;
  if (ipStr.startsWith('169.254.')) return true;
  if (ipStr.startsWith('172.')) {
    const parts = ipStr.split('.');
    if (parts.length >= 2) {
      const second = parseInt(parts[1], 10);
      if (second >= 16 && second <= 31) return true;
    }
  }
  if (ipStr.startsWith('fe80:') || ipStr.startsWith('fc00:') || ipStr.startsWith('fd00:')) return true;
  return false;
}

// Helper to detect if a DNS provider is gaming/anti-sanction
function isGamingDns(name) {
  if (!name) return false;
  const n = name.toLowerCase();
  return n.includes('radar') || n.includes('electro') || n.includes('403') || n.includes('shecan');
}

// Helper to parse IPv4 or IPv6 into an ECS-compatible structure
function parseIp(ipStr) {
  if (!ipStr) return null;
  if (ipStr.includes('.')) {
    // IPv4 parsing
    const parts = ipStr.split('.').map(x => parseInt(x, 10));
    if (parts.length === 4 && parts.every(x => !isNaN(x) && x >= 0 && x <= 255)) {
      return {
        family: 1, // IPv4
        prefixLen: 24, // Mask /24 is standard for ECS privacy
        bytes: parts.slice(0, 3) // 3 bytes representing the subnet
      };
    }
  } else if (ipStr.includes(':')) {
    // IPv6 parsing
    let fullIp = ipStr;
    if (ipStr.includes('::')) {
      const parts = ipStr.split('::');
      const left = parts[0] ? parts[0].split(':') : [];
      const right = parts[1] ? parts[1].split(':') : [];
      const missingCount = 8 - (left.length + right.length);
      const middle = Array(missingCount).fill('0');
      fullIp = [...left, ...middle, ...right].join(':');
    }
    const hexParts = fullIp.split(':').map(x => parseInt(x || '0', 16));
    if (hexParts.length === 8 && hexParts.every(x => !isNaN(x) && x >= 0 && x <= 0xffff)) {
      const bytes = [];
      // Grab first 4 blocks (8 bytes) of IPv6 for subnet
      for (let i = 0; i < 4; i++) {
        bytes.push((hexParts[i] >> 8) & 0xff);
        bytes.push(hexParts[i] & 0xff);
      }
      return {
        family: 2, // IPv6
        prefixLen: 56, // /56 prefix length
        bytes: bytes.slice(0, 7) // 7 bytes represent /56
      };
    }
  }
  return null;
}

// Walks through a DNS message to locate the beginning of the Additional section
function findAdditionalSectionOffset(view, byteLength) {
  if (byteLength < 12) return -1;
  const qdCount = view.getUint16(4);
  const anCount = view.getUint16(6);
  const nsCount = view.getUint16(8);
  
  let offset = 12;

  // Walk Questions
  for (let i = 0; i < qdCount; i++) {
    offset = skipName(view, offset, byteLength);
    if (offset === -1 || offset + 4 > byteLength) return -1;
    offset += 4; // Skip QTYPE and QCLASS
  }

  // Walk Answers
  for (let i = 0; i < anCount; i++) {
    offset = skipResourceRecord(view, offset, byteLength);
    if (offset === -1) return -1;
  }

  // Walk Authorities
  for (let i = 0; i < nsCount; i++) {
    offset = skipResourceRecord(view, offset, byteLength);
    if (offset === -1) return -1;
  }

  return offset;
}

// Utility to skip a DNS name domain (labels)
function skipName(view, offset, byteLength) {
  let curr = offset;
  while (curr < byteLength) {
    const len = view.getUint8(curr);
    if (len === 0) {
      return curr + 1;
    }
    if ((len & 0xC0) === 0xC0) {
      if (curr + 2 > byteLength) return -1;
      return curr + 2;
    }
    curr += 1 + len;
  }
  return -1;
}

// Utility to skip a full DNS Resource Record (RR)
function skipResourceRecord(view, offset, byteLength) {
  let curr = skipName(view, offset, byteLength);
  if (curr === -1 || curr + 10 > byteLength) return -1;
  const rdLength = view.getUint16(curr + 8);
  curr += 10 + rdLength;
  if (curr > byteLength) return -1;
  return curr;
}

// Main function to add/override EDNS Client Subnet (ECS) in the DNS message buffer
function addEcsToDnsQuery(arrayBuffer, clientIp) {
  if (!arrayBuffer || arrayBuffer.byteLength < 12) return arrayBuffer;
  if (!clientIp || isPrivateIp(clientIp)) return arrayBuffer;

  const ipInfo = parseIp(clientIp);
  if (!ipInfo) return arrayBuffer;

  const view = new DataView(arrayBuffer);
  const additionalOffset = findAdditionalSectionOffset(view, arrayBuffer.byteLength);
  if (additionalOffset === -1) return arrayBuffer;

  const ecsOptionDataLength = 4 + ipInfo.bytes.length;
  const ecsOptionTotalLength = 4 + ecsOptionDataLength;
  const optRecordTotalLength = 11 + ecsOptionTotalLength;

  // Create new DNS packet containing the modified Additional section
  const newBuffer = new Uint8Array(additionalOffset + optRecordTotalLength);
  
  // Copy everything before the Additional section
  newBuffer.set(new Uint8Array(arrayBuffer, 0, additionalOffset));

  // Set ARCOUNT to 1 in the header (bytes 10 and 11) to indicate we have exactly 1 OPT record
  newBuffer[10] = 0x00;
  newBuffer[11] = 0x01;

  // Build OPT record with ECS option at the end of the packet
  let o = additionalOffset;
  newBuffer[o++] = 0x00; // NAME: root
  newBuffer[o++] = 0x00; newBuffer[o++] = 0x29; // TYPE: OPT (41)
  newBuffer[o++] = 0x04; newBuffer[o++] = 0xd0; // CLASS: UDP payload size (1232)
  newBuffer[o++] = 0x00; newBuffer[o++] = 0x00; newBuffer[o++] = 0x00; newBuffer[o++] = 0x00; // TTL: 0

  newBuffer[o++] = (ecsOptionTotalLength >> 8) & 0xff;
  newBuffer[o++] = ecsOptionTotalLength & 0xff; // RDLENGTH

  // EDNS Client Subnet Option
  newBuffer[o++] = 0x00; newBuffer[o++] = 0x08; // Option Code: 8 (ECS)
  newBuffer[o++] = (ecsOptionDataLength >> 8) & 0xff;
  newBuffer[o++] = ecsOptionDataLength & 0xff; // Option Length

  newBuffer[o++] = 0x00; newBuffer[o++] = ipInfo.family; // Family (1 for IPv4, 2 for IPv6)
  newBuffer[o++] = ipInfo.prefixLen; // Source Prefix-Length
  newBuffer[o++] = 0x00; // Scope Prefix-Length

  for (let i = 0; i < ipInfo.bytes.length; i++) {
    newBuffer[o++] = ipInfo.bytes[i];
  }

  return newBuffer.buffer;
}

// Converts ArrayBuffer back to standard base64url for DoH GET queries
function arrayBufferToBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const b64 = btoa(binary);
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Track database initialization across requests to avoid redundant table checks
let dbInitialized = false;

// Worker Main Handler (ES Module Format)
export default {
  async fetch(request, env, ctx) {
    // Basic safety fallback if KV or D1 bindings are missing
    if (!env.DB) {
      return new Response("Configuration Error: Cloudflare D1 'DB' binding is missing in wrangler.toml.", { status: 500 });
    }

    const url = new URL(request.url);
    const method = request.method;
    const clientIp = request.headers.get('CF-Connecting-IP') || '127.0.0.1';
    const userAgent = request.headers.get('User-Agent') || 'Unknown';

    // CORS preflight requests
    if (method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: corsHeaders()
      });
    }

    // Rate Limiting (Skip for high-speed DNS-over-HTTPS queries to prevent connection drops)
    const isDnsQuery = url.pathname.includes('/dns-query') || url.searchParams.has('dns');
    if (!isDnsQuery && checkRateLimit(clientIp)) {
      return jsonResponse({ error: 'Too many requests. Please slow down.' }, 429);
    }

    // Auto-init DB (Ensure schemas exist once per isolate lifetime)
    if (!dbInitialized) {
      try {
        await initDb(env.DB, env);
        dbInitialized = true;
      } catch (e) {
        return new Response(`Database Initialisation Error: ${e.message}`, { status: 500 });
      }
    }

    // Ensure JWT Secret is present, fallback to a stable D1 value if not configured in environment
    let jwtSecret = env.JWT_SECRET;
    if (!jwtSecret) {
      const storedSecret = await env.DB.prepare("SELECT value FROM settings WHERE key = 'jwt_secret'").first();
      if (storedSecret) {
        jwtSecret = storedSecret.value;
      } else {
        jwtSecret = crypto.randomUUID();
        await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('jwt_secret', ?)").bind(jwtSecret).run();
      }
    }

    // Route: Admin Login
    if (method === 'POST' && url.pathname === '/api/login') {
      try {
        const { password } = await request.json();
        if (!password) {
          return jsonResponse({ error: 'Password is required' }, 400);
        }

        const adminHashRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'admin_password_hash'").first();
        const computedHash = await sha256(password);

        if (!adminHashRow || computedHash !== adminHashRow.value) {
          return jsonResponse({ error: 'Invalid password' }, 401);
        }

        // Generate JWT Token (Expires in 24 hours)
        const payload = {
          role: 'admin',
          exp: Date.now() + 24 * 60 * 60 * 1000
        };
        const token = await signJwt(payload, jwtSecret);

        // Serve with secure token body and cookie
        return new Response(JSON.stringify({ success: true, token }), {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
            'Set-Cookie': `token=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400`,
            ...corsHeaders()
          }
        });
      } catch (e) {
        return jsonResponse({ error: 'Failed to process login' }, 500);
      }
    }

    // DNS over HTTPS Handler (Checks subscriptions, does accounting, forwards query)
    // Supports path variables /dns-query/:uuid and query params /dns-query?uuid=...
    const dohMatch = url.pathname.match(/^\/dns-query\/?([a-fA-F0-9\-]+)?$/) || url.pathname.match(/^\/([a-fA-F0-9\-]+)\/dns-query\/?$/);
    if (dohMatch) {
      const pathUuid = dohMatch[1];
      const queryUuid = url.searchParams.get('uuid');
      const rawUuid = pathUuid || queryUuid;
      const uuid = rawUuid ? rawUuid.toLowerCase() : null;

      const acceptHeader = request.headers.get('Accept') || '';
      const isBrowserVisit = method === 'GET' && !url.searchParams.has('dns') && acceptHeader.includes('text/html');

      if (!uuid) {
        // If they open standard /dns-query in browser, show a helpful message
        if (isBrowserVisit) {
          return new Response(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>DNS over HTTPS Gateway</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen flex items-center justify-center font-sans p-6">
  <div class="max-w-md w-full bg-slate-900 border border-slate-800 p-8 rounded-2xl shadow-xl text-center space-y-4">
    <div class="text-orange-500 font-bold text-3xl font-mono">CF DoH</div>
    <h1 class="text-xl font-bold text-white">DNS over HTTPS Gateway</h1>
    <p class="text-sm text-slate-400">Please provide your personal subscription UUID in the URL path, for example:</p>
    <code class="block bg-slate-950 p-3 rounded-lg text-xs text-orange-400 border border-slate-800 break-all select-all">https://${url.host}/dns-query/YOUR-SUBSCRIBER-UUID</code>
  </div>
</body>
</html>`, {
            status: 200,
            headers: { 'Content-Type': 'text/html; charset=utf-8' }
          });
        }
        return new Response("Missing subscriber UUID. Standard DNS queries must contain a valid dns payload.", { status: 400, headers: corsHeaders() });
      }

      // Look up subscription user (utilizing ultra-fast in-memory cache to avoid slow DB reads)
      const now = Date.now();
      let user = null;
      const cachedUser = userCache.get(uuid);
      if (cachedUser && (now - cachedUser.timestamp < USER_CACHE_TTL)) {
        user = cachedUser.data;
      } else {
        user = await env.DB.prepare("SELECT * FROM users WHERE uuid = ?").bind(uuid).first();
        if (user) {
          userCache.set(uuid, { data: user, timestamp: now });
        }
      }

      if (!user) {
        if (isBrowserVisit) {
          return new Response(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Subscription Not Found</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen flex items-center justify-center font-sans p-6">
  <div class="max-w-md w-full bg-slate-900 border border-slate-800 p-8 rounded-2xl shadow-xl text-center space-y-4">
    <div class="text-red-500 font-bold text-3xl font-mono">⚠️ ERROR</div>
    <h1 class="text-xl font-bold text-white">Invalid Subscription</h1>
    <p class="text-sm text-slate-400">The subscriber UUID provided in the URL was not found or is invalid. Please contact your administrator to obtain a valid subscription URL.</p>
  </div>
</body>
</html>`, {
            status: 404,
            headers: { 'Content-Type': 'text/html; charset=utf-8' }
          });
        }
        return new Response("User not found or invalid UUID.", { status: 403, headers: corsHeaders() });
      }

      // Retrieve all settings in a single fast query (or KV/in-memory cache)
      let settingsMap = null;
      if (inMemorySettings && (now - inMemorySettingsTime < SETTINGS_CACHE_TTL)) {
        settingsMap = inMemorySettings;
      } else {
        settingsMap = new Map();
        const cachedSettingsStr = env.KV ? await env.KV.get('active_settings_map') : null;
        if (cachedSettingsStr) {
          try {
            const cachedArr = JSON.parse(cachedSettingsStr);
            settingsMap = new Map(cachedArr);
          } catch (e) {
            console.error("Failed to parse cached settings:", e);
          }
        }

        if (settingsMap.size === 0) {
          const settingsRows = await env.DB.prepare("SELECT key, value FROM settings").all();
          if (settingsRows && settingsRows.results) {
            const arr = settingsRows.results.map(r => [r.key, r.value]);
            settingsMap = new Map(arr);
            if (env.KV) {
              await env.KV.put('active_settings_map', JSON.stringify(arr), { expirationTtl: 60 });
            }
          }
        }

        if (settingsMap.size > 0) {
          inMemorySettings = settingsMap;
          inMemorySettingsTime = now;
        }
      }

      // 1. Load Providers
      let providers = [];
      const providersStr = settingsMap.get('dns_providers');
      if (providersStr) {
        try {
          providers = JSON.parse(providersStr);
        } catch (e) {
          console.error("Failed to parse providers setting:", e);
        }
      }
      if (!providers || providers.length === 0) {
        providers = DEFAULT_DNS_PROVIDERS;
      }

      let defaultDnsName = settingsMap.get('default_dns') || 'Cloudflare';

      // Handle user's self-selected provider update from the subscriber dashboard page (POST with JSON)
      if (method === 'POST' && request.headers.get('Content-Type')?.includes('application/json')) {
        try {
          const { dns_provider } = await request.json();
          let nextDnsProvider = null;
          if (dns_provider) {
            const found = providers.find(p => p.enabled && p.name.toLowerCase() === dns_provider.toLowerCase());
            if (!found) {
              return jsonResponse({ error: 'The selected DNS resolver is disabled or invalid.' }, 400);
            }
            nextDnsProvider = found.name;
          }

          await env.DB.prepare("UPDATE users SET dns_provider = ? WHERE uuid = ?").bind(nextDnsProvider, uuid).run();
          userCache.delete(uuid); // Invalidate cache immediately
          dnsCache.clear(); // Clear DNS query caches

          return jsonResponse({ success: true, dns_provider: nextDnsProvider });
        } catch (e) {
          return jsonResponse({ error: `Update failed: ${e.message}` }, 500);
        }
      }

      // If this is a browser visit (GET request and no 'dns' query param), serve the beautiful dashboard page!
      if (isBrowserVisit) {
        return new Response(getSubscriberPageHTML(user, url.host, providers, defaultDnsName), {
          status: 200,
          headers: {
            'Content-Type': 'text/html; charset=utf-8',
            ...corsHeaders()
          }
        });
      }

      // If we got here and there is no 'dns' query param in a GET request, it means a non-browser client is making an invalid query
      if (method === 'GET' && !url.searchParams.has('dns')) {
        return new Response("Missing 'dns' query parameter for GET DoH request.", {
          status: 400,
          headers: {
            'Content-Type': 'text/plain',
            ...corsHeaders()
          }
        });
      }

      // Check user block status
      if (user.enabled !== 1) {
        return new Response("Subscription disabled by administrator.", { status: 403, headers: corsHeaders() });
      }

      // Check expiration status
      if (user.expire_at) {
        const expireTime = new Date(user.expire_at).getTime();
        if (Date.now() > expireTime) {
          // Disable the subscription immediately
          await env.DB.prepare("UPDATE users SET enabled = 0 WHERE uuid = ?").bind(uuid).run();
          return new Response("Subscription expired.", { status: 403, headers: corsHeaders() });
        }
      }

      // Check traffic limits
      if (user.used_gb >= user.traffic_limit_gb) {
        // Disable subscription immediately
        await env.DB.prepare("UPDATE users SET enabled = 0 WHERE uuid = ?").bind(uuid).run();
        return new Response("Traffic quota exceeded.", { status: 403, headers: corsHeaders() });
      }

      // Load other parameters
      const queriesPerGb = parseInt(settingsMap.get('queries_per_gb') || '5000', 10);
      defaultDnsName = settingsMap.get('default_dns') || 'Cloudflare';
      const cfMode = settingsMap.get('cloudflare_mode') || 'Automatic';
      const customUa = settingsMap.get('custom_user_agent') || '';
      const isCacheEnabled = settingsMap.get('dns_cache_enabled') === 'true';
      const isEcsEnabled = settingsMap.get('dns_ecs_enabled') === 'true';

      // Determine DNS Provider URL
      let targetProvider = null;
      if (providers && providers.length > 0) {
        if (user.dns_provider) {
          targetProvider = providers.find(p => p.enabled && p.name.toLowerCase() === user.dns_provider.toLowerCase());
        }
        if (!targetProvider) {
          // Fallback to default setting
          targetProvider = providers.find(p => p.name.toLowerCase() === defaultDnsName.toLowerCase() && p.enabled) || providers.find(p => p.enabled);
        }
      }
      if (!targetProvider) {
        targetProvider = DEFAULT_DNS_PROVIDERS.find(p => p.name === 'Cloudflare');
      }

      let winningProviderName = targetProvider ? targetProvider.name : 'Unknown';

      const targetUrlStr = targetProvider ? targetProvider.url : 'https://1.1.1.1/dns-query';
      const targetUrl = new URL(targetUrlStr);

      // Apply Cloudflare Options / DNS Protocol IP Forcing to force IPv4/IPv6 outgoing connection
      const host = targetUrl.host.toLowerCase();
      if (cfMode === 'IPv4') {
        if (host.includes('1.1.1.1') || host.includes('cloudflare')) {
          targetUrl.host = '1.1.1.1';
        } else if (host.includes('8.8.8.8') || host.includes('google')) {
          targetUrl.host = '8.8.8.8';
        } else if (host.includes('9.9.9.9') || host.includes('quad9')) {
          targetUrl.host = '9.9.9.9';
        } else if (host.includes('adguard')) {
          targetUrl.host = '94.140.14.14';
        }
      } else if (cfMode === 'IPv6') {
        if (host.includes('1.1.1.1') || host.includes('cloudflare')) {
          targetUrl.host = '[2606:4700:4700::1111]';
        } else if (host.includes('8.8.8.8') || host.includes('google')) {
          targetUrl.host = '[2001:4860:4860::8888]';
        } else if (host.includes('9.9.9.9') || host.includes('quad9')) {
          targetUrl.host = '[2620:fe::fe]';
        } else if (host.includes('adguard')) {
          targetUrl.host = '[2a10:50c0::ad1:ff]';
        }
      }

      // Copy all incoming search parameters to the target URL, except 'provider'
      for (const [key, value] of url.searchParams.entries()) {
        if (key !== 'provider') {
          targetUrl.searchParams.set(key, value);
        }
      }

      // Prepare request forwarding headers
      const forwardHeaders = new Headers();
      forwardHeaders.set('Accept', 'application/dns-message');
      
      // Keep Content-Type for POST requests
      if (method === 'POST') {
        forwardHeaders.set('Content-Type', request.headers.get('Content-Type') || 'application/dns-message');
      }

      // Custom User-Agent
      if (customUa) {
        forwardHeaders.set('User-Agent', customUa);
      } else {
        forwardHeaders.set('User-Agent', 'DNS-over-HTTPS-Subscription/1.0');
      }

      // Forward DoH Request
      let dohResponseBuffer = null;
      let dohResponseStatus = 200;
      let dohResponseStatusText = 'OK';
      let dohResponseHeaders = null;
      let usedCache = false;

      let requestBody = null;
      try {
        requestBody = method === 'POST' ? await request.arrayBuffer() : null;
      } catch (err) {
        console.warn("Failed to parse request body:", err);
      }

      // Build DNS in-memory cache key
      let dnsCacheKey = null;
      if (isCacheEnabled) {
        const providerKey = targetProvider ? targetProvider.name : 'Unknown';
        let queryKey = '';
        if (method === 'GET') {
          queryKey = url.searchParams.get('dns') || '';
        } else if (requestBody) {
          // Fast arrayBuffer to base64 for key hashing
          let binary = '';
          const bytes = new Uint8Array(requestBody);
          const len = Math.min(bytes.byteLength, 1024); // Limit scan for fast hashing
          for (let i = 0; i < len; i++) {
            binary += String.fromCharCode(bytes[i]);
          }
          queryKey = btoa(binary) + '_' + bytes.byteLength;
        }
        const ipInfo = isEcsEnabled ? parseIp(clientIp) : null;
        const ecsKey = ipInfo ? `${ipInfo.family}_${ipInfo.bytes.join('.')}` : 'no_ecs';
        dnsCacheKey = `${providerKey}:${queryKey}:${ecsKey}`;
      }

      // Check in-memory DNS cache
      if (isCacheEnabled && dnsCacheKey) {
        const cachedDns = dnsCache.get(dnsCacheKey);
        if (cachedDns && (Date.now() - cachedDns.timestamp < DNS_CACHE_TTL)) {
          dohResponseBuffer = cachedDns.body;
          dohResponseStatus = cachedDns.status;
          dohResponseStatusText = cachedDns.statusText;
          dohResponseHeaders = cachedDns.headers;
          usedCache = true;
        }
      }

      if (!dohResponseBuffer) {
        try {
          // Extract queried domain name (QNAME) for logging or inspection if needed
          let originalDnsBuffer = null;
          if (method === 'GET') {
            const dnsParam = url.searchParams.get('dns');
            if (dnsParam) {
              try {
                let b64 = dnsParam.replace(/-/g, '+').replace(/_/g, '/');
                while (b64.length % 4) b64 += '=';
                const binary = atob(b64);
                const bytes = new Uint8Array(binary.length);
                for (let i = 0; i < binary.length; i++) {
                  bytes[i] = binary.charCodeAt(i);
                }
                originalDnsBuffer = bytes.buffer;
              } catch (e) {}
            }
          } else if (method === 'POST' && requestBody) {
            originalDnsBuffer = requestBody;
          }

          let dnsBuffer = originalDnsBuffer;

          // Inject EDNS Client Subnet (ECS) option to preserve geo-routing, low latency, and bypass game regional restrictions (Only if enabled and NOT a gaming/anti-sanction DNS)
          const shouldInjectEcs = isEcsEnabled && !isGamingDns(winningProviderName);
          if (dnsBuffer && shouldInjectEcs) {
            dnsBuffer = addEcsToDnsQuery(dnsBuffer, clientIp);
            if (method === 'GET') {
              targetUrl.searchParams.set('dns', arrayBufferToBase64Url(dnsBuffer));
            }
          }

          function extractQName(buffer) {
            if (!buffer || buffer.byteLength < 12) return null;
            try {
              const view = new DataView(buffer);
              const qcount = view.getUint16(4);
              if (qcount === 0) return null;

              let offset = 12;
              const labels = [];
              while (offset < buffer.byteLength) {
                const len = view.getUint8(offset);
                if (len === 0) {
                  break;
                }
                if ((len & 0xC0) === 0xC0) {
                  break;
                }
                offset++;
                if (offset + len > buffer.byteLength) break;
                const labelBytes = new Uint8Array(buffer, offset, len);
                let label = '';
                for (let i = 0; i < labelBytes.length; i++) {
                  label += String.fromCharCode(labelBytes[i]);
                }
                labels.push(label);
                offset += len;
              }
              return labels.join('.').toLowerCase();
            } catch (err) {
              return null;
            }
          }

          const queriedDomain = extractQName(dnsBuffer);

          const primaryUrl = targetUrl.toString();
          const primaryName = winningProviderName;

          // Helper to fetch with an exact timeout
          const fetchWithTimeout = async (urlStr, options, timeoutMs) => {
            const controller = new AbortController();
            const id = setTimeout(() => controller.abort(), timeoutMs);
            try {
              const r = await fetch(urlStr, { ...options, signal: controller.signal });
              clearTimeout(id);
              if (!r.ok) {
                throw new Error(`Upstream returned status ${r.status}`);
              }
              return r;
            } catch (err) {
              clearTimeout(id);
              throw err;
            }
          };

          let res;
          try {
            const fetchOptions = {
              method,
              headers: forwardHeaders
            };
            if (method !== 'GET' && method !== 'HEAD' && dnsBuffer) {
              fetchOptions.body = dnsBuffer;
            }

            try {
              // Perform DoH query to selected provider with a robust 5000ms timeout
              res = await fetchWithTimeout(primaryUrl, fetchOptions, 5000);
            } catch (firstErr) {
              console.warn(`Primary DNS query to ${primaryName} failed, retrying same provider (without ECS/original buffer for compatibility)... Error:`, firstErr);
              // Retry exactly once on the SAME user-selected provider to ensure maximum reliability with no cross-fallback leaks
              // But on retry, we use the original unmodified DNS buffer (no ECS) in case ECS/packet manipulation was the cause of the failure!
              let retryUrl = primaryUrl;
              let retryOptions = { ...fetchOptions };

              if (shouldInjectEcs) {
                const cleanUrl = new URL(targetUrl.toString());
                if (method === 'GET' && originalDnsBuffer) {
                  cleanUrl.searchParams.set('dns', arrayBufferToBase64Url(originalDnsBuffer));
                }
                retryUrl = cleanUrl.toString();
                if (method !== 'GET' && method !== 'HEAD' && originalDnsBuffer) {
                  retryOptions.body = originalDnsBuffer;
                }
              }

              res = await fetchWithTimeout(retryUrl, retryOptions, 5000);
            }
          } catch (err) {
            console.error(`DNS query to selected provider ${primaryName} failed completely:`, err);
            throw err;
          }

          dohResponseStatus = res.status;
          dohResponseStatusText = res.statusText;
          dohResponseHeaders = {};
          for (const [k, v] of res.headers.entries()) {
            dohResponseHeaders[k] = v;
          }
          dohResponseBuffer = await res.arrayBuffer();

          // Store in in-memory DNS cache
          if (isCacheEnabled && dnsCacheKey && dohResponseStatus === 200) {
            dnsCache.set(dnsCacheKey, {
              body: dohResponseBuffer,
              status: dohResponseStatus,
              statusText: dohResponseStatusText,
              headers: dohResponseHeaders,
              timestamp: Date.now()
            });
          }
        } catch (err) {
          return new Response(`Upstream DoH Forwarding Failed: ${err.message}`, { status: 502, headers: corsHeaders() });
        }
      }

      // SUCCESSFUL REQUEST: Increment Counters and Log activity
      if (dohResponseStatus === 200) {
        const updatedQueryCount = user.query_count + 1;
        const updatedUsedGb = updatedQueryCount / queriesPerGb;
        const updatedRemainingGb = user.traffic_limit_gb - updatedUsedGb;
        const isoNow = new Date().toISOString();

        // Update in-memory user cache with the updated data so we don't serve stale stats from cache
        // ONLY if the cache hasn't been deleted or updated by an admin in the meantime!
        const currentCached = userCache.get(uuid);
        if (currentCached && currentCached.data.dns_provider === user.dns_provider && currentCached.data.enabled === user.enabled) {
          const updatedUserData = {
            ...user,
            query_count: updatedQueryCount,
            used_gb: updatedUsedGb,
            remaining_gb: updatedRemainingGb,
            last_activity: isoNow
          };
          userCache.set(uuid, { data: updatedUserData, timestamp: Date.now() });
        }

        // Transactional-style DB updates (Fully asynchronous, non-blocking)
        ctx.waitUntil((async () => {
          try {
            await env.DB.prepare(`
              UPDATE users 
              SET query_count = ?, used_gb = ?, remaining_gb = ?, last_activity = ?
              WHERE uuid = ?
            `).bind(updatedQueryCount, updatedUsedGb, updatedRemainingGb, isoNow, uuid).run();

            await env.DB.prepare(`
              INSERT INTO traffic_logs (uuid, timestamp, provider, client_ip, user_agent)
              VALUES (?, ?, ?, ?, ?)
            `).bind(uuid, isoNow, winningProviderName, clientIp, userAgent).run();
          } catch (dbErr) {
            console.error('Failed to log DNS usage to DB:', dbErr);
          }
        })());
      }

      // Return DNS message response with correct binary headers
      // We clean headers to prevent transfer/compression/length decoding issues on the client side
      const responseHeaders = new Headers();
      if (dohResponseHeaders) {
        for (const [k, v] of Object.entries(dohResponseHeaders)) {
          const lowerK = k.toLowerCase();
          if (lowerK !== 'content-encoding' && lowerK !== 'content-length' && lowerK !== 'transfer-encoding') {
            responseHeaders.set(k, v);
          }
        }
      }
      if (!responseHeaders.has('content-type')) {
        responseHeaders.set('content-type', 'application/dns-message');
      }
      responseHeaders.set('Access-Control-Allow-Origin', '*');
      responseHeaders.set('X-Cache', usedCache ? 'HIT' : 'MISS');

      const clientResponse = new Response(dohResponseBuffer, {
        status: dohResponseStatus,
        statusText: dohResponseStatusText,
        headers: responseHeaders
      });
      return clientResponse;
    }

    // ALL SECURE API ROUTES (/api/*) REQUIRED ADMIN AUTH
    if (url.pathname.startsWith('/api/')) {
      const auth = await authenticateAdmin(request, jwtSecret);
      if (!auth) {
        return jsonResponse({ error: 'Unauthorized. Admin login required.' }, 401);
      }

      // GET /api/users - Fetch subscriber list with search/filtering
      if (method === 'GET' && url.pathname === '/api/users') {
        const search = url.searchParams.get('search') || '';
        const statusFilter = url.searchParams.get('status') || 'all'; // 'all', 'active', 'disabled', 'expired'
        
        let query = "SELECT * FROM users";
        let countQuery = "SELECT COUNT(*) as count FROM users";
        const params = [];
        const countParams = [];

        const conditions = [];
        if (search) {
          conditions.push("(username LIKE ? OR uuid LIKE ?)");
          params.push(`%${search}%`);
          params.push(`%${search}%`);
          countParams.push(`%${search}%`);
          countParams.push(`%${search}%`);
        }

        if (statusFilter === 'active') {
          conditions.push("enabled = 1 AND (expire_at IS NULL OR datetime(expire_at) > datetime('now')) AND used_gb < traffic_limit_gb");
        } else if (statusFilter === 'disabled') {
          conditions.push("enabled = 0");
        } else if (statusFilter === 'expired') {
          conditions.push("expire_at IS NOT NULL AND datetime(expire_at) <= datetime('now')");
        }

        if (conditions.length > 0) {
          const condStr = " WHERE " + conditions.join(" AND ");
          query += condStr;
          countQuery += condStr;
        }

        query += " ORDER BY id DESC";

        try {
          const list = await env.DB.prepare(query).bind(...params).all();
          const countRow = await env.DB.prepare(countQuery).bind(...countParams).first();
          
          return jsonResponse({
            users: list.results || [],
            total: countRow?.count || 0
          });
        } catch (e) {
          return jsonResponse({ error: `Fetch failed: ${e.message}` }, 500);
        }
      }

      // POST /api/users - Create custom subscriber
      if (method === 'POST' && url.pathname === '/api/users') {
        try {
          const { username, traffic_limit_gb, expire_at, dns_provider } = await request.json();
          if (!username) {
            return jsonResponse({ error: 'Username is required' }, 400);
          }

          const limit = parseFloat(traffic_limit_gb) || 10.0; // default 10GB
          const uuid = crypto.randomUUID();
          const isoNow = new Date().toISOString();

          // Expiration handling
          let expiry = null;
          if (expire_at) {
            expiry = new Date(expire_at).toISOString();
          }

          const providerToSave = dns_provider || null;

          await env.DB.prepare(`
            INSERT INTO users (uuid, username, created_at, expire_at, traffic_limit_gb, query_count, used_gb, remaining_gb, enabled, last_activity, dns_provider)
            VALUES (?, ?, ?, ?, ?, 0, 0.0, ?, 1, NULL, ?)
          `).bind(uuid, username, isoNow, expiry, limit, limit, providerToSave).run();

          return jsonResponse({ success: true, uuid });
        } catch (e) {
          return jsonResponse({ error: `Creation failed: ${e.message}` }, 500);
        }
      }

      // PUT /api/users/:uuid - Edit user details
      const userEditMatch = url.pathname.match(/^\/api\/users\/([a-f0-9\-]+)$/);
      if (method === 'PUT' && userEditMatch) {
        const uuid = userEditMatch[1];
        try {
          const { username, traffic_limit_gb, expire_at, enabled, dns_provider } = await request.json();
          
          const currentUser = await env.DB.prepare("SELECT * FROM users WHERE uuid = ?").bind(uuid).first();
          if (!currentUser) {
            return jsonResponse({ error: 'User not found' }, 404);
          }

          const nextUsername = username !== undefined ? username : currentUser.username;
          const nextLimit = traffic_limit_gb !== undefined ? parseFloat(traffic_limit_gb) : currentUser.traffic_limit_gb;
          const nextExpiry = expire_at !== undefined ? (expire_at ? new Date(expire_at).toISOString() : null) : currentUser.expire_at;
          const nextEnabled = enabled !== undefined ? (enabled ? 1 : 0) : currentUser.enabled;
          const nextDnsProvider = dns_provider !== undefined ? (dns_provider || null) : currentUser.dns_provider;

          const nextRemaining = nextLimit - currentUser.used_gb;

          await env.DB.prepare(`
            UPDATE users
            SET username = ?, traffic_limit_gb = ?, expire_at = ?, enabled = ?, remaining_gb = ?, dns_provider = ?
            WHERE uuid = ?
          `).bind(nextUsername, nextLimit, nextExpiry, nextEnabled, nextRemaining, nextDnsProvider, uuid).run();

          userCache.delete(uuid); // Clear user cache so changes are immediate
          dnsCache.clear(); // Clear DNS cache so the updated resolver is used immediately

          return jsonResponse({ success: true });
        } catch (e) {
          return jsonResponse({ error: `Update failed: ${e.message}` }, 500);
        }
      }

      // DELETE /api/users/:uuid - Delete subscriber
      const userDeleteMatch = url.pathname.match(/^\/api\/users\/([a-f0-9\-]+)$/);
      if (method === 'DELETE' && userDeleteMatch) {
        const uuid = userDeleteMatch[1];
        try {
          await env.DB.prepare("DELETE FROM users WHERE uuid = ?").bind(uuid).run();
          await env.DB.prepare("DELETE FROM traffic_logs WHERE uuid = ?").bind(uuid).run();
          return jsonResponse({ success: true });
        } catch (e) {
          return jsonResponse({ error: `Deletion failed: ${e.message}` }, 500);
        }
      }

      // POST /api/reset/:uuid - Reset subscriber traffic & queries
      const userResetMatch = url.pathname.match(/^\/api\/reset\/([a-f0-9\-]+)$/);
      if (method === 'POST' && userResetMatch) {
        const uuid = userResetMatch[1];
        try {
          const user = await env.DB.prepare("SELECT traffic_limit_gb FROM users WHERE uuid = ?").bind(uuid).first();
          if (!user) {
            return jsonResponse({ error: 'User not found' }, 404);
          }

          await env.DB.prepare(`
            UPDATE users
            SET query_count = 0, used_gb = 0.0, remaining_gb = ?, enabled = 1
            WHERE uuid = ?
          `).bind(user.traffic_limit_gb, uuid).run();

          return jsonResponse({ success: true });
        } catch (e) {
          return jsonResponse({ error: `Reset failed: ${e.message}` }, 500);
        }
      }

      // GET /api/statistics - Dashboard charts, analytics and general logs
      if (method === 'GET' && url.pathname === '/api/statistics') {
        try {
          // Total subscriber aggregations
          const totalUsers = await env.DB.prepare("SELECT COUNT(*) as count FROM users").first();
          const activeUsers = await env.DB.prepare("SELECT COUNT(*) as count FROM users WHERE enabled = 1 AND (expire_at IS NULL OR datetime(expire_at) > datetime('now')) AND used_gb < traffic_limit_gb").first();
          const disabledUsers = await env.DB.prepare("SELECT COUNT(*) as count FROM users WHERE enabled = 0").first();
          const expiredUsers = await env.DB.prepare("SELECT COUNT(*) as count FROM users WHERE expire_at IS NOT NULL AND datetime(expire_at) <= datetime('now')").first();

          // Query aggregations
          const totals = await env.DB.prepare("SELECT SUM(query_count) as total_queries, SUM(used_gb) as total_gb, SUM(traffic_limit_gb) as total_limit FROM users").first();

          // Traffic logs for table & CSV exporting
          const logs = await env.DB.prepare("SELECT * FROM traffic_logs ORDER BY id DESC LIMIT 500").all();

          // Chart data aggregates
          // 1. Queries per DNS provider
          const providerStats = await env.DB.prepare(`
            SELECT provider, COUNT(*) as count 
            FROM traffic_logs 
            GROUP BY provider 
            ORDER BY count DESC
          `).all();

          // 2. Daily queries (Last 7 Days)
          const dailyStats = await env.DB.prepare(`
            SELECT substr(timestamp, 1, 10) as day, COUNT(*) as count
            FROM traffic_logs
            WHERE datetime(timestamp) >= datetime('now', '-7 days')
            GROUP BY day
            ORDER BY day ASC
          `).all();

          // 3. Most active users (Top 10)
          const topUsers = await env.DB.prepare(`
            SELECT username, query_count, used_gb, uuid
            FROM users
            ORDER BY query_count DESC
            LIMIT 10
          `).all();

          // Load Providers & options config
          const configProvidersRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'dns_providers'").first();
          const currentProviders = configProvidersRow ? JSON.parse(configProvidersRow.value) : DEFAULT_DNS_PROVIDERS;

          const defaultDnsRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'default_dns'").first();
          const defaultDns = defaultDnsRow?.value || 'Cloudflare';

          const cfModeRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'cloudflare_mode'").first();
          const cfMode = cfModeRow?.value || 'Automatic';

          const cacheEnabledRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'dns_cache_enabled'").first();
          const dnsCacheVal = cacheEnabledRow?.value || 'false';

          const dnsEcsRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'dns_ecs_enabled'").first();
          const dnsEcsVal = dnsEcsRow?.value || 'false';

          const customUaRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'custom_user_agent'").first();
          const customUa = customUaRow?.value || '';

          const queriesPerGbRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'queries_per_gb'").first();
          const queriesPerGb = queriesPerGbRow?.value || '5000';

          return jsonResponse({
            summary: {
              totalUsers: totalUsers?.count || 0,
              activeUsers: activeUsers?.count || 0,
              disabledUsers: disabledUsers?.count || 0,
              expiredUsers: expiredUsers?.count || 0,
              totalQueries: totals?.total_queries || 0,
              usedGb: parseFloat((totals?.total_gb || 0).toFixed(4)),
              totalLimitGb: parseFloat((totals?.total_limit || 0).toFixed(2)),
              remainingGb: parseFloat(((totals?.total_limit || 0) - (totals?.total_gb || 0)).toFixed(4))
            },
            logs: logs.results || [],
            providers: currentProviders,
            config: {
              defaultDns,
              cfMode,
              dnsCache: dnsCacheVal,
              dnsEcs: dnsEcsVal,
              customUa,
              queriesPerGb
            },
            charts: {
              providers: providerStats.results || [],
              daily: dailyStats.results || [],
              topUsers: topUsers.results || []
            }
          });
        } catch (e) {
          return jsonResponse({ error: `Stats aggregation failed: ${e.message}` }, 500);
        }
      }

      // POST /api/settings - Update application settings
      if (method === 'POST' && url.pathname === '/api/settings') {
        try {
          const { defaultDns, cfMode, dnsCache: dnsCacheParam, dnsEcs: dnsEcsParam, customUa, queriesPerGb, adminPassword, providers } = await request.json();

          // Fetch current providers list to validate defaultDns
          let currentProviders = providers;
          if (!currentProviders) {
            const configProvidersRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'dns_providers'").first();
            currentProviders = configProvidersRow ? JSON.parse(configProvidersRow.value) : DEFAULT_DNS_PROVIDERS;
          }

          if (defaultDns !== undefined) {
            const selectedProv = currentProviders.find(p => p.name.toLowerCase() === defaultDns.toLowerCase());
            if (selectedProv && !selectedProv.enabled) {
              return jsonResponse({ error: 'Cannot set a disabled provider as the default resolver! Please enable it first.' }, 400);
            }
            await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('default_dns', ?)").bind(defaultDns).run();
          }
          if (cfMode !== undefined) {
            await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('cloudflare_mode', ?)").bind(cfMode).run();
          }
          if (dnsCacheParam !== undefined) {
            await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('dns_cache_enabled', ?)").bind(dnsCacheParam ? 'true' : 'false').run();
          }
          if (dnsEcsParam !== undefined) {
            await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('dns_ecs_enabled', ?)").bind(dnsEcsParam ? 'true' : 'false').run();
          }
          if (customUa !== undefined) {
            await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('custom_user_agent', ?)").bind(customUa).run();
          }
          if (queriesPerGb !== undefined) {
            await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('queries_per_gb', ?)").bind(queriesPerGb.toString()).run();
          }
          if (adminPassword) {
            const newHash = await sha256(adminPassword);
            await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('admin_password_hash', ?)").bind(newHash).run();
          }
          if (providers) {
            // Check if currently configured default DNS is being disabled
            const defaultDnsRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'default_dns'").first();
            const defaultDnsName = defaultDnsRow?.value || 'Cloudflare';
            const defaultProv = providers.find(p => p.name.toLowerCase() === defaultDnsName.toLowerCase());
            if (defaultProv && !defaultProv.enabled) {
              return jsonResponse({ error: 'Cannot disable the default resolver! Please set another active provider as the default first.' }, 400);
            }
            await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('dns_providers', ?)").bind(JSON.stringify(providers)).run();
          }

          // Invalidate KV Caches
          if (env.KV) {
            await env.KV.delete('active_settings_map');
            await env.KV.delete('active_dns_providers');
          }

          // Clear local in-memory caches immediately
          inMemorySettings = null;
          inMemorySettingsTime = 0;
          dnsCache.clear();

          return jsonResponse({ success: true });
        } catch (e) {
          return jsonResponse({ error: `Settings update failed: ${e.message}` }, 500);
        }
      }
    }

    // Default Fallback: Serve the Responsive Admin Dashboard SPA (HTML + Tailwind + Vanilla JS)
    return new Response(ADMIN_HTML, {
      status: 200,
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        ...corsHeaders()
      }
    });
  }
};

// EMBEDDED SINGLE-PAGE APPLICATION: HTML / CSS / JS
const ADMIN_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DoH Subscriptions Admin</title>
  <!-- Tailwind CSS Play CDN -->
  <script src="https://cdn.tailwindcss.com"></script>
  <!-- Inter & Space Grotesk fonts -->
  <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Space+Grotesk:wght@500;600;700&display=swap">
  <!-- Chart.js -->
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <!-- Lucide Icons -->
  <script src="https://unpkg.com/lucide@latest"></script>
  
  <style>
    :root {
      --cf-orange: #f6821f;
      --cf-dark: #0f172a;
      --cf-card: #1e293b;
      --cf-border: #334155;
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
    }
    body {
      font-family: 'Inter', sans-serif;
    }
    .font-display {
      font-family: 'Space Grotesk', sans-serif;
    }
    
    /* Custom High Density classes */
    .status-pill {
      display: inline-block;
      padding: 2px 8px !important;
      border-radius: 4px !important;
      font-size: 11px !important;
      font-weight: 600 !important;
      text-align: center !important;
      width: fit-content !important;
      letter-spacing: 0.05em !important;
    }
    .status-active {
      background: rgba(34, 197, 94, 0.15) !important;
      color: #4ade80 !important;
      border: 1px solid rgba(34, 197, 94, 0.25) !important;
    }
    .status-disabled {
      background: rgba(239, 68, 68, 0.15) !important;
      color: #f87171 !important;
      border: 1px solid rgba(239, 68, 68, 0.25) !important;
    }
    .status-expired {
      background: rgba(245, 158, 11, 0.15) !important;
      color: #fbbf24 !important;
      border: 1px solid rgba(245, 158, 11, 0.25) !important;
    }

    /* Tight scrollbars */
    ::-webkit-scrollbar {
      width: 6px;
      height: 6px;
    }
    ::-webkit-scrollbar-track {
      background: transparent;
    }
    ::-webkit-scrollbar-thumb {
      background: rgba(156, 163, 175, 0.25);
      border-radius: 3px;
    }
    ::-webkit-scrollbar-thumb:hover {
      background: rgba(156, 163, 175, 0.45);
    }
    
    /* Table modifications for high density */
    th {
      font-size: 11px !important;
      text-transform: uppercase !important;
      letter-spacing: 0.05em !important;
      font-weight: 600 !important;
      padding: 8px 12px !important;
    }
    td {
      padding: 8px 12px !important;
    }
    
    /* Monospace formatting */
    .mono {
      font-family: 'Fira Code', 'JetBrains Mono', 'Courier New', Courier, monospace !important;
      color: var(--cf-orange) !important;
      font-size: 12px !important;
    }
  </style>
  <script>
    // Config tailwind fonts and color maps to inject Cloudflare Orange styling
    tailwind.config = {
      darkMode: 'class',
      theme: {
        extend: {
          colors: {
            blue: {
              50: '#fffdfa',
              100: '#fff3e6',
              200: '#ffe2cc',
              300: '#ffc199',
              400: '#ffa166',
              500: '#f6821f', // Main Cloudflare Orange
              600: '#e06e12',
              700: '#b8540a',
              800: '#913f05',
              900: '#692c02',
              950: '#421a00'
            },
            slate: {
              900: '#0f172a',
              950: '#0b1120'
            }
          },
          fontFamily: {
            sans: ['Inter', 'sans-serif'],
            display: ['Space Grotesk', 'sans-serif'],
          }
        }
      }
    }
  </script>
</head>
<body class="bg-slate-50 text-slate-900 transition-colors duration-200 dark:bg-slate-950 dark:text-slate-100 min-h-screen flex flex-col">

  <!-- LOGIN PANEL OVERLAY -->
  <div id="login-overlay" class="fixed inset-0 bg-slate-950/80 backdrop-blur-md flex items-center justify-center z-50 transition-opacity duration-300">
    <div class="bg-white dark:bg-slate-900 p-8 rounded-2xl shadow-2xl max-w-md w-full border border-slate-200 dark:border-slate-800 transform transition-all duration-300 scale-100">
      <div class="flex flex-col items-center mb-6">
        <div class="p-3 bg-blue-500/10 text-blue-500 rounded-full mb-3">
          <i data-lucide="shield-check" class="w-10 h-10"></i>
        </div>
        <h1 class="font-display text-2xl font-bold">Secure Admin Access</h1>
        <p class="text-xs text-slate-500 mt-1">DNS-over-HTTPS Subscriptions Gateway</p>
      </div>
      <form id="login-form" class="space-y-4">
        <div>
          <label class="block text-xs font-semibold mb-1 text-slate-500 uppercase tracking-wider">Admin Password</label>
          <input type="password" id="login-password" class="w-full px-4 py-3 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 focus:outline-none focus:ring-2 focus:ring-blue-500" placeholder="••••••••" required>
        </div>
        <div id="login-error" class="hidden text-sm text-red-500 bg-red-500/10 p-3 rounded-lg border border-red-500/20 text-center"></div>
        <button type="submit" class="w-full bg-blue-600 hover:bg-blue-700 active:bg-blue-800 text-white font-medium py-3 rounded-xl transition duration-200 shadow-lg shadow-blue-500/20 flex items-center justify-center gap-2">
          <span>Authenticate</span>
          <i data-lucide="arrow-right" class="w-4 h-4"></i>
        </button>
      </form>
    </div>
  </div>

  <!-- AUTHENTICATED APP CONTENT -->
  <div id="app-content" class="hidden flex-1 flex flex-col md:flex-row min-h-screen">
    
    <!-- LEFT SIDEBAR NAVIGATION (Desktop) -->
    <aside class="hidden md:flex flex-col w-64 bg-slate-950 border-r border-slate-200 dark:border-slate-800 shrink-0 text-slate-400">
      <div class="p-6 border-b border-slate-200 dark:border-slate-800 flex items-center gap-3">
        <div class="p-2.5 bg-blue-500 text-white rounded-xl font-bold font-display text-base tracking-tight flex items-center justify-center w-10 h-10 shrink-0 shadow-lg shadow-blue-500/20">
          CF
        </div>
        <div>
          <span class="font-display font-bold text-base text-slate-900 dark:text-white tracking-tight block">DoH Admin</span>
          <span class="text-[10px] block text-emerald-500 font-medium">● Connected to D1</span>
        </div>
      </div>
      <nav class="flex-1 p-4 space-y-1">
        <button onclick="switchTab('dashboard')" id="sidebar-tab-dashboard" class="w-full flex items-center gap-3 px-4 py-3 text-sm font-medium rounded-xl transition duration-150 bg-blue-500/10 text-blue-600 dark:text-blue-400 border-l-4 border-blue-500 pl-3">
          <i data-lucide="layout-dashboard" class="w-5 h-5"></i>
          <span>Dashboard</span>
        </button>
        <button onclick="switchTab('users')" id="sidebar-tab-users" class="w-full flex items-center gap-3 px-4 py-3 text-sm font-medium rounded-xl transition duration-150 hover:bg-slate-100 dark:hover:bg-slate-900 hover:text-slate-900 dark:hover:text-slate-100 border-l-4 border-transparent">
          <i data-lucide="users" class="w-5 h-5"></i>
          <span>Subscriptions</span>
        </button>
        <button onclick="switchTab('providers')" id="sidebar-tab-providers" class="w-full flex items-center gap-3 px-4 py-3 text-sm font-medium rounded-xl transition duration-150 hover:bg-slate-100 dark:hover:bg-slate-900 hover:text-slate-900 dark:hover:text-slate-100 border-l-4 border-transparent">
          <i data-lucide="globe" class="w-5 h-5"></i>
          <span>DNS Providers</span>
        </button>
        <button onclick="switchTab('logs')" id="sidebar-tab-logs" class="w-full flex items-center gap-3 px-4 py-3 text-sm font-medium rounded-xl transition duration-150 hover:bg-slate-100 dark:hover:bg-slate-900 hover:text-slate-900 dark:hover:text-slate-100 border-l-4 border-transparent">
          <i data-lucide="terminal" class="w-5 h-5"></i>
          <span>Traffic Logs</span>
        </button>
        <button onclick="switchTab('statistics')" id="sidebar-tab-statistics" class="w-full flex items-center gap-3 px-4 py-3 text-sm font-medium rounded-xl transition duration-150 hover:bg-slate-100 dark:hover:bg-slate-900 hover:text-slate-900 dark:hover:text-slate-100 border-l-4 border-transparent">
          <i data-lucide="bar-chart-3" class="w-5 h-5"></i>
          <span>Statistics</span>
        </button>
        <button onclick="switchTab('settings')" id="sidebar-tab-settings" class="w-full flex items-center gap-3 px-4 py-3 text-sm font-medium rounded-xl transition duration-150 hover:bg-slate-100 dark:hover:bg-slate-900 hover:text-slate-900 dark:hover:text-slate-100 border-l-4 border-transparent">
          <i data-lucide="settings" class="w-5 h-5"></i>
          <span>Settings</span>
        </button>
      </nav>
      <!-- Footer details inside sidebar -->
      <div class="p-6 border-t border-slate-200 dark:border-slate-800 text-[11px] leading-relaxed">
        <div class="flex items-center gap-2 mb-1">
          <div class="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></div>
          <span class="font-semibold text-slate-800 dark:text-slate-200">v1.2.0-stable</span>
        </div>
        <p class="text-slate-500">Cloudflare D1 Enabled</p>
      </div>
    </aside>

    <!-- RIGHT CONTAINER (HEADER + SCROLLABLE BODY) -->
    <div class="flex-1 flex flex-col min-w-0">
      <!-- TOP NAVIGATION BAR (For mobile logo and desktop controls) -->
      <header class="bg-white dark:bg-slate-900 border-b border-slate-200 dark:border-slate-800 sticky top-0 z-40 shrink-0">
        <div class="px-4 sm:px-6 lg:px-8">
          <div class="flex items-center justify-between h-16">
            <!-- Mobile Logo -->
            <div class="flex items-center gap-3 md:hidden">
              <div class="p-2 bg-blue-500 text-white rounded-xl">
                <i data-lucide="server" class="w-5 h-5"></i>
              </div>
              <div>
                <span class="font-display font-bold text-sm tracking-tight">DoH Proxy Admin</span>
              </div>
            </div>
            
            <!-- Desktop Info Header / Section Title -->
            <div class="hidden md:flex items-center gap-3">
              <span id="current-section-title" class="font-display font-bold text-lg text-slate-800 dark:text-slate-100 tracking-tight">Overview</span>
              <div class="px-2.5 py-0.5 text-[11px] font-semibold bg-emerald-500/10 text-emerald-500 rounded-full border border-emerald-500/20">
                Runtime: Cloudflare Worker 2.0
              </div>
            </div>

            <!-- Global Action Controls (Theme, User, Logout) -->
            <div class="flex items-center gap-2 sm:gap-4">
              <!-- Admin avatar/badge -->
              <div class="flex items-center gap-2.5 px-3 py-1.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-xs">
                <div class="w-6 h-6 rounded-full bg-slate-200 dark:bg-slate-800 flex items-center justify-center font-bold text-[10px] text-blue-500 border border-blue-500/20">AD</div>
                <span class="hidden sm:inline font-medium text-slate-700 dark:text-slate-300">Administrator</span>
              </div>
              
              <!-- Theme Toggle -->
              <button onclick="toggleTheme()" class="p-2 text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100 rounded-xl hover:bg-slate-100 dark:hover:bg-slate-800 transition" title="Toggle Theme">
                <i id="theme-icon" data-lucide="moon" class="w-5 h-5"></i>
              </button>
              
              <!-- Logout Button -->
              <button onclick="logout()" class="p-2 text-red-500 hover:bg-red-500/10 rounded-xl transition flex items-center gap-1 sm:gap-2 text-sm font-medium">
                <i data-lucide="log-out" class="w-4 h-4"></i>
                <span class="hidden sm:inline">Logout</span>
              </button>
            </div>
          </div>
        </div>
      </header>

      <!-- MOBILE ONLY SUB NAVIGATION / TABS -->
      <nav class="md:hidden flex overflow-x-auto gap-2 p-3 bg-slate-200/50 dark:bg-slate-900/50 border-b border-slate-200 dark:border-slate-800 shrink-0">
        <button onclick="switchTab('dashboard')" id="tab-dashboard" class="px-4 py-2 text-xs font-medium rounded-lg flex items-center gap-2 transition whitespace-nowrap bg-white dark:bg-slate-800 shadow-sm text-blue-600 dark:text-blue-400">
          <i data-lucide="layout-dashboard" class="w-4 h-4"></i>
          <span>Dashboard</span>
        </button>
        <button onclick="switchTab('users')" id="tab-users" class="px-4 py-2 text-xs font-medium rounded-lg flex items-center gap-2 transition whitespace-nowrap text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100">
          <i data-lucide="users" class="w-4 h-4"></i>
          <span>Subscriptions</span>
        </button>
        <button onclick="switchTab('providers')" id="tab-providers" class="px-4 py-2 text-xs font-medium rounded-lg flex items-center gap-2 transition whitespace-nowrap text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100">
          <i data-lucide="globe" class="w-4 h-4"></i>
          <span>DNS Providers</span>
        </button>
        <button onclick="switchTab('logs')" id="tab-logs" class="px-4 py-2 text-xs font-medium rounded-lg flex items-center gap-2 transition whitespace-nowrap text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100">
          <i data-lucide="terminal" class="w-4 h-4"></i>
          <span>Traffic Logs</span>
        </button>
        <button onclick="switchTab('statistics')" id="tab-statistics" class="px-4 py-2 text-xs font-medium rounded-lg flex items-center gap-2 transition whitespace-nowrap text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100">
          <i data-lucide="bar-chart-3" class="w-4 h-4"></i>
          <span>Statistics</span>
        </button>
        <button onclick="switchTab('settings')" id="tab-settings" class="px-4 py-2 text-xs font-medium rounded-lg flex items-center gap-2 transition whitespace-nowrap text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100">
          <i data-lucide="settings" class="w-4 h-4"></i>
          <span>Settings</span>
        </button>
      </nav>

      <!-- MAIN BODY SECTION -->
      <div class="px-4 sm:px-6 lg:px-8 py-6 w-full flex-1 flex flex-col gap-6 overflow-y-auto">
        
        <!-- ALERT MESSAGE BANNER -->
        <div id="alert-banner" class="hidden p-4 rounded-xl text-sm border flex items-center justify-between gap-3 animate-fade-in shrink-0">
          <div class="flex items-center gap-2">
            <i id="alert-icon" class="w-5 h-5"></i>
            <span id="alert-text"></span>
          </div>
          <button onclick="hideAlert()" class="text-slate-400 hover:text-slate-900 dark:hover:text-slate-100">
            <i data-lucide="x" class="w-4 h-4"></i>
          </button>
        </div>

        <!-- MAIN PAGES SECTIONS -->
        <main class="flex-1">

          <!-- PAGE 1: DASHBOARD -->
          <section id="page-dashboard" class="space-y-6">
            <div class="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <!-- Total Users -->
            <div class="bg-white dark:bg-slate-900 p-5 rounded-2xl border border-slate-200 dark:border-slate-800">
              <div class="flex justify-between items-start text-slate-400 mb-2">
                <span class="text-xs font-semibold uppercase tracking-wider">Total Subscriptions</span>
                <div class="p-2 bg-blue-500/10 text-blue-500 rounded-lg"><i data-lucide="users" class="w-5 h-5"></i></div>
              </div>
              <h2 id="stat-total-users" class="text-3xl font-display font-bold">0</h2>
            </div>
            <!-- Active Users -->
            <div class="bg-white dark:bg-slate-900 p-5 rounded-2xl border border-slate-200 dark:border-slate-800">
              <div class="flex justify-between items-start text-slate-400 mb-2">
                <span class="text-xs font-semibold uppercase tracking-wider">Active Users</span>
                <div class="p-2 bg-emerald-500/10 text-emerald-500 rounded-lg"><i data-lucide="user-check" class="w-5 h-5"></i></div>
              </div>
              <h2 id="stat-active-users" class="text-3xl font-display font-bold">0</h2>
            </div>
            <!-- Disabled/Expired -->
            <div class="bg-white dark:bg-slate-900 p-5 rounded-2xl border border-slate-200 dark:border-slate-800">
              <div class="flex justify-between items-start text-slate-400 mb-2">
                <span class="text-xs font-semibold uppercase tracking-wider">Expired / Blocked</span>
                <div class="p-2 bg-amber-500/10 text-amber-500 rounded-lg"><i data-lucide="user-minus" class="w-5 h-5"></i></div>
              </div>
              <h2 id="stat-disabled-users" class="text-3xl font-display font-bold">0</h2>
            </div>
            <!-- Total Queries -->
            <div class="bg-white dark:bg-slate-900 p-5 rounded-2xl border border-slate-200 dark:border-slate-800">
              <div class="flex justify-between items-start text-slate-400 mb-2">
                <span class="text-xs font-semibold uppercase tracking-wider">Total Queries</span>
                <div class="p-2 bg-purple-500/10 text-purple-500 rounded-lg"><i data-lucide="activity" class="w-5 h-5"></i></div>
              </div>
              <h2 id="stat-total-queries" class="text-3xl font-display font-bold">0</h2>
            </div>
          </div>

          <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <!-- Traffic Progress Card -->
            <div class="bg-white dark:bg-slate-900 p-6 rounded-2xl border border-slate-200 dark:border-slate-800 space-y-4">
              <h3 class="font-display text-lg font-bold flex items-center gap-2">
                <i data-lucide="database" class="w-5 h-5 text-blue-500"></i>
                <span>Traffic Allocation</span>
              </h3>
              <div class="space-y-2">
                <div class="flex justify-between text-sm">
                  <span class="text-slate-500">Total Used Volume</span>
                  <span id="stat-used-gb" class="font-medium">0 GB</span>
                </div>
                <div class="w-full bg-slate-100 dark:bg-slate-800 rounded-full h-3 overflow-hidden">
                  <div id="stat-progress-bar" class="bg-blue-600 h-full rounded-full transition-all duration-500" style="width: 0%"></div>
                </div>
                <div class="flex justify-between text-xs text-slate-400">
                  <span id="stat-allocated-gb">0 GB Limit</span>
                  <span id="stat-remaining-gb">0 GB Remaining</span>
                </div>
              </div>
            </div>

            <!-- DNS System Summary -->
            <div class="bg-white dark:bg-slate-900 p-6 rounded-2xl border border-slate-200 dark:border-slate-800 lg:col-span-2 space-y-4">
              <h3 class="font-display text-lg font-bold flex items-center gap-2">
                <i data-lucide="cpu" class="w-5 h-5 text-indigo-500"></i>
                <span>Core Configurations</span>
              </h3>
              <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 text-sm">
                <div class="p-3 bg-slate-50 dark:bg-slate-950 rounded-xl flex justify-between items-center">
                  <span class="text-slate-500">Default DNS:</span>
                  <span id="summary-default-dns" class="font-semibold text-indigo-500">-</span>
                </div>
                <div class="p-3 bg-slate-50 dark:bg-slate-950 rounded-xl flex justify-between items-center">
                  <span class="text-slate-500">CF IP Mode:</span>
                  <span id="summary-cf-mode" class="font-semibold text-blue-500">-</span>
                </div>
                <div class="p-3 bg-slate-50 dark:bg-slate-950 rounded-xl flex justify-between items-center">
                  <span class="text-slate-500">DNS Cache:</span>
                  <span id="summary-dns-cache" class="font-semibold text-emerald-500">-</span>
                </div>
                <div class="p-3 bg-slate-50 dark:bg-slate-950 rounded-xl flex justify-between items-center">
                  <span class="text-slate-500">ECS Geo-Routing:</span>
                  <span id="summary-dns-ecs" class="font-semibold text-pink-500">-</span>
                </div>
                <div class="p-3 bg-slate-50 dark:bg-slate-950 rounded-xl flex justify-between items-center">
                  <span class="text-slate-500">Queries/GB Ratio:</span>
                  <span id="summary-ratio" class="font-semibold text-amber-500">-</span>
                </div>
              </div>
            </div>
          </div>

          <!-- Recent Logs in Dashboard -->
          <div class="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 overflow-hidden">
            <div class="p-5 border-b border-slate-200 dark:border-slate-800 flex justify-between items-center">
              <h3 class="font-display font-bold text-lg flex items-center gap-2">
                <i data-lucide="history" class="w-5 h-5 text-emerald-500"></i>
                <span>Recent DNS Activity</span>
              </h3>
              <button onclick="switchTab('logs')" class="text-xs font-semibold text-blue-600 dark:text-blue-400 hover:underline">View All Logs</button>
            </div>
            <div class="overflow-x-auto">
              <table class="w-full text-left border-collapse text-sm">
                <thead>
                  <tr class="bg-slate-50 dark:bg-slate-950 text-slate-400 uppercase text-xs font-semibold border-b border-slate-200 dark:border-slate-800">
                    <th class="p-4">Timestamp</th>
                    <th class="p-4">Subscriber UUID</th>
                    <th class="p-4">Upstream DNS</th>
                    <th class="p-4">Client IP</th>
                    <th class="p-4">User Agent</th>
                  </tr>
                </thead>
                <tbody id="dashboard-recent-logs">
                  <tr>
                    <td colspan="5" class="p-8 text-center text-slate-400">No recent activities logged yet.</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </section>

        <!-- PAGE 2: USER SUBSCRIPTIONS -->
        <section id="page-users" class="space-y-4 hidden">
          <div class="flex flex-col sm:flex-row justify-between items-stretch sm:items-center gap-4">
            <div class="flex-1 flex gap-2">
              <div class="relative flex-1">
                <i data-lucide="search" class="w-5 h-5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"></i>
                <input type="text" id="user-search-input" oninput="fetchUsers()" class="w-full pl-10 pr-4 py-2.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-500" placeholder="Search by username or UUID...">
              </div>
              <select id="user-status-filter" onchange="fetchUsers()" class="px-4 py-2.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm">
                <option value="all">All Statuses</option>
                <option value="active">Active Only</option>
                <option value="disabled">Disabled Only</option>
                <option value="expired">Expired Only</option>
              </select>
            </div>
            <button onclick="openCreateUserModal()" class="bg-blue-600 hover:bg-blue-700 text-white font-medium px-5 py-2.5 rounded-xl flex items-center gap-2 transition shadow-lg shadow-blue-500/10 whitespace-nowrap">
              <i data-lucide="user-plus" class="w-4 h-4"></i>
              <span>Create Subscription</span>
            </button>
          </div>

          <!-- Subscriptions Table -->
          <div class="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 overflow-hidden">
            <div class="overflow-x-auto">
              <table class="w-full text-left border-collapse text-sm">
                <thead>
                  <tr class="bg-slate-50 dark:bg-slate-950 text-slate-400 uppercase text-xs font-semibold border-b border-slate-200 dark:border-slate-800">
                    <th class="p-4">Username</th>
                    <th class="p-4">UUID Key</th>
                    <th class="p-4">DoH Connection (Intra)</th>
                    <th class="p-4">Status</th>
                    <th class="p-4">Upstream DNS</th>
                    <th class="p-4">Limit (GB)</th>
                    <th class="p-4">Used (GB)</th>
                    <th class="p-4">Queries</th>
                    <th class="p-4">Expiry Date</th>
                    <th class="p-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody id="users-table-body">
                  <!-- JS Inserted -->
                </tbody>
              </table>
            </div>
          </div>
        </section>

        <!-- PAGE 3: DNS PROVIDERS -->
        <section id="page-providers" class="space-y-6 hidden">
          <div class="flex justify-between items-center">
            <div>
              <h3 class="font-display font-bold text-xl">Upstream DNS Providers</h3>
              <p class="text-sm text-slate-500 mt-1">Configure external resolvers. Clients can route specifically using the provider query parameter.</p>
            </div>
            <button onclick="openAddProviderModal()" class="bg-blue-600 hover:bg-blue-700 text-white font-medium px-4 py-2 rounded-xl flex items-center gap-2 transition">
              <i data-lucide="plus" class="w-4 h-4"></i>
              <span>Add Custom Provider</span>
            </button>
          </div>

          <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6" id="dns-providers-grid">
            <!-- Dynamically Loaded Cards -->
          </div>
        </section>

        <!-- PAGE 4: TRAFFIC LOGS -->
        <section id="page-logs" class="space-y-4 hidden">
          <div class="flex flex-col sm:flex-row justify-between items-stretch sm:items-center gap-4">
            <div class="flex-1 flex gap-2">
              <div class="relative flex-1">
                <i data-lucide="search" class="w-5 h-5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"></i>
                <input type="text" id="logs-search-input" oninput="filterLogs()" class="w-full pl-10 pr-4 py-2.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-500" placeholder="Search logs by IP, Provider or UUID...">
              </div>
            </div>
            <button onclick="exportLogsCsv()" class="bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 font-semibold px-5 py-2.5 rounded-xl flex items-center gap-2 transition border border-slate-200 dark:border-slate-700">
              <i data-lucide="download" class="w-4 h-4"></i>
              <span>Export CSV</span>
            </button>
          </div>

          <!-- Logs Table -->
          <div class="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 overflow-hidden">
            <div class="overflow-x-auto">
              <table class="w-full text-left border-collapse text-sm">
                <thead>
                  <tr class="bg-slate-50 dark:bg-slate-950 text-slate-400 uppercase text-xs font-semibold border-b border-slate-200 dark:border-slate-800">
                    <th class="p-4">Timestamp</th>
                    <th class="p-4">Subscriber UUID</th>
                    <th class="p-4">Upstream DNS Resolver</th>
                    <th class="p-4">Client IP</th>
                    <th class="p-4">User Agent</th>
                  </tr>
                </thead>
                <tbody id="logs-table-body">
                  <!-- Filled via JS -->
                </tbody>
              </table>
            </div>
          </div>
        </section>

        <!-- PAGE 5: STATISTICS & GRAPHICS -->
        <section id="page-statistics" class="grid grid-cols-1 lg:grid-cols-2 gap-6 hidden">
          <!-- Daily Queries Chart -->
          <div class="bg-white dark:bg-slate-900 p-6 rounded-2xl border border-slate-200 dark:border-slate-800 space-y-4">
            <h4 class="font-display font-bold text-lg flex items-center gap-2">
              <i data-lucide="calendar" class="w-5 h-5 text-blue-500"></i>
              <span>Daily Queries (Last 7 Days)</span>
            </h4>
            <div class="h-64 relative">
              <canvas id="chart-daily-queries"></canvas>
            </div>
          </div>

          <!-- Most Used Providers Chart -->
          <div class="bg-white dark:bg-slate-900 p-6 rounded-2xl border border-slate-200 dark:border-slate-800 space-y-4">
            <h4 class="font-display font-bold text-lg flex items-center gap-2">
              <i data-lucide="pie-chart" class="w-5 h-5 text-indigo-500"></i>
              <span>Upstream Resolver Popularity</span>
            </h4>
            <div class="h-64 relative flex justify-center">
              <canvas id="chart-providers"></canvas>
            </div>
          </div>

          <!-- Top Users Chart -->
          <div class="bg-white dark:bg-slate-900 p-6 rounded-2xl border border-slate-200 dark:border-slate-800 lg:col-span-2 space-y-4">
            <h4 class="font-display font-bold text-lg flex items-center gap-2">
              <i data-lucide="trophy" class="w-5 h-5 text-amber-500"></i>
              <span>Top 10 Most Active Subscriptions</span>
            </h4>
            <div class="h-80 relative">
              <canvas id="chart-top-users"></canvas>
            </div>
          </div>
        </section>

        <!-- PAGE 6: ADMIN SYSTEM SETTINGS -->
        <section id="page-settings" class="bg-white dark:bg-slate-900 p-6 rounded-2xl border border-slate-200 dark:border-slate-800 space-y-8 hidden">
          <h3 class="font-display font-bold text-xl flex items-center gap-2">
            <i data-lucide="sliders-horizontal" class="w-6 h-6 text-blue-500"></i>
            <span>System Configurations</span>
          </h3>

          <form id="settings-form" class="space-y-6">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
              <!-- Traffic Ratio -->
              <div class="space-y-2">
                <label class="block text-sm font-semibold">Queries Per GB Ratio</label>
                <input type="number" id="setting-queries-per-gb" class="w-full px-4 py-2.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm" placeholder="5000">
                <p class="text-xs text-slate-400">Specify how many successful DNS queries equal 1 GB of used volume (Default 5000).</p>
              </div>

              <!-- Default Provider Selector -->
              <div class="space-y-2">
                <label class="block text-sm font-semibold">Default Upstream DNS</label>
                <select id="setting-default-dns" class="w-full px-4 py-2.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm">
                  <!-- Populated dynamically -->
                </select>
                <p class="text-xs text-slate-400">Resolver assigned when queries exclude specific upstream parameters.</p>
              </div>

              <!-- Cloudflare mode -->
              <div class="space-y-2">
                <label class="block text-sm font-semibold">Cloudflare IP Mode</label>
                <select id="setting-cf-mode" class="w-full px-4 py-2.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm">
                  <option value="Automatic">Automatic (Recommended)</option>
                  <option value="IPv4">Force IPv4 Resolved Outbound</option>
                  <option value="IPv6">Force IPv6 Resolved Outbound</option>
                </select>
                <p class="text-xs text-slate-400">Restricts DNS forwarding queries to specific network protocols.</p>
              </div>

              <!-- Custom User Agent -->
              <div class="space-y-2">
                <label class="block text-sm font-semibold">Outgoing custom User-Agent</label>
                <input type="text" id="setting-custom-ua" class="w-full px-4 py-2.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm" placeholder="DNS-over-HTTPS-Subscription/1.0">
                <p class="text-xs text-slate-400">User-Agent header passed when fetching from external providers.</p>
              </div>

              <!-- DNS Cache toggler -->
              <div class="space-y-2 flex items-center justify-between p-4 bg-slate-50 dark:bg-slate-950 rounded-xl border border-slate-200 dark:border-slate-800/60 md:col-span-2">
                <div>
                  <label class="block text-sm font-semibold">Enable Edge Cache</label>
                  <span class="text-xs text-slate-400 block mt-0.5">Utilises Cloudflare's Cache API to cache repetitive GET queries. Reduces latency significantly.</span>
                </div>
                <input type="checkbox" id="setting-dns-cache" class="w-6 h-6 text-blue-600 border-slate-300 rounded focus:ring-blue-500 focus:outline-none">
              </div>

              <!-- DNS ECS toggler -->
              <div class="space-y-2 flex items-center justify-between p-4 bg-slate-50 dark:bg-slate-950 rounded-xl border border-slate-200 dark:border-slate-800/60 md:col-span-2">
                <div>
                  <label class="block text-sm font-semibold">Enable EDNS Client Subnet (ECS) Geo-Routing</label>
                  <span class="text-xs text-slate-400 block mt-0.5">Injects your client IP subnet into the query so that upstream DNS resolvers can return geographically optimized results for games and content delivery networks. Disable this if connection is unstable or fails to load websites.</span>
                </div>
                <input type="checkbox" id="setting-dns-ecs" class="w-6 h-6 text-blue-600 border-slate-300 rounded focus:ring-blue-500 focus:outline-none">
              </div>

              <!-- Change Admin Password -->
              <div class="p-5 border border-slate-200 dark:border-slate-800 rounded-xl space-y-3 md:col-span-2 bg-slate-50/50 dark:bg-slate-900/30">
                <h4 class="font-display font-bold text-sm text-blue-500">Modify Login Security Password</h4>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div class="space-y-1">
                    <label class="block text-xs font-semibold">New Administrative Password</label>
                    <input type="password" id="setting-password" class="w-full px-4 py-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950 focus:outline-none text-sm" placeholder="••••••••">
                  </div>
                  <div class="space-y-1">
                    <label class="block text-xs font-semibold">Confirm New Password</label>
                    <input type="password" id="setting-confirm-password" class="w-full px-4 py-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950 focus:outline-none text-sm" placeholder="••••••••">
                  </div>
                </div>
              </div>
            </div>

            <div class="flex justify-end gap-3">
              <button type="submit" class="bg-blue-600 hover:bg-blue-700 active:bg-blue-800 text-white font-medium px-6 py-2.5 rounded-xl transition shadow-lg shadow-blue-500/10">
                Save Configurations
              </button>
            </div>
          </form>
        </section>

      </main>
    </div>
  </div>

  <!-- MODAL: CREATE USER -->
  <div id="modal-create-user" class="fixed inset-0 bg-slate-900/50 backdrop-blur-sm hidden items-center justify-center z-50">
    <div class="bg-white dark:bg-slate-900 p-6 rounded-2xl shadow-2xl max-w-md w-full border border-slate-200 dark:border-slate-800 transform scale-100 transition-all">
      <div class="flex justify-between items-center mb-4">
        <h4 class="font-display font-bold text-lg">Create Subscription</h4>
        <button onclick="closeModal('modal-create-user')" class="text-slate-400 hover:text-slate-950 dark:hover:text-white"><i data-lucide="x" class="w-5 h-5"></i></button>
      </div>
      <form id="form-create-user" class="space-y-4">
        <div>
          <label class="block text-xs font-semibold mb-1 uppercase tracking-wider text-slate-400">Username / Client ID</label>
          <input type="text" id="create-username" class="w-full px-4 py-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 text-sm focus:outline-none" placeholder="e.g. John Doe" required>
        </div>
        <div>
          <label class="block text-xs font-semibold mb-1 uppercase tracking-wider text-slate-400">Traffic Allocation Limit (GB)</label>
          <input type="number" step="0.1" id="create-limit" class="w-full px-4 py-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 text-sm focus:outline-none" value="10.0" required>
        </div>
        <div>
          <label class="block text-xs font-semibold mb-1 uppercase tracking-wider text-slate-400">Expiration Date (Optional)</label>
          <input type="datetime-local" id="create-expiry" class="w-full px-4 py-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 text-sm focus:outline-none">
        </div>
        <div>
          <label class="block text-xs font-semibold mb-1 uppercase tracking-wider text-slate-400">DNS Provider</label>
          <select id="create-provider" class="w-full px-4 py-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 text-sm focus:outline-none">
            <option value="">System Default</option>
          </select>
        </div>
        <button type="submit" class="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-3 rounded-xl transition mt-2">Create Account</button>
      </form>
    </div>
  </div>

  <!-- MODAL: EDIT USER -->
  <div id="modal-edit-user" class="fixed inset-0 bg-slate-900/50 backdrop-blur-sm hidden items-center justify-center z-50">
    <div class="bg-white dark:bg-slate-900 p-6 rounded-2xl shadow-2xl max-w-md w-full border border-slate-200 dark:border-slate-800 transform scale-100 transition-all">
      <div class="flex justify-between items-center mb-4">
        <h4 class="font-display font-bold text-lg">Edit Subscriber details</h4>
        <button onclick="closeModal('modal-edit-user')" class="text-slate-400 hover:text-slate-950 dark:hover:text-white"><i data-lucide="x" class="w-5 h-5"></i></button>
      </div>
      <form id="form-edit-user" class="space-y-4">
        <input type="hidden" id="edit-uuid">
        <div>
          <label class="block text-xs font-semibold mb-1 uppercase tracking-wider text-slate-400">Username</label>
          <input type="text" id="edit-username" class="w-full px-4 py-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 text-sm focus:outline-none" required>
        </div>
        <div>
          <label class="block text-xs font-semibold mb-1 uppercase tracking-wider text-slate-400">Traffic Allocation (GB)</label>
          <input type="number" step="0.1" id="edit-limit" class="w-full px-4 py-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 text-sm focus:outline-none" required>
        </div>
        <div>
          <label class="block text-xs font-semibold mb-1 uppercase tracking-wider text-slate-400">Expiration Date</label>
          <input type="datetime-local" id="edit-expiry" class="w-full px-4 py-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 text-sm focus:outline-none">
        </div>
        <div>
          <label class="block text-xs font-semibold mb-1 uppercase tracking-wider text-slate-400">DNS Provider</label>
          <select id="edit-provider" class="w-full px-4 py-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 text-sm focus:outline-none">
            <option value="">System Default</option>
          </select>
        </div>
        <div>
          <label class="block text-xs font-semibold mb-1 uppercase tracking-wider text-slate-400">Status</label>
          <select id="edit-enabled" class="w-full px-4 py-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 text-sm focus:outline-none">
            <option value="1">Enabled / Active</option>
            <option value="0">Disabled / Blocked</option>
          </select>
        </div>
        <button type="submit" class="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-3 rounded-xl transition mt-2">Save Subscriber</button>
      </form>
    </div>
  </div>

  <!-- MODAL: ADD DNS PROVIDER -->
  <div id="modal-add-provider" class="fixed inset-0 bg-slate-900/50 backdrop-blur-sm hidden items-center justify-center z-50">
    <div class="bg-white dark:bg-slate-900 p-6 rounded-2xl shadow-2xl max-w-md w-full border border-slate-200 dark:border-slate-800 transform scale-100 transition-all">
      <div class="flex justify-between items-center mb-4">
        <h4 class="font-display font-bold text-lg">Add DNS Provider</h4>
        <button onclick="closeModal('modal-add-provider')" class="text-slate-400 hover:text-slate-950 dark:hover:text-white"><i data-lucide="x" class="w-5 h-5"></i></button>
      </div>
      <form id="form-add-provider" class="space-y-4">
        <div>
          <label class="block text-xs font-semibold mb-1 uppercase tracking-wider text-slate-400">Provider Name</label>
          <input type="text" id="add-provider-name" class="w-full px-4 py-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 text-sm focus:outline-none" placeholder="e.g. Quad9 Primary" required>
        </div>
        <div>
          <label class="block text-xs font-semibold mb-1 uppercase tracking-wider text-slate-400">DNS Over HTTPS (DoH) Endpoint</label>
          <input type="url" id="add-provider-url" class="w-full px-4 py-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 text-sm focus:outline-none" placeholder="https://dns.quad9.net/dns-query" required>
        </div>
        <button type="submit" class="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-3 rounded-xl transition mt-2">Register Resolver</button>
      </form>
    </div>
  </div>

  <footer class="py-6 border-t border-slate-200 dark:border-slate-800 text-center text-xs text-slate-400 bg-white dark:bg-slate-950 mt-auto shrink-0">
    <div class="max-w-7xl mx-auto px-4">
      <span>DNS-Over-HTTPS Subscription Management System &copy; 2026</span>
    </div>
  </footer>

  <script>
    // Copy to clipboard helper
    function copyToClipboard(text, btn) {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(() => {
          showCopySuccess(btn);
        }).catch(() => {
          fallbackCopyText(text, btn);
        });
      } else {
        fallbackCopyText(text, btn);
      }
    }

    function fallbackCopyText(text, btn) {
      const textArea = document.createElement("textarea");
      textArea.value = text;
      textArea.style.position = "fixed";  // avoid scrolling to bottom
      document.body.appendChild(textArea);
      textArea.focus();
      textArea.select();
      try {
        document.execCommand('copy');
        showCopySuccess(btn);
      } catch (err) {
        console.error('Fallback copy failed', err);
      }
      document.body.removeChild(textArea);
    }

    function showCopySuccess(btn) {
      const originalHtml = btn.innerHTML;
      btn.innerHTML = '<i data-lucide="check" class="w-3.5 h-3.5 text-emerald-500"></i>';
      btn.classList.add('bg-emerald-500/10', 'border-emerald-500/20');
      btn.classList.remove('text-blue-500', 'border-blue-500/10');
      lucide.createIcons();
      setTimeout(() => {
        btn.innerHTML = originalHtml;
        btn.classList.remove('bg-emerald-500/10', 'border-emerald-500/20');
        btn.classList.add('text-blue-500', 'border-blue-500/10');
        lucide.createIcons();
      }, 1500);
    }

    // State values
    let sessionToken = localStorage.getItem('jwt_token') || '';
    let appData = null;
    let activeTab = 'dashboard';
    
    // Charts variables
    let chartDaily = null;
    let chartProv = null;
    let chartUsers = null;

    // Run when DOM elements are active
    document.addEventListener('DOMContentLoaded', () => {
      lucide.createIcons();
      
      // Auto dark mode system trigger
      if (localStorage.getItem('theme') === 'dark' || (!localStorage.getItem('theme') && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
        document.documentElement.classList.add('dark');
        document.getElementById('theme-icon').setAttribute('data-lucide', 'sun');
      } else {
        document.documentElement.classList.remove('dark');
        document.getElementById('theme-icon').setAttribute('data-lucide', 'moon');
      }
      lucide.createIcons();

      // Check current token
      if (sessionToken) {
        document.getElementById('login-overlay').classList.add('hidden');
        document.getElementById('app-content').classList.remove('hidden');
        refreshAllData();
      }

      // Handle Form actions
      document.getElementById('login-form').addEventListener('submit', handleLogin);
      document.getElementById('settings-form').addEventListener('submit', handleSaveSettings);
      document.getElementById('form-create-user').addEventListener('submit', handleCreateUser);
      document.getElementById('form-edit-user').addEventListener('submit', handleSaveEditUser);
      document.getElementById('form-add-provider').addEventListener('submit', handleAddProvider);
    });

    function toggleTheme() {
      const isDark = document.documentElement.classList.contains('dark');
      if (isDark) {
        document.documentElement.classList.remove('dark');
        localStorage.setItem('theme', 'light');
        document.getElementById('theme-icon').setAttribute('data-lucide', 'moon');
      } else {
        document.documentElement.classList.add('dark');
        localStorage.setItem('theme', 'dark');
        document.getElementById('theme-icon').setAttribute('data-lucide', 'sun');
      }
      lucide.createIcons();
    }

    // Secure Login
    async function handleLogin(e) {
      e.preventDefault();
      const password = document.getElementById('login-password').value;
      const errorDiv = document.getElementById('login-error');
      errorDiv.classList.add('hidden');

      try {
        const res = await fetch('/api/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password })
        });
        const data = await res.json();
        
        if (res.ok && data.token) {
          sessionToken = data.token;
          localStorage.setItem('jwt_token', sessionToken);
          document.getElementById('login-overlay').classList.add('hidden');
          document.getElementById('app-content').classList.remove('hidden');
          showAlert('Successfully Authenticated!', 'success');
          refreshAllData();
        } else {
          errorDiv.textContent = data.error || 'Authentication Failed';
          errorDiv.classList.remove('hidden');
        }
      } catch (err) {
        errorDiv.textContent = 'Connection error. Please verify endpoints.';
        errorDiv.classList.remove('hidden');
      }
    }

    function logout() {
      sessionToken = '';
      localStorage.removeItem('jwt_token');
      // Clear cookie
      document.cookie = 'token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
      document.getElementById('login-overlay').classList.remove('hidden');
      document.getElementById('app-content').classList.add('hidden');
    }

    // Fetch and redraw everything
    async function refreshAllData() {
      if (!sessionToken) return;
      try {
        const res = await fetch('/api/statistics', {
          headers: { 'Authorization': 'Bearer ' + sessionToken }
        });
        
        if (res.status === 401) {
          logout();
          return;
        }

        if (!res.ok) throw new Error('API request failed');

        appData = await res.json();
        
        updateDashboard();
        updateProvidersTab();
        updateLogsTab();
        updateSettingsTab();
        populateUserProviderDropdowns();
        updateCharts();

        // If on user page, trigger fetch users too
        if (activeTab === 'users') {
          fetchUsers();
        }
      } catch (e) {
        showAlert('Failed to synchronize server statistics: ' + e.message, 'error');
      }
    }

    function switchTab(tabId) {
      activeTab = tabId;
      // Toggle CSS Styles
      const tabs = ['dashboard', 'users', 'providers', 'logs', 'statistics', 'settings'];
      tabs.forEach(t => {
        const el = document.getElementById('tab-' + t);
        const sideEl = document.getElementById('sidebar-tab-' + t);
        const page = document.getElementById('page-' + t);
        
        if (t === tabId) {
          if (el) el.className = "px-4 py-2 text-xs font-medium rounded-lg flex items-center gap-2 transition whitespace-nowrap bg-white dark:bg-slate-800 shadow-sm text-blue-600 dark:text-blue-400";
          if (sideEl) sideEl.className = "w-full flex items-center gap-3 px-4 py-3 text-sm font-medium rounded-xl transition duration-150 bg-blue-500/10 text-blue-600 dark:text-blue-400 border-l-4 border-blue-500 pl-3";
          if (page) page.classList.remove('hidden');
        } else {
          if (el) el.className = "px-4 py-2 text-xs font-medium rounded-lg flex items-center gap-2 transition whitespace-nowrap text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100";
          if (sideEl) sideEl.className = "w-full flex items-center gap-3 px-4 py-3 text-sm font-medium rounded-xl transition duration-150 hover:bg-slate-100 dark:hover:bg-slate-900 hover:text-slate-900 dark:hover:text-slate-100 border-l-4 border-transparent";
          if (page) page.classList.add('hidden');
        }
      });

      // Update Section Title
      const titles = {
        'dashboard': 'Overview',
        'users': 'User Management',
        'providers': 'DNS Providers',
        'logs': 'Traffic Logs',
        'statistics': 'Traffic Analysis',
        'settings': 'System Settings'
      };
      const titleEl = document.getElementById('current-section-title');
      if (titleEl) titleEl.textContent = titles[tabId] || 'Overview';

      if (tabId === 'users') {
        fetchUsers();
      } else if (tabId === 'statistics') {
        // Force redraw charts
        setTimeout(updateCharts, 50);
      }
    }

    // Dashboard UI
    function updateDashboard() {
      if (!appData) return;
      const s = appData.summary;
      document.getElementById('stat-total-users').textContent = s.totalUsers;
      document.getElementById('stat-active-users').textContent = s.activeUsers;
      document.getElementById('stat-disabled-users').textContent = s.disabledUsers + s.expiredUsers;
      document.getElementById('stat-total-queries').textContent = s.totalQueries.toLocaleString();

      document.getElementById('stat-used-gb').textContent = s.usedGb.toFixed(4) + ' GB';
      document.getElementById('stat-allocated-gb').textContent = s.totalLimitGb.toFixed(1) + ' GB Limit';
      document.getElementById('stat-remaining-gb').textContent = Math.max(0, s.remainingGb).toFixed(4) + ' GB Remaining';
      
      const percent = s.totalLimitGb > 0 ? (s.usedGb / s.totalLimitGb) * 100 : 0;
      document.getElementById('stat-progress-bar').style.width = Math.min(100, percent) + '%';

      // Config summary values
      document.getElementById('summary-default-dns').textContent = appData.config.defaultDns;
      document.getElementById('summary-cf-mode').textContent = appData.config.cfMode;
      document.getElementById('summary-dns-cache').textContent = appData.config.dnsCache === 'true' ? 'Enabled' : 'Disabled';
      document.getElementById('summary-dns-ecs').textContent = appData.config.dnsEcs === 'true' ? 'Enabled' : 'Disabled';
      document.getElementById('summary-ratio').textContent = parseInt(appData.config.queriesPerGb).toLocaleString() + ' Queries/GB';

      // Recent logs inside Dashboard
      const logsBody = document.getElementById('dashboard-recent-logs');
      logsBody.innerHTML = '';
      const recentLogs = appData.logs.slice(0, 5);
      
      if (recentLogs.length === 0) {
        logsBody.innerHTML = '<tr><td colspan="5" class="p-8 text-center text-slate-400">No active traffic logs present.</td></tr>';
        return;
      }

      recentLogs.forEach(l => {
        const tr = document.createElement('tr');
        tr.className = "border-b border-slate-100 dark:border-slate-800/60 hover:bg-slate-50/50 dark:hover:bg-slate-900/40";
        tr.innerHTML = \`
          <td class="p-4 font-mono text-xs text-slate-500">\${new Date(l.timestamp).toLocaleString()}</td>
          <td class="p-4 font-mono text-xs">\${l.uuid}</td>
          <td class="p-4"><span class="px-2 py-1 bg-slate-100 dark:bg-slate-800 rounded-lg text-xs font-medium">\${l.provider}</span></td>
          <td class="p-4 font-mono text-xs text-blue-500">\${l.client_ip}</td>
          <td class="p-4 text-xs text-slate-400 max-w-xs truncate" title="\${l.user_agent}">\${l.user_agent}</td>
        \`;
        logsBody.appendChild(tr);
      });
    }

    // Fetch and populate Users
    async function fetchUsers() {
      const search = document.getElementById('user-search-input').value;
      const status = document.getElementById('user-status-filter').value;
      try {
        const res = await fetch(\`/api/users?search=\${encodeURIComponent(search)}&status=\${status}\`, {
          headers: { 'Authorization': 'Bearer ' + sessionToken }
        });
        const data = await res.json();
        
        const tbody = document.getElementById('users-table-body');
        tbody.innerHTML = '';

        if (!data.users || data.users.length === 0) {
          tbody.innerHTML = '<tr><td colspan="9" class="p-8 text-center text-slate-400">No users found matching query criteria.</td></tr>';
          return;
        }

        data.users.forEach(u => {
          const isExpired = u.expire_at ? (new Date(u.expire_at).getTime() < Date.now()) : false;
          const isQuotaExceeded = u.used_gb >= u.traffic_limit_gb;
          let statusBadge = '';

          if (u.enabled !== 1) {
            statusBadge = '<span class="status-pill status-disabled">BLOCKED</span>';
          } else if (isExpired) {
            statusBadge = '<span class="status-pill status-expired">EXPIRED</span>';
          } else if (isQuotaExceeded) {
            statusBadge = '<span class="status-pill status-expired">FULL</span>';
          } else {
            statusBadge = '<span class="status-pill status-active">ACTIVE</span>';
          }

          const formattedExpiry = u.expire_at ? new Date(u.expire_at).toLocaleString() : 'Lifetime';

          const host = window.location.host;
          const dohLink = 'https://' + host + '/dns-query/' + u.uuid;

          const tr = document.createElement('tr');
          tr.className = "border-b border-slate-100 dark:border-slate-800/60 hover:bg-slate-50/50 dark:hover:bg-slate-900/40";
          tr.innerHTML = \`
            <td class="p-4 font-semibold">\${u.username}</td>
            <td class="p-4 font-mono text-xs select-all bg-slate-50 dark:bg-slate-950/50 p-1.5 rounded border border-slate-100 dark:border-slate-900">\${u.uuid}</td>
            <td class="p-4">
              <div class="flex items-center gap-1.5 max-w-[280px]">
                <input type="text" readonly value="\${dohLink}" class="w-full font-mono text-xs select-all bg-slate-50 dark:bg-slate-950/50 p-1 rounded border border-slate-100 dark:border-slate-900 focus:outline-none" onclick="this.select()">
                <button onclick="copyToClipboard('\${dohLink}', this)" class="p-1 text-blue-500 hover:bg-blue-500/10 rounded border border-blue-500/10 transition flex items-center justify-center shrink-0" title="Copy DoH Connection URL">
                  <i data-lucide="copy" class="w-3.5 h-3.5"></i>
                </button>
              </div>
            </td>
            <td class="p-4">\${statusBadge}</td>
            <td class="p-4">
              <span class="px-2 py-1 rounded-md text-xs font-semibold bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 border border-slate-200/50 dark:border-slate-700/50">
                \${u.dns_provider ? u.dns_provider : 'Default (' + (appData ? appData.config.defaultDns : 'Cloudflare') + ')'}
              </span>
            </td>
            <td class="p-4 font-mono text-xs font-medium">\${u.traffic_limit_gb.toFixed(1)} GB</td>
            <td class="p-4 font-mono text-xs text-slate-500">\${u.used_gb.toFixed(4)} GB</td>
            <td class="p-4 font-mono text-xs">\${u.query_count.toLocaleString()}</td>
            <td class="p-4 text-xs text-slate-500">\${formattedExpiry}</td>
            <td class="p-4 text-right flex justify-end gap-1.5">
              <button onclick="editUserModal('\${u.uuid}', '\${u.username}', \${u.traffic_limit_gb}, '\${u.expire_at || ""}', \${u.enabled}, '\${u.dns_provider || ""}')" class="p-1.5 text-blue-500 hover:bg-blue-500/10 rounded-lg transition" title="Edit Subscription"><i data-lucide="edit" class="w-4.5 h-4.5"></i></button>
              <button onclick="resetUserTraffic('\${u.uuid}')" class="p-1.5 text-amber-500 hover:bg-amber-500/10 rounded-lg transition" title="Reset Traffic Consumption"><i data-lucide="refresh-cw" class="w-4.5 h-4.5"></i></button>
              <button onclick="deleteUser('\${u.uuid}')" class="p-1.5 text-red-500 hover:bg-red-500/10 rounded-lg transition" title="Delete Subscription"><i data-lucide="trash-2" class="w-4.5 h-4.5"></i></button>
            </td>
          \`;
          tbody.appendChild(tr);
        });
        lucide.createIcons();
      } catch (err) {
        showAlert('Failed to fetch subscription records: ' + err.message, 'error');
      }
    }

    // DNS Providers tab UI
    function updateProvidersTab() {
      if (!appData) return;
      const grid = document.getElementById('dns-providers-grid');
      grid.innerHTML = '';

      appData.providers.forEach((p, idx) => {
        const isDefault = p.name.toLowerCase() === appData.config.defaultDns.toLowerCase();
        const card = document.createElement('div');
        card.className = "bg-white dark:bg-slate-900 p-5 rounded-2xl border border-slate-200 dark:border-slate-800 space-y-4 shadow-sm flex flex-col justify-between";
        card.innerHTML = \`
          <div class="space-y-1">
            <div class="flex justify-between items-start">
              <h4 class="font-display font-bold text-lg flex items-center gap-2">
                <span>\${p.name}</span>
                \${p.is_built_in ? '<span class="text-[10px] bg-slate-100 dark:bg-slate-800 text-slate-500 px-1.5 py-0.5 rounded font-bold font-sans">Built-In</span>' : ''}
              </h4>
              <div class="flex items-center gap-2">
                <span class="text-xs text-slate-400">\${p.enabled ? 'Enabled' : 'Disabled'}</span>
                <input type="checkbox" \${p.enabled ? 'checked' : ''} onchange="toggleProviderState(\${idx})" class="w-4 h-4 rounded text-blue-600">
              </div>
            </div>
            <p class="text-xs font-mono text-slate-400 break-all select-all">\${p.url}</p>
          </div>
          <div class="flex justify-between items-center border-t border-slate-100 dark:border-slate-800/80 pt-3">
            \${isDefault ? 
              '<span class="text-xs text-indigo-500 font-bold flex items-center gap-1"><i data-lucide="check-circle" class="w-3.5 h-3.5"></i> Default Resolver</span>' : 
              \`<button onclick="setDefaultProvider('\${p.name}')" class="text-xs font-medium text-slate-500 hover:text-indigo-500 transition">Set Default</button>\`
            }
            \${!p.is_built_in ? \`<button onclick="deleteCustomProvider(\${idx})" class="text-xs text-red-500 hover:underline">Remove</button>\` : ''}
          </div>
        \`;
        grid.appendChild(card);
      });
      lucide.createIcons();
    }

    // Traffic Logs Filtering
    function updateLogsTab() {
      filterLogs();
    }

    function filterLogs() {
      if (!appData) return;
      const search = document.getElementById('logs-search-input').value.toLowerCase();
      const tbody = document.getElementById('logs-table-body');
      tbody.innerHTML = '';

      const filtered = appData.logs.filter(l => {
        return l.uuid.toLowerCase().includes(search) || 
               l.provider.toLowerCase().includes(search) || 
               l.client_ip.toLowerCase().includes(search);
      });

      if (filtered.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="p-8 text-center text-slate-400">No logs found.</td></tr>';
        return;
      }

      filtered.forEach(l => {
        const tr = document.createElement('tr');
        tr.className = "border-b border-slate-100 dark:border-slate-800/60 hover:bg-slate-50/50 dark:hover:bg-slate-900/40";
        tr.innerHTML = \`
          <td class="p-4 font-mono text-xs text-slate-500">\${new Date(l.timestamp).toLocaleString()}</td>
          <td class="p-4 font-mono text-xs select-all">\${l.uuid}</td>
          <td class="p-4"><span class="px-2 py-1 bg-slate-100 dark:bg-slate-800 rounded-lg text-xs font-medium">\${l.provider}</span></td>
          <td class="p-4 font-mono text-xs text-blue-500">\${l.client_ip}</td>
          <td class="p-4 text-xs text-slate-400 max-w-xs truncate" title="\${l.user_agent}">\${l.user_agent}</td>
        \`;
        tbody.appendChild(tr);
      });
    }

    function exportLogsCsv() {
      if (!appData || appData.logs.length === 0) {
        showAlert('No logs available for CSV export.', 'info');
        return;
      }
      let csvContent = "data:text/csv;charset=utf-8,";
      csvContent += "Timestamp,UUID,Provider,Client IP,User Agent\\n";
      
      appData.logs.forEach(l => {
        const row = [
          l.timestamp,
          l.uuid,
          l.provider,
          l.client_ip,
          \`"\${l.user_agent.replace(/"/g, '""')}"\`
        ].join(",");
        csvContent += row + "\\n";
      });

      const encodedUri = encodeURI(csvContent);
      const link = document.createElement("a");
      link.setAttribute("href", encodedUri);
      link.setAttribute("download", "doh_traffic_logs_" + new Date().toISOString().substring(0,10) + ".csv");
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    }

    // Populate system settings tab
    function updateSettingsTab() {
      if (!appData) return;
      const conf = appData.config;
      document.getElementById('setting-queries-per-gb').value = conf.queriesPerGb;
      document.getElementById('setting-cf-mode').value = conf.cfMode;
      document.getElementById('setting-dns-cache').checked = conf.dnsCache === 'true';
      document.getElementById('setting-dns-ecs').checked = conf.dnsEcs === 'true';
      document.getElementById('setting-custom-ua').value = conf.customUa;

      // Populate default DNS select options
      const selector = document.getElementById('setting-default-dns');
      selector.innerHTML = '';
      appData.providers.filter(p => p.enabled).forEach(p => {
        const opt = document.createElement('option');
        opt.value = p.name;
        opt.textContent = p.name;
        if (p.name.toLowerCase() === conf.defaultDns.toLowerCase()) {
          opt.selected = true;
        }
        selector.appendChild(opt);
      });
    }

    // Save configuration settings
    async function handleSaveSettings(e) {
      e.preventDefault();
      const queriesPerGb = document.getElementById('setting-queries-per-gb').value;
      const defaultDns = document.getElementById('setting-default-dns').value;
      const cfMode = document.getElementById('setting-cf-mode').value;
      const dnsCache = document.getElementById('setting-dns-cache').checked;
      const dnsEcs = document.getElementById('setting-dns-ecs').checked;
      const customUa = document.getElementById('setting-custom-ua').value;

      const password = document.getElementById('setting-password').value;
      const confirmPassword = document.getElementById('setting-confirm-password').value;

      const payload = {
        queriesPerGb: parseInt(queriesPerGb, 10),
        defaultDns,
        cfMode,
        dnsCache,
        dnsEcs,
        customUa
      };

      if (password) {
        if (password !== confirmPassword) {
          showAlert('Passwords do not match.', 'error');
          return;
        }
        payload.adminPassword = password;
      }

      try {
        const res = await fetch('/api/settings', {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + sessionToken
          },
          body: JSON.stringify(payload)
        });

        if (res.ok) {
          showAlert('Configurations saved successfully!', 'success');
          document.getElementById('setting-password').value = '';
          document.getElementById('setting-confirm-password').value = '';
          refreshAllData();
        } else {
          const d = await res.json();
          showAlert(d.error || 'Failed to update settings', 'error');
        }
      } catch (err) {
        showAlert('Failed to connect to configurations API', 'error');
      }
    }

    function populateUserProviderDropdowns() {
      if (!appData || !appData.providers) return;
      const createSelect = document.getElementById('create-provider');
      const editSelect = document.getElementById('edit-provider');
      if (!createSelect || !editSelect) return;

      const createVal = createSelect.value;
      const editVal = editSelect.value;

      const enabledProviders = appData.providers.filter(p => p.enabled);

      let optionsHtml = '<option value="">System Default</option>';
      enabledProviders.forEach(p => {
        optionsHtml += \`<option value="\${p.name}">\${p.name}</option>\`;
      });

      createSelect.innerHTML = optionsHtml;
      editSelect.innerHTML = optionsHtml;

      createSelect.value = createVal;
      editSelect.value = editVal;
    }

    // Users CRUD
    function openCreateUserModal() {
      populateUserProviderDropdowns();
      document.getElementById('modal-create-user').style.display = 'flex';
    }

    async function handleCreateUser(e) {
      e.preventDefault();
      const username = document.getElementById('create-username').value;
      const traffic_limit_gb = document.getElementById('create-limit').value;
      const expire_at = document.getElementById('create-expiry').value;
      const dns_provider = document.getElementById('create-provider').value;

      try {
        const res = await fetch('/api/users', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + sessionToken
          },
          body: JSON.stringify({ username, traffic_limit_gb, expire_at, dns_provider })
        });
        
        if (res.ok) {
          closeModal('modal-create-user');
          showAlert('Subscription successfully created!', 'success');
          document.getElementById('form-create-user').reset();
          refreshAllData();
        } else {
          const d = await res.json();
          showAlert(d.error || 'Failed to create subscription', 'error');
        }
      } catch (err) {
        showAlert('Connection failed', 'error');
      }
    }

    function editUserModal(uuid, name, limit, expiry, enabled, dnsProvider) {
      populateUserProviderDropdowns();
      document.getElementById('edit-uuid').value = uuid;
      document.getElementById('edit-username').value = name;
      document.getElementById('edit-limit').value = limit;
      
      if (expiry) {
        // format ISO to local datetime
        const d = new Date(expiry);
        const pad = n => n.toString().padStart(2, '0');
        const formatted = \`\${d.getFullYear()}-\${pad(d.getMonth()+1)}-\${pad(d.getDate())}T\${pad(d.getHours())}:\${pad(d.getMinutes())}\`;
        document.getElementById('edit-expiry').value = formatted.substring(0, 16);
      } else {
        document.getElementById('edit-expiry').value = '';
      }
      
      document.getElementById('edit-provider').value = dnsProvider || '';
      document.getElementById('edit-enabled').value = enabled;
      document.getElementById('modal-edit-user').style.display = 'flex';
    }

    async function handleSaveEditUser(e) {
      e.preventDefault();
      const uuid = document.getElementById('edit-uuid').value;
      const username = document.getElementById('edit-username').value;
      const traffic_limit_gb = document.getElementById('edit-limit').value;
      const expire_at = document.getElementById('edit-expiry').value;
      const dns_provider = document.getElementById('edit-provider').value;
      const enabled = document.getElementById('edit-enabled').value === '1';

      try {
        const res = await fetch('/api/users/' + uuid, {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + sessionToken
          },
          body: JSON.stringify({ username, traffic_limit_gb, expire_at, enabled, dns_provider })
        });

        if (res.ok) {
          closeModal('modal-edit-user');
          showAlert('Subscriber details updated!', 'success');
          refreshAllData();
        } else {
          const d = await res.json();
          showAlert(d.error || 'Failed to edit subscriber', 'error');
        }
      } catch (err) {
        showAlert('Connection error', 'error');
      }
    }

    async function deleteUser(uuid) {
      if (!confirm('Are you absolutely sure you want to delete this subscription? All logs for this UUID will be destroyed!')) return;
      try {
        const res = await fetch('/api/users/' + uuid, {
          method: 'DELETE',
          headers: { 'Authorization': 'Bearer ' + sessionToken }
        });
        if (res.ok) {
          showAlert('Subscription successfully destroyed', 'success');
          refreshAllData();
        } else {
          showAlert('Failed to delete user', 'error');
        }
      } catch (err) {
        showAlert('Connection error', 'error');
      }
    }

    async function resetUserTraffic(uuid) {
      if (!confirm('Reset all traffic and query logs for this user? This will re-enable the UUID immediately.')) return;
      try {
        const res = await fetch('/api/reset/' + uuid, {
          method: 'POST',
          headers: { 'Authorization': 'Bearer ' + sessionToken }
        });
        if (res.ok) {
          showAlert('User statistics reset successfully!', 'success');
          refreshAllData();
        } else {
          showAlert('Failed to reset user statistics', 'error');
        }
      } catch (err) {
        showAlert('Connection error', 'error');
      }
    }

    // Providers Actions
    async function toggleProviderState(idx) {
      if (!appData) return;
      const provider = appData.providers[idx];
      const isCurrentlyDefault = provider.name.toLowerCase() === appData.config.defaultDns.toLowerCase();
      if (isCurrentlyDefault && provider.enabled) {
        showAlert('Cannot disable the default resolver! Please set another provider as default first.', 'error');
        refreshAllData();
        return;
      }
      provider.enabled = !provider.enabled;
      await saveProvidersState();
    }

    async function deleteCustomProvider(idx) {
      if (!confirm('Are you sure you want to delete this DNS Provider?')) return;
      const provider = appData.providers[idx];
      const isCurrentlyDefault = provider.name.toLowerCase() === appData.config.defaultDns.toLowerCase();
      if (isCurrentlyDefault) {
        showAlert('Cannot delete the default resolver! Please set another provider as default first.', 'error');
        return;
      }
      appData.providers.splice(idx, 1);
      await saveProvidersState();
    }

    async function setDefaultProvider(name) {
      const provider = appData.providers.find(p => p.name.toLowerCase() === name.toLowerCase());
      if (provider && !provider.enabled) {
        showAlert('Cannot set a disabled provider as the default resolver! Please enable it first.', 'error');
        return;
      }
      try {
        const res = await fetch('/api/settings', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + sessionToken
          },
          body: JSON.stringify({ defaultDns: name })
        });
        if (res.ok) {
          showAlert('Default Upstream DNS configured to ' + name, 'success');
          refreshAllData();
        } else {
          const data = await res.json();
          showAlert(data.error || 'Failed to update default DNS provider', 'error');
          refreshAllData();
        }
      } catch (err) {
        showAlert('Connection failure', 'error');
      }
    }

    function openAddProviderModal() {
      document.getElementById('modal-add-provider').style.display = 'flex';
    }

    async function handleAddProvider(e) {
      e.preventDefault();
      const name = document.getElementById('add-provider-name').value;
      const url = document.getElementById('add-provider-url').value;

      appData.providers.push({
        name,
        url,
        enabled: true,
        is_built_in: false
      });

      closeModal('modal-add-provider');
      document.getElementById('form-add-provider').reset();
      await saveProvidersState();
    }

    async function saveProvidersState() {
      try {
        const res = await fetch('/api/settings', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + sessionToken
          },
          body: JSON.stringify({ providers: appData.providers })
        });
        if (res.ok) {
          showAlert('DNS providers updated successfully', 'success');
          refreshAllData();
        } else {
          const data = await res.json();
          showAlert(data.error || 'Failed to synchronize resolvers', 'error');
          refreshAllData();
        }
      } catch (err) {
        showAlert('Connection error syncing resolvers', 'error');
      }
    }

    function closeModal(id) {
      document.getElementById(id).style.display = 'none';
    }

    // Alert Banner Manager
    function showAlert(text, type = 'info') {
      const banner = document.getElementById('alert-banner');
      const icon = document.getElementById('alert-icon');
      const textEl = document.getElementById('alert-text');
      
      textEl.textContent = text;
      
      banner.className = "p-4 rounded-xl text-sm border flex items-center justify-between gap-3 animate-fade-in";
      
      if (type === 'success') {
        banner.classList.add('bg-emerald-50', 'text-emerald-800', 'border-emerald-200', 'dark:bg-emerald-950/20', 'dark:text-emerald-400', 'dark:border-emerald-900/40');
        icon.setAttribute('data-lucide', 'check-circle');
      } else if (type === 'error') {
        banner.classList.add('bg-red-50', 'text-red-800', 'border-red-200', 'dark:bg-red-950/20', 'dark:text-red-400', 'dark:border-red-900/40');
        icon.setAttribute('data-lucide', 'alert-triangle');
      } else {
        banner.classList.add('bg-blue-50', 'text-blue-800', 'border-blue-200', 'dark:bg-blue-950/20', 'dark:text-blue-400', 'dark:border-blue-900/40');
        icon.setAttribute('data-lucide', 'info');
      }
      
      lucide.createIcons();
      banner.classList.remove('hidden');

      // Auto hide after 4 seconds
      setTimeout(hideAlert, 4000);
    }

    function hideAlert() {
      document.getElementById('alert-banner').classList.add('hidden');
    }

    // Chart.js Configuration & Rendering
    function updateCharts() {
      if (!appData || activeTab !== 'statistics') return;

      const isDark = document.documentElement.classList.contains('dark');
      const gridColor = isDark ? '#1e293b' : '#e2e8f0';
      const textColor = isDark ? '#f8fafc' : '#0f172a';

      // 1. Daily queries Chart
      const dailyCanvas = document.getElementById('chart-daily-queries');
      if (chartDaily) chartDaily.destroy();
      
      const dailyData = appData.charts.daily;
      const dailyLabels = dailyData.map(d => d.day);
      const dailyCounts = dailyData.map(d => d.count);

      chartDaily = new Chart(dailyCanvas, {
        type: 'line',
        data: {
          labels: dailyLabels.length > 0 ? dailyLabels : [new Date().toISOString().substring(0,10)],
          datasets: [{
            label: 'Queries count',
            data: dailyCounts.length > 0 ? dailyCounts : [0],
            borderColor: '#f6821f',
            backgroundColor: 'rgba(246, 130, 31, 0.1)',
            fill: true,
            tension: 0.3,
            borderWidth: 2
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            x: { grid: { color: gridColor }, ticks: { color: textColor } },
            y: { grid: { color: gridColor }, ticks: { color: textColor }, beginAtZero: true }
          }
        }
      });

      // 2. Upstream Popularity
      const provCanvas = document.getElementById('chart-providers');
      if (chartProv) chartProv.destroy();

      const provData = appData.charts.providers;
      const provLabels = provData.map(p => p.provider);
      const provCounts = provData.map(p => p.count);

      chartProv = new Chart(provCanvas, {
        type: 'doughnut',
        data: {
          labels: provLabels.length > 0 ? provLabels : ['No active traffic'],
          datasets: [{
            data: provCounts.length > 0 ? provCounts : [1],
            backgroundColor: ['#f6821f', '#10b981', '#3b82f6', '#8b5cf6', '#ec4899', '#f59e0b', '#14b8a6'],
            borderWidth: 0
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { 
            legend: { 
              position: 'right',
              labels: { color: textColor }
            } 
          }
        }
      });

      // 3. Top Users Chart
      const usersCanvas = document.getElementById('chart-top-users');
      if (chartUsers) chartUsers.destroy();

      const topUsers = appData.charts.topUsers;
      const userLabels = topUsers.map(u => u.username);
      const userQueries = topUsers.map(u => u.query_count);

      chartUsers = new Chart(usersCanvas, {
        type: 'bar',
        data: {
          labels: userLabels.length > 0 ? userLabels : ['No Users'],
          datasets: [{
            label: 'DNS Queries Volume',
            data: userQueries.length > 0 ? userQueries : [0],
            backgroundColor: '#f6821f',
            borderRadius: 8
          }]
        },
        options: {
          indexAxis: 'y',
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            x: { grid: { color: gridColor }, ticks: { color: textColor }, beginAtZero: true },
            y: { grid: { display: false }, ticks: { color: textColor } }
          }
        }
      });
    }
  </script>
</body>
</html>
`;

function getSubscriberPageHTML(user, host, providers, defaultDnsName) {
  // Determine user status
  let status = 'ACTIVE';
  let statusColor = 'text-emerald-500 bg-emerald-500/10 border-emerald-500/20';
  let isExpired = false;
  let isQuotaExceeded = false;

  if (user.expire_at) {
    const expireTime = new Date(user.expire_at).getTime();
    if (Date.now() > expireTime) {
      isExpired = true;
    }
  }
  if (user.used_gb >= user.traffic_limit_gb) {
    isQuotaExceeded = true;
  }

  if (user.enabled !== 1) {
    status = 'BLOCKED';
    statusColor = 'text-red-500 bg-red-500/10 border-red-500/20';
  } else if (isExpired) {
    status = 'EXPIRED';
    statusColor = 'text-amber-500 bg-amber-500/10 border-amber-500/20';
  } else if (isQuotaExceeded) {
    status = 'LIMIT EXCEEDED';
    statusColor = 'text-amber-500 bg-amber-500/10 border-amber-500/20';
  }

  const usedGb = parseFloat(user.used_gb.toFixed(4));
  const limitGb = parseFloat(user.traffic_limit_gb.toFixed(2));
  const percent = Math.min(100, Math.max(0, (usedGb / limitGb) * 100)).toFixed(1);
  const remainingGb = parseFloat((limitGb - usedGb).toFixed(4));
  const formattedExpiry = user.expire_at ? new Date(user.expire_at).toLocaleString() : 'Lifetime';

  // Format providers to show only enabled ones
  const enabledProviders = providers.filter(p => p.enabled);
  const activeProvider = user.dns_provider || defaultDnsName || 'Cloudflare';

  return `<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DNS Over HTTPS Subscription | ${user.username}</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Space+Grotesk:wght@500;600;700&display=swap">
  <script src="https://unpkg.com/lucide@latest"></script>
  <style>
    :root {
      --cf-orange: #f6821f;
      --cf-dark: #0f172a;
      --cf-card: #1e293b;
      --cf-border: #334155;
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
    }
    body {
      font-family: 'Inter', sans-serif;
      background-color: #0b1120;
    }
    .font-display {
      font-family: 'Space Grotesk', sans-serif;
    }
  </style>
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: {
        extend: {
          colors: {
            orange: {
              500: '#f6821f',
              600: '#e06e12',
            }
          }
        }
      }
    }
  </script>
</head>
<body class="text-slate-100 min-h-screen flex flex-col justify-between">

  <!-- Header -->
  <header class="border-b border-slate-800 bg-slate-900/50 backdrop-blur-md sticky top-0 z-40">
    <div class="max-w-6xl mx-auto px-4 py-4 flex items-center justify-between">
      <div class="flex items-center gap-3">
        <div class="p-2.5 bg-orange-500 text-white rounded-xl font-bold font-display tracking-tight shadow-lg shadow-orange-500/20">
          CF
        </div>
        <div>
          <span class="font-display font-bold text-base tracking-tight block">Secure DoH Service</span>
          <span class="text-[10px] block text-emerald-400 font-medium">● Network Node Connected</span>
        </div>
      </div>
      <div class="flex items-center gap-2">
        <span class="px-2.5 py-1 text-xs font-semibold rounded-full border ${statusColor}">
          ${status}
        </span>
      </div>
    </div>
  </header>

  <!-- Main Dashboard -->
  <main class="max-w-6xl w-full mx-auto px-4 py-8 flex-1 grid grid-cols-1 lg:grid-cols-12 gap-8">
    
    <!-- LEFT PANEL: Subscription details -->
    <section class="lg:col-span-5 space-y-6">
      <div class="bg-slate-900 border border-slate-800 p-6 rounded-2xl shadow-xl space-y-6">
        <div class="flex items-center gap-4">
          <div class="w-12 h-12 rounded-2xl bg-orange-500/10 flex items-center justify-center border border-orange-500/20">
            <i data-lucide="user" class="w-6 h-6 text-orange-500"></i>
          </div>
          <div>
            <h2 class="font-display font-bold text-lg text-white">${user.username}</h2>
            <p class="text-xs text-slate-400">Subscriber Dashboard</p>
          </div>
        </div>

        <div class="border-t border-slate-800/80 pt-4 space-y-4">
          <div>
            <div class="flex justify-between text-xs font-medium text-slate-400 mb-1.5">
              <span>Traffic Consumption</span>
              <span>${percent}%</span>
            </div>
            <!-- Progress Bar -->
            <div class="w-full bg-slate-800 rounded-full h-3.5 overflow-hidden p-[2px] border border-slate-700/50">
              <div class="bg-gradient-to-r from-orange-500 to-amber-500 h-full rounded-full transition-all duration-500" style="width: ${percent}%"></div>
            </div>
            <div class="flex justify-between text-xs text-slate-500 mt-1.5">
              <span>Used: <strong class="text-slate-300 font-mono">${usedGb} GB</strong></span>
              <span>Limit: <strong class="text-slate-300 font-mono">${limitGb} GB</strong></span>
            </div>
          </div>

          <div class="grid grid-cols-2 gap-4 border-t border-slate-800/80 pt-4">
            <div class="bg-slate-950/40 p-3 rounded-xl border border-slate-800/50">
              <span class="text-[10px] uppercase tracking-wider text-slate-500 block mb-0.5">Remaining Traffic</span>
              <span class="text-sm font-bold font-mono text-emerald-400">${remainingGb < 0 ? 0 : remainingGb} GB</span>
            </div>
            <div class="bg-slate-950/40 p-3 rounded-xl border border-slate-800/50">
              <span class="text-[10px] uppercase tracking-wider text-slate-500 block mb-0.5">Total Queries</span>
              <span class="text-sm font-bold font-mono text-blue-400">${user.query_count}</span>
            </div>
          </div>

          <div class="space-y-2 border-t border-slate-800/80 pt-4 text-xs text-slate-400">
            <div class="flex justify-between">
              <span>UUID Token:</span>
              <span class="font-mono text-slate-200 select-all">${user.uuid}</span>
            </div>
            <div class="flex justify-between">
              <span>Expiration Date:</span>
              <span class="font-medium text-slate-200">${formattedExpiry}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Support card -->
      <div class="bg-slate-900/50 border border-slate-800/50 p-6 rounded-2xl space-y-3">
        <h4 class="font-display font-bold text-sm text-slate-300 flex items-center gap-2">
          <i data-lucide="shield" class="w-4 h-4 text-orange-500"></i>
          <span>Secure DNS Encryption</span>
        </h4>
        <p class="text-xs text-slate-400 leading-relaxed">
          Your connection is encrypted using TLS 1.3, preventing your Internet Service Provider (ISP) or local network admins from eavesdropping on your DNS inquiries.
        </p>
      </div>
    </section>

    <!-- RIGHT PANEL: Interactive DNS Connection Setup -->
    <section class="lg:col-span-7 space-y-6">
      <div class="bg-slate-900 border border-slate-800 p-6 rounded-2xl shadow-xl space-y-6">
        <div>
          <h3 class="font-display font-bold text-lg text-white">Connection Configuration</h3>
          <p class="text-xs text-slate-400 mt-1">Select your preferred upstream DNS server to customize your connection URL.</p>
        </div>

        <!-- DNS Resolver Dropdown -->
        <div class="space-y-2">
          <div class="flex justify-between items-center">
            <label class="text-xs font-semibold text-slate-300 block">Upstream DNS Resolver</label>
            <span class="text-[10px] text-orange-500 font-semibold animate-pulse hidden" id="saving-status">● Saving Changes...</span>
            <span class="text-[10px] text-slate-500 font-medium" id="resolver-status">Interactive Subscriber Mode</span>
          </div>
          <div class="relative">
            <select id="resolver-select" onchange="updateDnsProvider(this.value)" class="w-full px-4 py-3 rounded-xl border border-slate-700 bg-slate-950 text-slate-200 text-sm focus:outline-none focus:ring-2 focus:ring-orange-500/40 appearance-none cursor-pointer transition">
              ${enabledProviders.map(p => {
                const isSel = p.name.toLowerCase() === activeProvider.toLowerCase();
                return `<option value="${p.name}" ${isSel ? 'selected' : ''}>${p.name}</option>`;
              }).join('')}
            </select>
            <div class="absolute inset-y-0 right-4 flex items-center pointer-events-none text-slate-400">
              <i data-lucide="chevron-down" class="w-4 h-4"></i>
            </div>
          </div>
        </div>

        <!-- Connection URL -->
        <div class="space-y-2">
          <label class="text-xs font-semibold text-slate-300 block">Your Personal DoH Address (Intra / Chrome)</label>
          <div class="flex gap-2">
            <input type="text" id="connection-url-input" readonly class="flex-1 px-4 py-3 rounded-xl border border-slate-700 bg-slate-950 text-orange-400 font-mono text-xs select-all focus:outline-none" onclick="this.select()">
            <button onclick="copyConnectionUrl(this)" class="px-4 bg-orange-500 hover:bg-orange-600 active:scale-95 text-white rounded-xl transition flex items-center justify-center shrink-0 shadow-lg shadow-orange-500/10">
              <i data-lucide="copy" class="w-4 h-4"></i>
            </button>
          </div>
        </div>

        <!-- Setup Guides tabs -->
        <div class="border-t border-slate-800 pt-6">
          <h4 class="font-display font-semibold text-sm text-white mb-4">Client Installation Instructions</h4>
          
          <div class="space-y-4">
            <!-- Intra app -->
            <div class="p-4 bg-slate-950/40 rounded-xl border border-slate-800/80 space-y-2.5">
              <div class="flex items-center gap-2">
                <div class="p-1.5 bg-orange-500/10 rounded-lg text-orange-500">
                  <i data-lucide="smartphone" class="w-4 h-4"></i>
                </div>
                <h5 class="text-xs font-bold text-white">Android: Intra App Integration (Recommended)</h5>
              </div>
              <ol class="list-decimal list-inside text-xs text-slate-400 space-y-1.5 pl-1 leading-relaxed">
                <li>Install the free <strong class="text-slate-300">Intra</strong> app from the Play Store.</li>
                <li>Open Intra, tap the menu (top left) and choose <strong class="text-slate-300">Settings</strong>.</li>
                <li>Tap <strong class="text-slate-300">Select DNS Provider</strong> and choose <strong class="text-slate-300">Custom Server URL</strong>.</li>
                <li>Paste your personal DoH Address from above into the input field and tap <strong class="text-slate-300">Accept</strong>.</li>
                <li>Turn the switch on the main screen <strong class="text-emerald-400">ON</strong>.</li>
              </ol>
            </div>

            <!-- Browser Guide -->
            <div class="p-4 bg-slate-950/40 rounded-xl border border-slate-800/80 space-y-2.5">
              <div class="flex items-center gap-2">
                <div class="p-1.5 bg-blue-500/10 rounded-lg text-blue-400">
                  <i data-lucide="chrome" class="w-4 h-4"></i>
                </div>
                <h5 class="text-xs font-bold text-white">Browsers: Google Chrome / Edge / Brave</h5>
              </div>
              <ol class="list-decimal list-inside text-xs text-slate-400 space-y-1.5 pl-1 leading-relaxed">
                <li>Go to browser <strong class="text-slate-300">Settings</strong>.</li>
                <li>Search for or navigate to <strong class="text-slate-300">Security & Privacy</strong>.</li>
                <li>Enable <strong class="text-slate-300">Use secure DNS</strong>.</li>
                <li>Select <strong class="text-slate-300">Customized / Enter custom provider</strong>.</li>
                <li>Paste your personal DoH Address into the text box.</li>
              </ol>
            </div>
          </div>
        </div>
      </div>
    </section>
  </main>

  <!-- Footer -->
  <footer class="border-t border-slate-900 bg-slate-950/80 py-6 text-center text-xs text-slate-500">
    <div class="max-w-6xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-4">
      <p>&copy; ${new Date().getFullYear()} DNS over HTTPS Gateway. All rights reserved.</p>
      <div class="flex items-center gap-1.5">
        <div class="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></div>
        <span class="font-medium text-slate-400">Node Secure Endpoint</span>
      </div>
    </div>
  </footer>

  <script>
    const uuid = "${user.uuid}";
    const host = "${host}";

    function updateConnectionLink() {
      const input = document.getElementById('connection-url-input');
      input.value = 'https://' + host + '/dns-query/' + uuid;
    }

    function copyConnectionUrl(btn) {
      const input = document.getElementById('connection-url-input');
      const text = input.value;
      
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(() => {
          animateCopyButton(btn);
        }).catch(() => {
          fallbackCopy(text, btn);
        });
      } else {
        fallbackCopy(text, btn);
      }
    }

    function fallbackCopy(text, btn) {
      const el = document.createElement('textarea');
      el.value = text;
      el.style.position = 'fixed';
      document.body.appendChild(el);
      el.select();
      try {
        document.execCommand('copy');
        animateCopyButton(btn);
      } catch (e) {
        console.error('fallback copy failed', e);
      }
      document.body.removeChild(el);
    }

    function animateCopyButton(btn) {
      const originalHtml = btn.innerHTML;
      btn.innerHTML = '<i data-lucide="check" class="w-4 h-4 text-emerald-400"></i>';
      btn.classList.add('bg-emerald-500/10', 'border', 'border-emerald-500/30');
      btn.classList.remove('bg-orange-500', 'hover:bg-orange-600');
      lucide.createIcons();
      setTimeout(() => {
        btn.innerHTML = originalHtml;
        btn.classList.remove('bg-emerald-500/10', 'border', 'border-emerald-500/30');
        btn.classList.add('bg-orange-500', 'hover:bg-orange-600');
        lucide.createIcons();
      }, 1500);
    }

    async function updateDnsProvider(dnsProvider) {
      const savingEl = document.getElementById('saving-status');
      const statusEl = document.getElementById('resolver-status');
      
      savingEl.classList.remove('hidden');
      statusEl.classList.add('hidden');
      
      try {
        const response = await fetch(window.location.href, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ dns_provider: dnsProvider })
        });
        
        const data = await response.json();
        if (response.ok && data.success) {
          // Success! Flash save indicator
          savingEl.textContent = '● Changes Saved!';
          savingEl.className = 'text-[10px] text-emerald-400 font-semibold';
          setTimeout(() => {
            savingEl.classList.add('hidden');
            savingEl.textContent = '● Saving Changes...';
            savingEl.className = 'text-[10px] text-orange-500 font-semibold animate-pulse';
            statusEl.classList.remove('hidden');
          }, 1500);
        } else {
          alert('Failed to update DNS provider: ' + (data.error || 'Unknown error'));
          window.location.reload();
        }
      } catch (err) {
        console.error(err);
        alert('Network error while updating DNS provider');
        window.location.reload();
      }
    }

    // Initialize connection link on load
    updateConnectionLink();
    lucide.createIcons();
  </script>
</body>
</html>`;
}
