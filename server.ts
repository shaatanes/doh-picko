/**
 * Local Cloudflare Workers Dev Simulator
 * Connects Express requests on port 3000 to the pristine worker.js fetch handler.
 * Simulates Cloudflare D1 with a local sqlite3 file, and KV with local JSON files.
 */

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

import express from 'express';
import path from 'path';
import fs from 'fs';
import Database from 'better-sqlite3';

// @ts-ignore
import worker from './worker.js';

const app = express();
const PORT = 3000;

// Setup Local Databases
const D1_DB_FILE = 'd1_local.db';
const KV_FILE = 'kv_local.json';

const sqlite = new Database(D1_DB_FILE);

// D1 Binding Emulation
const DB = {
  prepare: (sql: string) => {
    try {
      const stmt = sqlite.prepare(sql);
      
      const executeStatement = (args: any[], method: 'run' | 'all' | 'get') => {
        const mappedArgs = args.map(arg => {
          if (typeof arg === 'boolean') return arg ? 1 : 0;
          return arg;
        });

        if (method === 'run') {
          const info = stmt.run(...mappedArgs);
          return { success: true, meta: { changes: info.changes } };
        } else if (method === 'all') {
          const results = stmt.all(...mappedArgs);
          return { success: true, results };
        } else {
          const result = stmt.get(...mappedArgs);
          return result;
        }
      };

      return {
        bind: (...args: any[]) => {
          return {
            run: async () => executeStatement(args, 'run'),
            all: async () => executeStatement(args, 'all'),
            first: async (colName?: string) => {
              const row: any = executeStatement(args, 'get');
              if (!row) return null;
              if (colName) return row[colName];
              return row;
            }
          };
        },
        run: async () => executeStatement([], 'run'),
        all: async () => executeStatement([], 'all'),
        first: async (colName?: string) => {
          const row: any = executeStatement([], 'get');
          if (!row) return null;
          if (colName) return row[colName];
          return row;
        }
      };
    } catch (err: any) {
      // In case prepare fails because table doesn't exist yet during init steps
      // Return a dummy binder that will fail gracefully or allow execution to continue
      return {
        bind: (...args: any[]) => ({
          run: async () => { throw err; },
          all: async () => { throw err; },
          first: async () => { throw err; }
        }),
        run: async () => { throw err; },
        all: async () => { throw err; },
        first: async () => { throw err; }
      };
    }
  }
};

// KV Binding Emulation
let kvStore: Record<string, string> = {};
if (fs.existsSync(KV_FILE)) {
  try {
    kvStore = JSON.parse(fs.readFileSync(KV_FILE, 'utf8'));
  } catch (e) {}
}

const saveKv = () => {
  fs.writeFileSync(KV_FILE, JSON.stringify(kvStore, null, 2));
};

const KV = {
  get: async (key: string) => {
    return kvStore[key] || null;
  },
  put: async (key: string, value: string) => {
    kvStore[key] = value;
    saveKv();
  },
  delete: async (key: string) => {
    delete kvStore[key];
    saveKv();
  }
};

// Mount body parsers for specific paths before proxying
app.use('/api', express.json());
app.use('/dns-query', express.raw({ type: '*/*' }));

// Worker Gateway Handler
app.all('*', async (req, res) => {
  try {
    const protocol = req.protocol;
    const host = req.get('host') || `localhost:${PORT}`;
    const fullUrl = `${protocol}://${host}${req.originalUrl}`;
    
    const headers = new Headers();
    for (const [key, value] of Object.entries(req.headers)) {
      if (value) {
        if (Array.isArray(value)) {
          value.forEach(v => headers.append(key, v));
        } else {
          headers.set(key, value);
        }
      }
    }
    
    let body: any = null;
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      if (req.originalUrl.startsWith('/dns-query')) {
        // Carry raw binary DNS payloads for POST requests
        body = req.body;
      } else {
        // JSON API data
        body = typeof req.body === 'object' ? JSON.stringify(req.body) : req.body;
      }
    }
    
    const request = new Request(fullUrl, {
      method: req.method,
      headers: headers,
      body: body
    });
    
    const ctx = {
      waitUntil: (promise: Promise<any>) => {
        promise.catch(e => console.error('Error in simulation waitUntil:', e));
      }
    };
    
    const env = {
      DB,
      KV,
      JWT_SECRET: 'local-dev-jwt-secret-key-12345'
    };
    
    const response = await worker.fetch(request, env, ctx);
    
    // Copy headers and status
    res.status(response.status);
    response.headers.forEach((value, key) => {
      res.setHeader(key, value);
    });
    
    // Send binary or text body
    const arrayBuffer = await response.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);
    res.send(buffer);
  } catch (err: any) {
    console.error('Error in local worker pipeline simulation:', err);
    res.status(500).send(`Simulation Pipeline Failure: ${err.message}`);
  }
});

// Run Dev Server on Port 3000
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Cloudflare Workers Simulator booted successfully on http://0.0.0.0:${PORT}`);
  console.log(`Pristine worker.js is mapped on port ${PORT}`);
});
