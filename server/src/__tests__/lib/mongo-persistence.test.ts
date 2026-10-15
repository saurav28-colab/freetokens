import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import express from 'express';
import { initDb, getUnifiedApiKey } from '../../db/index.js';
import type { Db } from '../../db/types.js';
import { encrypt } from '../../lib/crypto.js';
import {
  attachMongoPersistence, closeMongoPersistence, flushToMongo, mongoPersistence, type MongoCollection,
} from '../../lib/mongo-persistence.js';

class FakeCollection implements MongoCollection {
  docs = new Map<unknown, Record<string, unknown>>();
  constructor(private readonly mongo: FakeMongo) {}
  find() { return { toArray: async () => [...this.docs.values()].map(d => ({ ...d })) as any }; }
  async bulkWrite(ops: any[]) {
    if (this.mongo.fail) throw new Error('down');
    for (const { replaceOne } of ops) this.docs.set(replaceOne.filter._id, { ...replaceOne.replacement });
  }
  async deleteMany(filter: any) {
    if (this.mongo.fail) throw new Error('down');
    const keep = new Set(filter._id.$nin);
    for (const id of [...this.docs.keys()]) if (!keep.has(id)) this.docs.delete(id);
  }
}

class FakeMongo {
  fail = false;
  private readonly colls = new Map<string, FakeCollection>();
  coll(name: string): FakeCollection {
    if (!this.colls.has(name)) this.colls.set(name, new FakeCollection(this));
    return this.colls.get(name)!;
  }
  readonly collectionFor = (name: string) => this.coll(name);
}

function insertKey(db: Db, platform: string, secret = 'sk-test'): number {
  const { encrypted, iv, authTag } = encrypt(secret);
  return Number(db.prepare(
    'INSERT INTO api_keys (platform, label, encrypted_key, iv, auth_tag) VALUES (?, ?, ?, ?, ?)',
  ).run(platform, '', encrypted, iv, authTag).lastInsertRowid);
}

function count(db: Db, table: string): number {
  return (db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get() as { n: number }).n;
}

async function post(app: express.Express, path: string): Promise<{ status: number }> {
  const server = app.listen(0, '127.0.0.1');
  await new Promise<void>(resolve => server.once('listening', () => resolve()));
  try {
    const { port } = server.address() as { port: number };
    const res = await fetch(`http://127.0.0.1:${port}${path}`, { method: 'POST' });
    return { status: res.status };
  } finally {
    server.close();
  }
}

describe('mongo-persistence', () => {
  let db: Db;
  let mongo: FakeMongo;

  beforeEach(() => {
    process.env.ENCRYPTION_KEY = '0'.repeat(64);
    db = initDb(':memory:');
    mongo = new FakeMongo();
  });
  afterEach(async () => { await closeMongoPersistence(); });

  it('seeds empty collections from the local tables, preserving primary keys', async () => {
    const id = insertKey(db, 'groq');
    await attachMongoPersistence(db, mongo.collectionFor);
    expect(mongo.coll('api_keys').docs.get(id)).toMatchObject({ _id: id, platform: 'groq', status: 'unknown', enabled: 1 });
    expect(mongo.coll('api_keys').docs.get(id)).not.toHaveProperty('id');
    expect(mongo.coll('settings').docs.get('unified_api_key')).toMatchObject({ value: getUnifiedApiKey() });
  });

  it('replaces the local key table with MongoDB contents on boot', async () => {
    insertKey(db, 'stale');
    const { encrypted, iv, authTag } = encrypt('sk-real');
    mongo.coll('api_keys').docs.set(42, { _id: 42, platform: 'google', label: 'main', encrypted_key: encrypted, iv, auth_tag: authTag, status: 'healthy', enabled: 1, created_at: '2026-01-01 00:00:00', unknown_field: 'x' });
    await attachMongoPersistence(db, mongo.collectionFor);
    expect(db.prepare('SELECT id, platform, status FROM api_keys').all())
      .toEqual([{ id: 42, platform: 'google', status: 'healthy' }]);
    // AUTOINCREMENT continues after the hydrated id.
    expect(insertKey(db, 'groq')).toBe(43);
  });

  it('restores the unified API key and keeps settings rows MongoDB has not seen', async () => {
    mongo.coll('settings').docs.set('unified_api_key', { _id: 'unified_api_key', value: 'freellmapi-persisted' });
    db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('new_default', 'x')").run();
    await attachMongoPersistence(db, mongo.collectionFor);
    expect(getUnifiedApiKey()).toBe('freellmapi-persisted');
    expect(db.prepare("SELECT value FROM settings WHERE key = 'new_default'").get()).toEqual({ value: 'x' });
    expect(mongo.coll('settings').docs.has('new_default')).toBe(true);
  });

  it('never persists a fallback encryption key from settings', async () => {
    db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('encryption_key', 'secret')").run();
    await attachMongoPersistence(db, mongo.collectionFor);
    expect(mongo.coll('settings').docs.has('encryption_key')).toBe(false);
  });

  it('restores dashboard accounts and their sessions', async () => {
    mongo.coll('users').docs.set(7, { _id: 7, email: 'a@example.com', password_hash: 'h', created_at: '2026-01-01 00:00:00' });
    mongo.coll('sessions').docs.set('tok', { _id: 'tok', user_id: 7, expires_at_ms: 9e12, created_at: '2026-01-01 00:00:00' });
    await attachMongoPersistence(db, mongo.collectionFor);
    expect(db.prepare('SELECT id, email FROM users').all()).toEqual([{ id: 7, email: 'a@example.com' }]);
    expect(db.prepare('SELECT token_hash, user_id FROM sessions').all()).toEqual([{ token_hash: 'tok', user_id: 7 }]);

    db.prepare('DELETE FROM sessions').run();
    await flushToMongo();
    expect(mongo.coll('sessions').docs.size).toBe(0);
    expect(mongo.coll('users').docs.size).toBe(1);
  });

  it('refuses to boot when stored keys do not decrypt with ENCRYPTION_KEY', async () => {
    mongo.coll('api_keys').docs.set(1, { _id: 1, platform: 'groq', label: '', encrypted_key: 'aa', iv: '0'.repeat(32), auth_tag: '0'.repeat(32) });
    await expect(attachMongoPersistence(db, mongo.collectionFor)).rejects.toThrow(/ENCRYPTION_KEY/);
  });

  it('mirrors inserts, updates and deletes', async () => {
    await attachMongoPersistence(db, mongo.collectionFor);
    const a = insertKey(db, 'groq');
    const b = insertKey(db, 'nvidia');
    await flushToMongo();
    db.prepare("UPDATE api_keys SET status = 'healthy' WHERE id = ?").run(a);
    db.prepare('DELETE FROM api_keys WHERE id = ?').run(b);
    await flushToMongo();
    expect([...mongo.coll('api_keys').docs.keys()]).toEqual([a]);
    expect(mongo.coll('api_keys').docs.get(a)!.status).toBe('healthy');
  });

  it('holds the response until MongoDB has the change, and 503s if it cannot', async () => {
    await attachMongoPersistence(db, mongo.collectionFor);
    const app = express();
    app.use('/api', mongoPersistence());
    app.post('/api/keys', (_req, res) => { insertKey(db, 'cohere'); res.json({ ok: true }); });
    app.post('/api/settings', (_req, res) => {
      db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('routing', 'fast')").run();
      res.json({ ok: true });
    });

    expect((await post(app, '/api/keys')).status).toBe(200);
    expect([...mongo.coll('api_keys').docs.values()].map(d => d.platform)).toEqual(['cohere']);
    expect((await post(app, '/api/settings')).status).toBe(200);
    expect(mongo.coll('settings').docs.get('routing')).toMatchObject({ value: 'fast' });

    mongo.fail = true;
    expect((await post(app, '/api/keys')).status).toBe(503);
    // While MongoDB stays down, key changes are refused before touching SQLite.
    const before = count(db, 'api_keys');
    expect((await post(app, '/api/keys')).status).toBe(503);
    expect(count(db, 'api_keys')).toBe(before);

    mongo.fail = false;
    expect((await post(app, '/api/keys')).status).toBe(200);
    expect(mongo.coll('api_keys').docs.size).toBe(3);
  });
});
