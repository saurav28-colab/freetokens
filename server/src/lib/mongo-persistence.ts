import { MongoClient } from 'mongodb';
import type { RequestHandler } from 'express';
import type { Db } from '../db/types.js';
import { decrypt } from './crypto.js';

/**
 * Optional MongoDB persistence for the state that must survive a host with an
 * ephemeral filesystem (e.g. Render Free), where the SQLite file is lost on
 * every restart or redeploy:
 *
 *   - api_keys  provider keys (encrypted)
 *   - users     dashboard accounts (password hashes)
 *   - sessions  dashboard logins (token hashes)
 *   - settings  unified API key, routing and proxy settings, etc.
 *
 * MongoDB is the durable source of truth; the local SQLite tables are the
 * in-process cache every existing read path already uses, so none of those
 * call sites change:
 *
 *   - Boot: MongoDB contents are loaded into the local tables. A collection
 *     that is still empty is instead seeded from the local table (the one-time
 *     migration).
 *   - Changes: connection-scoped TEMP triggers bump a per-table version counter
 *     on every insert/update/delete. A dirty table is pushed to MongoDB as a
 *     full snapshot (primary keys preserved as `_id`). Responses to dashboard
 *     writes are held until the change is flushed; background writes (health
 *     status, budgets, session expiry) are flushed on a short interval.
 *
 * Provider secrets are stored exactly as SQLite holds them: AES-256-GCM
 * ciphertext with its hex IV and auth tag, so the same ENCRYPTION_KEY must be
 * configured wherever the documents are read. Nothing is decrypted except one
 * boot-time check that the configured key matches.
 *
 * Disabled entirely unless MONGODB_URI is set.
 */

interface TableSpec {
  table: string;
  pk: string;
  /**
   * 'replace': the local table becomes exactly the MongoDB contents.
   * 'merge': MongoDB rows overwrite local ones but local-only rows are kept —
   * used for settings, where a newer build seeds default rows at boot that
   * MongoDB has never seen and the code expects to exist.
   */
  hydrate: 'replace' | 'merge';
  /** SQL condition for rows that are never persisted. */
  exclude?: string;
}

// Load order matters: sessions reference users.
const TABLES: TableSpec[] = [
  { table: 'api_keys', pk: 'id', hydrate: 'replace' },
  { table: 'users', pk: 'id', hydrate: 'replace' },
  { table: 'sessions', pk: 'token_hash', hydrate: 'replace' },
  // The dev-fallback encryption key must never sit next to the ciphertext it
  // protects; production takes ENCRYPTION_KEY from the environment.
  { table: 'settings', pk: 'key', hydrate: 'merge', exclude: "key = 'encryption_key'" },
];

type Row = Record<string, unknown>;
type Doc = Record<string, unknown> & { _id: unknown };

/** The subset of a mongodb Collection this module uses (lets tests pass a fake). */
export interface MongoCollection {
  find(filter: object): { toArray(): Promise<Doc[]> };
  bulkWrite(ops: any[], opts?: object): Promise<unknown>;
  deleteMany(filter: object): Promise<unknown>;
}

export type CollectionFor = (table: string) => MongoCollection;

const FLUSH_INTERVAL_MS = 15_000;

let localDb: Db | null = null;
let collectionFor: CollectionFor | null = null;
const syncedVersion = new Map<string, number>();
let healthy = false;
let flushChain: Promise<void> = Promise.resolve();
let timer: NodeJS.Timeout | null = null;
let client: MongoClient | null = null;

export function isMongoPersistenceEnabled(): boolean {
  return collectionFor !== null;
}

/** Connect, hydrate the local tables, and start mirroring. No-op without MONGODB_URI. */
export async function initMongoPersistence(db: Db): Promise<void> {
  const uri = process.env.MONGODB_URI?.trim();
  if (!uri) return;
  const dbName = process.env.MONGODB_DB?.trim() || 'freellmapi';

  client = new MongoClient(uri, { serverSelectionTimeoutMS: 15_000 });
  try {
    await client.connect();
  } catch (err: any) {
    // Never echo the URI: it carries the Atlas password.
    throw new Error(
      `[mongo] could not connect to MongoDB (${err?.name ?? 'Error'}: ${err?.message ?? err}). ` +
      'Check MONGODB_URI and the Atlas network access list.',
    );
  }
  const mongoDb = client.db(dbName);
  await attachMongoPersistence(db, table =>
    mongoDb.collection(table, { writeConcern: { w: 'majority', journal: true } }) as unknown as MongoCollection);

  timer = setInterval(() => {
    flushToMongo().catch(() => { /* logged in flushOnce */ });
  }, FLUSH_INTERVAL_MS);
  timer.unref();
  console.log(`[mongo] api_keys, users, sessions and settings persisted to MongoDB database "${dbName}"`);
}

/** Exported for tests: hydrate from MongoDB and install change tracking. */
export async function attachMongoPersistence(db: Db, collections: CollectionFor): Promise<void> {
  localDb = db;
  collectionFor = collections;

  const loaded = new Map<TableSpec, Doc[]>();
  for (const spec of TABLES) loaded.set(spec, await collections(spec.table).find({}).toArray());

  hydrate(db, loaded);
  installTriggers(db);
  // Force the first flush: seeds empty collections from the local tables, and
  // is an idempotent re-write otherwise.
  for (const spec of TABLES) syncedVersion.set(spec.table, -1);
  await flushToMongo();

  for (const [spec, docs] of loaded) {
    console.log(docs.length > 0
      ? `[mongo] ${spec.table}: loaded ${docs.length} row(s) from MongoDB`
      : `[mongo] ${spec.table}: MongoDB was empty; seeded it from the local database`);
  }
}

function tableColumns(db: Db, table: string): Set<string> {
  const rows = db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>;
  return new Set(rows.map(r => r.name));
}

function hydrate(db: Db, loaded: Map<TableSpec, Doc[]>): void {
  const toLoad = TABLES.filter(spec => loaded.get(spec)!.length > 0);
  db.transaction(() => {
    // Children before parents, so deleting users cannot cascade into sessions
    // that are about to be reloaded anyway.
    for (const spec of [...toLoad].reverse()) {
      if (spec.hydrate === 'replace') db.prepare(`DELETE FROM ${spec.table}`).run();
    }
    for (const spec of toLoad) {
      const columns = tableColumns(db, spec.table);
      const verb = spec.hydrate === 'merge' ? 'INSERT OR REPLACE' : 'INSERT';
      for (const doc of loaded.get(spec)!) {
        const row: Row = { [spec.pk]: doc._id };
        // Only known columns: field names come from outside and are spliced into SQL.
        for (const [k, v] of Object.entries(doc)) {
          if (k !== '_id' && k !== spec.pk && columns.has(k)) row[k] = v;
        }
        const names = Object.keys(row);
        db.prepare(`${verb} INTO ${spec.table} (${names.join(', ')}) VALUES (${names.map(() => '?').join(', ')})`)
          .run(...names.map(n => row[n] ?? null));
      }
    }
  })();

  // Ciphertext is copied verbatim, so a different ENCRYPTION_KEY would make
  // every key fail at request time. Catch that at boot instead.
  const sample = db.prepare('SELECT encrypted_key, iv, auth_tag FROM api_keys LIMIT 1').get() as
    { encrypted_key: string; iv: string; auth_tag: string } | undefined;
  if (sample) {
    try {
      decrypt(sample.encrypted_key, sample.iv, sample.auth_tag);
    } catch {
      throw new Error(
        '[mongo] provider keys in MongoDB cannot be decrypted with the configured ENCRYPTION_KEY. ' +
        'Set ENCRYPTION_KEY to the key that encrypted them.',
      );
    }
  }
}

function installTriggers(db: Db): void {
  db.exec('CREATE TEMP TABLE IF NOT EXISTS mongo_sync_version (tbl TEXT PRIMARY KEY, v INTEGER NOT NULL)');
  for (const { table } of TABLES) {
    const bump = `BEGIN UPDATE temp.mongo_sync_version SET v = v + 1 WHERE tbl = '${table}'; END`;
    db.exec(`
      INSERT OR IGNORE INTO temp.mongo_sync_version (tbl, v) VALUES ('${table}', 0);
      CREATE TEMP TRIGGER IF NOT EXISTS mongo_${table}_ins AFTER INSERT ON main.${table} ${bump};
      CREATE TEMP TRIGGER IF NOT EXISTS mongo_${table}_upd AFTER UPDATE ON main.${table} ${bump};
      CREATE TEMP TRIGGER IF NOT EXISTS mongo_${table}_del AFTER DELETE ON main.${table} ${bump};
    `);
  }
}

function currentVersion(table: string): number {
  const row = localDb!.prepare('SELECT v FROM temp.mongo_sync_version WHERE tbl = ?').get(table) as
    { v: number } | undefined;
  return row?.v ?? 0;
}

function dirtyTables(): TableSpec[] {
  if (!collectionFor || !localDb) return [];
  return TABLES.filter(({ table }) => currentVersion(table) !== syncedVersion.get(table));
}

async function flushTable(spec: TableSpec): Promise<void> {
  // Version and rows are read synchronously together, so they describe the
  // same state; changes made while the write is in flight stay dirty.
  const version = currentVersion(spec.table);
  const where = spec.exclude ? ` WHERE NOT (${spec.exclude})` : '';
  const rows = localDb!.prepare(`SELECT * FROM ${spec.table}${where}`).all() as Row[];
  const coll = collectionFor!(spec.table);
  if (rows.length > 0) {
    await coll.bulkWrite(
      rows.map(row => {
        const { [spec.pk]: id, ...rest } = row;
        return { replaceOne: { filter: { _id: id }, replacement: { _id: id, ...rest }, upsert: true } };
      }),
      { ordered: false },
    );
  }
  await coll.deleteMany({ _id: { $nin: rows.map(r => r[spec.pk]) } });
  syncedVersion.set(spec.table, version);
}

async function flushOnce(): Promise<void> {
  const dirty = dirtyTables();
  if (dirty.length === 0) return;
  try {
    for (const spec of dirty) await flushTable(spec);
    if (!healthy) console.log('[mongo] persisted state in sync with MongoDB');
    healthy = true;
  } catch (err: any) {
    if (healthy) console.error(`[mongo] write to MongoDB failed: ${err?.name ?? 'Error'}: ${err?.message ?? err}`);
    healthy = false;
    throw err;
  }
}

/** Push any pending changes to MongoDB. Calls are serialized. */
export function flushToMongo(): Promise<void> {
  flushChain = flushChain.catch(() => {}).then(flushOnce);
  return flushChain;
}

const UNAVAILABLE = 'Persistent storage (MongoDB) is unavailable; the change was not durably saved. Try again shortly.';

/**
 * For mutating /api requests: a persisted change must reach MongoDB before
 * success is reported. Key-management requests are refused up front while
 * MongoDB is unreachable; any request that changed a persisted table has its
 * response held until the change is flushed, and turned into a 503 if that
 * fails. (The local change then stays pending and is retried in the
 * background, but is lost on restart if MongoDB stays down — which is what the
 * 503 tells the caller.)
 */
export function mongoPersistence(): RequestHandler {
  return (req, res, next) => {
    if (!isMongoPersistenceEnabled() || ['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();

    const proceed = () => {
      const send = res.send.bind(res);
      res.send = ((body?: unknown) => {
        if (dirtyTables().length === 0) return send(body);
        flushToMongo().then(
          () => send(body),
          () => { res.status(503).type('json'); send(JSON.stringify({ error: UNAVAILABLE })); },
        );
        return res;
      }) as typeof res.send;
      next();
    };

    if (req.originalUrl.startsWith('/api/keys') && (!healthy || dirtyTables().length > 0)) {
      flushToMongo().then(proceed, () => res.status(503).json({ error: UNAVAILABLE }));
      return;
    }
    proceed();
  };
}

/** Test/shutdown helper. */
export async function closeMongoPersistence(): Promise<void> {
  if (timer) clearInterval(timer);
  timer = null;
  try { await flushToMongo(); } catch { /* best effort */ }
  collectionFor = null;
  localDb = null;
  healthy = false;
  syncedVersion.clear();
  await client?.close().catch(() => {});
  client = null;
}
