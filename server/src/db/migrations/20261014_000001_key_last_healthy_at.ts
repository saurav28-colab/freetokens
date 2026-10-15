import type { Db } from '../types.js';

function hasColumn(db: Db, table: string, column: string): boolean {
  const columns = db.prepare(`PRAGMA table_info(${table})`).all() as { name: string }[];
  return columns.some((candidate) => candidate.name === column);
}

/**
 * #1493: record when a key last demonstrably worked — either a successful
 * health probe or (throttled) a real request it served. A key can otherwise
 * stay `status='healthy'` with a fresh `last_checked_at` while never actually
 * serving anything, and providers that forbid probes (#1459) have no probe
 * trail at all.
 */
export function up(db: Db): void {
  if (!hasColumn(db, 'api_keys', 'last_healthy_at')) {
    db.prepare('ALTER TABLE api_keys ADD COLUMN last_healthy_at TEXT').run();
  }
}

export function down(db: Db): void {
  if (hasColumn(db, 'api_keys', 'last_healthy_at')) {
    db.prepare('ALTER TABLE api_keys DROP COLUMN last_healthy_at').run();
  }
}
