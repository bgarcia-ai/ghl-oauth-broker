import { describe, it, expect } from 'vitest';
import {
  sha256Hex, generateKey, putKey, getKeyByHash, getKeyById,
  listKeys, revokeKeyById, updateKeyById, type KeyPolicy,
} from '../src/keys';

function fakeKV() {
  const m = new Map<string, string>();
  return {
    _m: m,
    async get(key: string) { return m.get(key) ?? null; },
    async put(key: string, val: string) { m.set(key, val); },
    async delete(key: string) { m.delete(key); },
    async list({ prefix }: { prefix?: string } = {}) {
      const keys = [...m.keys()].filter((k) => !prefix || k.startsWith(prefix)).map((name) => ({ name }));
      return { keys, list_complete: true, cacheStatus: null };
    },
  } as unknown as KVNamespace;
}

function policy(over: Partial<KeyPolicy> = {}): KeyPolicy {
  const now = 1_700_000_000;
  return { id: 'teammate', label: 'Teammate', tier: 'team', locations: '*',
    denied: ['sub-accounts'], expiresAt: null, revoked: false,
    createdAt: now, updatedAt: now, ...over };
}

describe('sha256Hex', () => {
  it('is deterministic 64-char hex', async () => {
    const a = await sha256Hex('glk_abc');
    const b = await sha256Hex('glk_abc');
    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('generateKey', () => {
  it('returns a glk_-prefixed key', () => {
    expect(generateKey()).toMatch(/^glk_[0-9a-f]{40}$/);
  });
  it('returns a different key each call', () => {
    expect(generateKey()).not.toBe(generateKey());
  });
});

describe('key CRUD', () => {
  it('put then getByHash / getById round-trips', async () => {
    const kv = fakeKV();
    const hash = await sha256Hex('glk_xyz');
    await putKey(kv, hash, policy());
    expect((await getKeyByHash(kv, hash))?.id).toBe('teammate');
    expect((await getKeyById(kv, 'teammate'))?.tier).toBe('team');
  });

  it('getByHash / getById return null for unknown entries', async () => {
    const kv = fakeKV();
    expect(await getKeyByHash(kv, 'deadbeef')).toBeNull();
    expect(await getKeyById(kv, 'ghost')).toBeNull();
  });

  it('listKeys returns all policies', async () => {
    const kv = fakeKV();
    await putKey(kv, await sha256Hex('a'), policy({ id: 'a' }));
    await putKey(kv, await sha256Hex('b'), policy({ id: 'b' }));
    const ids = (await listKeys(kv)).map((k) => k.id).sort();
    expect(ids).toEqual(['a', 'b']);
  });

  it('revokeKeyById flips revoked and persists', async () => {
    const kv = fakeKV();
    const hash = await sha256Hex('glk_r');
    await putKey(kv, hash, policy({ id: 'r' }));
    expect(await revokeKeyById(kv, 'r')).toBe(true);
    expect((await getKeyByHash(kv, hash))?.revoked).toBe(true);
    expect(await revokeKeyById(kv, 'missing')).toBe(false);
  });

  it('updateKeyById patches allowed fields', async () => {
    const kv = fakeKV();
    const hash = await sha256Hex('glk_u');
    await putKey(kv, hash, policy({ id: 'u', tier: 'team' }));
    const updated = await updateKeyById(kv, 'u', { tier: 'owner', locations: ['L1'] });
    expect(updated?.tier).toBe('owner');
    expect((await getKeyByHash(kv, hash))?.locations).toEqual(['L1']);
  });

  it('updateKeyById returns null for an unknown id', async () => {
    const kv = fakeKV();
    expect(await updateKeyById(kv, 'nope', { tier: 'owner' })).toBeNull();
  });
});
