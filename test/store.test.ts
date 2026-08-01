import { describe, it, expect, beforeEach } from 'vitest';
import {
  getAgency, putAgency, getLoc, putLoc, delLoc, countLocs, putState, consumeState,
  getLocationList, putLocationList,
  type AgencyRecord,
} from '../src/store';

// Minimal in-memory KVNamespace stand-in.
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

const sampleAgency: AgencyRecord = {
  accessToken: 'a', refreshToken: 'r', expiresAt: 9999999999, companyId: 'C1',
  scope: 'oauth.write', updatedAt: 1, needsReauth: false,
};

describe('agency record', () => {
  let kv: KVNamespace;
  beforeEach(() => { kv = fakeKV(); });
  it('returns null when unset', async () => { expect(await getAgency(kv)).toBeNull(); });
  it('round-trips', async () => {
    await putAgency(kv, sampleAgency);
    expect(await getAgency(kv)).toEqual(sampleAgency);
  });
});

describe('location cache', () => {
  let kv: KVNamespace;
  beforeEach(() => { kv = fakeKV(); });
  it('round-trips and counts', async () => {
    await putLoc(kv, 'L1', { accessToken: 't1', expiresAt: 10, updatedAt: 1 });
    await putLoc(kv, 'L2', { accessToken: 't2', expiresAt: 20, updatedAt: 1 });
    expect((await getLoc(kv, 'L1'))?.accessToken).toBe('t1');
    expect(await countLocs(kv)).toBe(2);
  });
  it('delLoc(id) deletes one; delLoc() deletes all', async () => {
    await putLoc(kv, 'L1', { accessToken: 't1', expiresAt: 10, updatedAt: 1 });
    await putLoc(kv, 'L2', { accessToken: 't2', expiresAt: 20, updatedAt: 1 });
    await delLoc(kv, 'L1');
    expect(await getLoc(kv, 'L1')).toBeNull();
    expect(await countLocs(kv)).toBe(1);
    await delLoc(kv);
    expect(await countLocs(kv)).toBe(0);
  });
});

describe('state nonce', () => {
  let kv: KVNamespace;
  beforeEach(() => { kv = fakeKV(); });
  it('consumeState returns true once, then false', async () => {
    await putState(kv, 'NONCE');
    expect(await consumeState(kv, 'NONCE')).toBe(true);
    expect(await consumeState(kv, 'NONCE')).toBe(false);
  });
});

describe('location list', () => {
  let kv: KVNamespace;
  beforeEach(() => { kv = fakeKV(); });

  it('returns null when unset', async () => {
    expect(await getLocationList(kv)).toBeNull();
  });

  it('round-trips a location list record', async () => {
    const record = {
      companyId: 'C1',
      lastEnumeratedAt: 1234567890,
      locations: [
        { id: 'L1', name: 'Clinic A' },
        { id: 'L2', name: 'Clinic B' },
      ],
    };
    await putLocationList(kv, record);
    const got = await getLocationList(kv);
    expect(got).toEqual(record);
  });

  it('overwrites an existing record', async () => {
    await putLocationList(kv, { companyId: 'C1', lastEnumeratedAt: 1, locations: [{ id: 'L1', name: 'A' }] });
    await putLocationList(kv, { companyId: 'C1', lastEnumeratedAt: 2, locations: [{ id: 'L2', name: 'B' }] });
    const got = await getLocationList(kv);
    expect(got?.lastEnumeratedAt).toBe(2);
    expect(got?.locations).toHaveLength(1);
    expect(got?.locations[0].id).toBe('L2');
  });
});
