/** KV-backed storage for the OAuth broker. Namespace binding: `OAUTH`. */

const K_AGENCY = 'agency';
const K_LOC_PREFIX = 'loc:';
const K_STATE_PREFIX = 'state:';
const K_LOCATION_LIST = 'locations:list';
const LOC_TTL_S = 23 * 60 * 60; // ~23h — slightly under GHL's ~24h location token
const STATE_TTL_S = 10 * 60;

export interface AgencyRecord {
  accessToken: string;
  refreshToken: string;
  expiresAt: number; // epoch seconds
  companyId: string;
  scope?: string;
  updatedAt: number; // epoch seconds
  needsReauth: boolean;
}

export interface LocRecord {
  accessToken: string;
  expiresAt: number; // epoch seconds
  scope?: string;
  updatedAt: number; // epoch seconds
}

export async function getAgency(kv: KVNamespace): Promise<AgencyRecord | null> {
  const raw = await kv.get(K_AGENCY);
  return raw ? (JSON.parse(raw) as AgencyRecord) : null;
}

export async function putAgency(kv: KVNamespace, r: AgencyRecord): Promise<void> {
  await kv.put(K_AGENCY, JSON.stringify(r));
}

export async function getLoc(kv: KVNamespace, locationId: string): Promise<LocRecord | null> {
  const raw = await kv.get(K_LOC_PREFIX + locationId);
  return raw ? (JSON.parse(raw) as LocRecord) : null;
}

export async function putLoc(kv: KVNamespace, locationId: string, r: LocRecord): Promise<void> {
  await kv.put(K_LOC_PREFIX + locationId, JSON.stringify(r), { expirationTtl: LOC_TTL_S });
}

export async function delLoc(kv: KVNamespace, locationId?: string): Promise<void> {
  if (locationId) {
    await kv.delete(K_LOC_PREFIX + locationId);
    return;
  }
  const { keys } = await kv.list({ prefix: K_LOC_PREFIX });
  await Promise.all(keys.map((k) => kv.delete(k.name)));
}

export async function countLocs(kv: KVNamespace): Promise<number> {
  const { keys } = await kv.list({ prefix: K_LOC_PREFIX });
  return keys.length;
}

export async function putState(kv: KVNamespace, nonce: string): Promise<void> {
  await kv.put(K_STATE_PREFIX + nonce, '1', { expirationTtl: STATE_TTL_S });
}

/** Returns true if the nonce existed (and deletes it). Single-use. */
export async function consumeState(kv: KVNamespace, nonce: string): Promise<boolean> {
  const key = K_STATE_PREFIX + nonce;
  const v = await kv.get(key);
  if (v === null) return false;
  await kv.delete(key);
  return true;
}

export interface LocationListRecord {
  companyId: string;
  lastEnumeratedAt: number; // epoch seconds
  locations: { id: string; name: string }[];
}

export async function getLocationList(kv: KVNamespace): Promise<LocationListRecord | null> {
  const raw = await kv.get(K_LOCATION_LIST);
  return raw ? (JSON.parse(raw) as LocationListRecord) : null;
}

export async function putLocationList(kv: KVNamespace, r: LocationListRecord): Promise<void> {
  await kv.put(K_LOCATION_LIST, JSON.stringify(r));
}
