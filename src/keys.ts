/** KV-backed API-key registry for the OAuth broker. Keys are stored hashed — plaintext is
 *  shown exactly once at issue time and never persisted. A secondary `keyid:<id>` index lets
 *  admin endpoints address a key (list/revoke/update) without knowing its plaintext. */

export type DeniedClass = 'sub-accounts' | 'users' | 'saas-billing' | 'bulk-destructive';

export interface KeyPolicy {
  id: string;                 // stable human id, e.g. "teammate"
  label: string;
  tier: 'owner' | 'team';
  locations: '*' | string[];  // '*' = all installed sub-accounts
  denied: DeniedClass[];      // owner => []
  expiresAt: number | null;   // epoch seconds; null = never
  revoked: boolean;
  createdAt: number;
  updatedAt: number;
}

const K_KEY_PREFIX = 'key:';   // key:<hash> -> KeyPolicy
const K_ID_PREFIX = 'keyid:';  // keyid:<id> -> <hash>

export async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function generateKey(): string {
  const bytes = new Uint8Array(20);
  crypto.getRandomValues(bytes);
  return 'glk_' + [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export async function getKeyByHash(kv: KVNamespace, hash: string): Promise<KeyPolicy | null> {
  const raw = await kv.get(K_KEY_PREFIX + hash);
  return raw ? (JSON.parse(raw) as KeyPolicy) : null;
}

async function hashForId(kv: KVNamespace, id: string): Promise<string | null> {
  return kv.get(K_ID_PREFIX + id);
}

export async function getKeyById(kv: KVNamespace, id: string): Promise<KeyPolicy | null> {
  const hash = await hashForId(kv, id);
  return hash ? getKeyByHash(kv, hash) : null;
}

export async function putKey(kv: KVNamespace, hash: string, policy: KeyPolicy): Promise<void> {
  await kv.put(K_KEY_PREFIX + hash, JSON.stringify(policy));
  await kv.put(K_ID_PREFIX + policy.id, hash);
}

export async function listKeys(kv: KVNamespace): Promise<KeyPolicy[]> {
  const { keys } = await kv.list({ prefix: K_KEY_PREFIX });
  const out: KeyPolicy[] = [];
  for (const k of keys) {
    const raw = await kv.get(k.name);
    if (raw) out.push(JSON.parse(raw) as KeyPolicy);
  }
  return out;
}

export async function revokeKeyById(kv: KVNamespace, id: string): Promise<boolean> {
  const hash = await hashForId(kv, id);
  if (!hash) return false;
  const policy = await getKeyByHash(kv, hash);
  if (!policy) return false;
  policy.revoked = true;
  policy.updatedAt = Math.floor(Date.now() / 1000);
  await kv.put(K_KEY_PREFIX + hash, JSON.stringify(policy));
  return true;
}

export type KeyPatch = Partial<Pick<KeyPolicy, 'tier' | 'locations' | 'denied' | 'expiresAt' | 'label'>>;

export async function updateKeyById(kv: KVNamespace, id: string, patch: KeyPatch): Promise<KeyPolicy | null> {
  const hash = await hashForId(kv, id);
  if (!hash) return null;
  const policy = await getKeyByHash(kv, hash);
  if (!policy) return null;
  const updated: KeyPolicy = { ...policy, ...patch, updatedAt: Math.floor(Date.now() / 1000) };
  await kv.put(K_KEY_PREFIX + hash, JSON.stringify(updated));
  return updated;
}
