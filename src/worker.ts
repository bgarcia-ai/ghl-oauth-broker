import { getAgency, countLocs, putAgency, putState, consumeState, getLoc, putLoc, delLoc, getLocationList, putLocationList } from './store';
import { exchangeAuthCode, refreshAccessToken, mintLocationToken, getInstalledLocations, GhlHttpError } from './ghl';
import { generateKey, getKeyByHash, listKeys, putKey, revokeKeyById, sha256Hex, updateKeyById, type DeniedClass, type KeyPolicy } from './keys';

export interface Env {
  OAUTH: KVNamespace;
  GHL_CLIENT_ID: string;
  GHL_CLIENT_SECRET: string;
  GHL_REDIRECT_URI: string;
  GHL_OAUTH_SCOPES: string;
  BROKER_KEY: string;
  ALERT_WEBHOOK_URL?: string;
}

const json = (obj: unknown, status = 200): Response =>
  new Response(JSON.stringify(obj), { status, headers: { 'content-type': 'application/json' } });

const html = (body: string, status = 200): Response =>
  new Response(`<!doctype html><meta charset="utf-8"><body style="font-family:system-ui;max-width:36rem;margin:4rem auto;line-height:1.5">${body}</body>`, {
    status,
    headers: { 'content-type': 'text/html; charset=utf-8' },
  });

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return out === 0;
}

export type ResolvedKey = { policy: KeyPolicy; isOwnerSecret: boolean };

/** Synthetic policy for the bootstrap BROKER_KEY secret — full owner power, zero migration. */
function ownerPolicy(): KeyPolicy {
  return { id: 'owner', label: 'owner (BROKER_KEY)', tier: 'owner', locations: '*',
    denied: [], expiresAt: null, revoked: false, createdAt: 0, updatedAt: 0 };
}

async function resolveKey(req: Request, env: Env): Promise<ResolvedKey | Response> {
  const provided = (req.headers.get('authorization') ?? '').replace(/^Bearer\s+/i, '');
  if (!provided) return json({ error: 'unauthorized' }, 401);
  if (env.BROKER_KEY && timingSafeEqual(provided, env.BROKER_KEY)) {
    return { policy: ownerPolicy(), isOwnerSecret: true };
  }
  const policy = await getKeyByHash(env.OAUTH, await sha256Hex(provided));
  if (!policy) return json({ error: 'unauthorized' }, 401);
  if (policy.revoked) return json({ error: 'key_revoked' }, 401);
  const now = Math.floor(Date.now() / 1000);
  if (policy.expiresAt !== null && policy.expiresAt <= now) return json({ error: 'key_expired' }, 401);
  return { policy, isOwnerSecret: false };
}

function requireOwner(rk: ResolvedKey): Response | null {
  return rk.policy.tier === 'owner' ? null : json({ error: 'owner_required' }, 403);
}

const ALL_DENIED_CLASSES: DeniedClass[] = ['sub-accounts', 'users', 'saas-billing', 'bulk-destructive'];

async function handleIssueKey(req: Request, env: Env): Promise<Response> {
  const b = (await req.json().catch(() => ({}))) as Record<string, unknown>;
  const id = typeof b.id === 'string' ? b.id.trim() : '';
  if (!id) return json({ error: 'bad_request', detail: 'id is required' }, 400);
  const tier = b.tier === 'owner' ? 'owner' : 'team';
  const locations = b.locations === '*' || b.locations === undefined
    ? '*' : Array.isArray(b.locations) ? (b.locations as string[]) : '*';
  const denied = Array.isArray(b.denied)
    ? (b.denied as DeniedClass[])
    : tier === 'team' ? ALL_DENIED_CLASSES : [];
  const now = Math.floor(Date.now() / 1000);
  const policy: KeyPolicy = {
    id, label: typeof b.label === 'string' ? b.label : id, tier, locations, denied,
    expiresAt: typeof b.expiresAt === 'number' ? b.expiresAt : null,
    revoked: false, createdAt: now, updatedAt: now,
  };
  const key = generateKey();
  await putKey(env.OAUTH, await sha256Hex(key), policy);
  return json({ key, policy });
}

async function handleListKeys(env: Env): Promise<Response> {
  return json({ keys: await listKeys(env.OAUTH) });
}

async function handleRevokeKey(req: Request, env: Env): Promise<Response> {
  const b = (await req.json().catch(() => ({}))) as { id?: unknown };
  const id = typeof b.id === 'string' ? b.id : '';
  if (!id) return json({ error: 'bad_request', detail: 'id is required' }, 400);
  return json({ ok: true, revoked: await revokeKeyById(env.OAUTH, id) });
}

async function handleUpdateKey(req: Request, env: Env): Promise<Response> {
  const b = (await req.json().catch(() => ({}))) as Record<string, unknown>;
  const id = typeof b.id === 'string' ? b.id : '';
  if (!id) return json({ error: 'bad_request', detail: 'id is required' }, 400);
  const patch: Record<string, unknown> = {};
  if (b.tier === 'owner' || b.tier === 'team') patch.tier = b.tier;
  if (b.locations === '*' || Array.isArray(b.locations)) patch.locations = b.locations;
  if (Array.isArray(b.denied)) patch.denied = b.denied;
  if (typeof b.expiresAt === 'number' || b.expiresAt === null) patch.expiresAt = b.expiresAt;
  if (typeof b.label === 'string') patch.label = b.label;
  const policy = await updateKeyById(env.OAUTH, id, patch);
  if (!policy) return json({ error: 'not_found', detail: `no key with id ${id}` }, 404);
  return json({ ok: true, policy });
}

async function handleHealth(env: Env): Promise<Response> {
  const agency = await getAgency(env.OAUTH);
  const locationList = await getLocationList(env.OAUTH);
  return json({
    ok: true,
    service: 'ghl-oauth-broker',
    agencyTokenExpiresAt: agency?.expiresAt ?? null,
    lastRefreshAt: agency?.updatedAt ?? null,
    needsReauth: agency?.needsReauth ?? false,
    cachedLocations: await countLocs(env.OAUTH),
    knownLocations: locationList?.locations.length ?? 0,
  });
}

const WARM_CHUNK_SIZE = 6;

interface WarmResult {
  enumerated: number;
  warmed: number;
  failed: { id: string; error: string }[];
}

async function enumerateAndWarmLocations(env: Env): Promise<WarmResult> {
  const { accessToken, companyId } = await ensureFreshAgency(env);
  const appId = versionIdFromClientId(env.GHL_CLIENT_ID);
  const locations = await getInstalledLocations(globalThis.fetch, { agencyAccessToken: accessToken, companyId, appId });

  const now = Math.floor(Date.now() / 1000);
  await putLocationList(env.OAUTH, {
    companyId,
    lastEnumeratedAt: now,
    locations: locations.map((l) => ({ id: l.id, name: l.name })),
  });

  const failed: { id: string; error: string }[] = [];
  let warmed = 0;

  // Process in chunks of WARM_CHUNK_SIZE
  for (let i = 0; i < locations.length; i += WARM_CHUNK_SIZE) {
    const chunk = locations.slice(i, i + WARM_CHUNK_SIZE);
    const results = await Promise.allSettled(
      chunk.map((loc) =>
        mintLocationToken(globalThis.fetch, { agencyAccessToken: accessToken, companyId, locationId: loc.id }),
      ),
    );
    for (let j = 0; j < results.length; j++) {
      const result = results[j];
      const loc = chunk[j];
      if (result.status === 'fulfilled') {
        const tok = result.value;
        await putLoc(env.OAUTH, loc.id, { accessToken: tok.access_token, expiresAt: now + tok.expires_in, scope: tok.scope, updatedAt: now });
        warmed++;
      } else {
        failed.push({ id: loc.id, error: String((result.reason as Error).message ?? result.reason) });
      }
    }
  }

  return { enumerated: locations.length, warmed, failed };
}

const CHOOSELOCATION_URL = 'https://marketplace.gohighlevel.com/v2/oauth/chooselocation';

function versionIdFromClientId(clientId: string): string {
  return clientId.includes('-') ? clientId.split('-')[0] : clientId;
}

async function handleOAuthStart(env: Env): Promise<Response> {
  const nonce = crypto.randomUUID();
  await putState(env.OAUTH, nonce);
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: env.GHL_CLIENT_ID,
    redirect_uri: env.GHL_REDIRECT_URI,
    scope: env.GHL_OAUTH_SCOPES,
    version_id: versionIdFromClientId(env.GHL_CLIENT_ID),
    state: nonce,
  });
  return new Response(null, { status: 302, headers: { location: `${CHOOSELOCATION_URL}?${params.toString()}` } });
}

async function handleOAuthCallback(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const url = new URL(req.url);
  const code = url.searchParams.get('code') ?? '';
  const state = url.searchParams.get('state') ?? '';
  if (!code || !state || !(await consumeState(env.OAUTH, state))) {
    return html('<h2>❌ Invalid or expired authorization request</h2><p>Start again from <code>/oauth/start</code>.</p>', 400);
  }
  let tok;
  try {
    tok = await exchangeAuthCode(globalThis.fetch, {
      clientId: env.GHL_CLIENT_ID,
      clientSecret: env.GHL_CLIENT_SECRET,
      code,
      redirectUri: env.GHL_REDIRECT_URI,
    });
  } catch (e) {
    return html(`<h2>❌ Token exchange failed</h2><p>${String((e as Error).message).replace(/</g, '&lt;')}</p>`, 400);
  }
  if (tok.userType !== 'Company' || !tok.companyId) {
    return html(`<h2>❌ Wrong install type</h2><p>This returned a <code>${tok.userType ?? 'unknown'}</code> token, not an agency (<code>Company</code>) token. Install the app at the <b>agency</b> level (bulk install) and try again.</p>`, 400);
  }
  if (!tok.refresh_token) {
    return html('<h2>❌ No refresh token returned</h2><p>Cannot operate without a refresh token. Check the app configuration.</p>', 400);
  }
  const now = Math.floor(Date.now() / 1000);
  await putAgency(env.OAUTH, {
    accessToken: tok.access_token,
    refreshToken: tok.refresh_token,
    expiresAt: now + tok.expires_in,
    companyId: tok.companyId,
    scope: tok.scope,
    updatedAt: now,
    needsReauth: false,
  });
  ctx.waitUntil(
    enumerateAndWarmLocations(env).catch((e) =>
      fireAlert(env, `location warm-up after authorize failed: ${String((e as Error).message)}`),
    ),
  );
  return html('<h2>✅ Broker authorized</h2><p>The agency token is stored. Discovering your sub-accounts in the background. You can close this tab.</p>');
}

const AGENCY_SKEW_S = 120; // refresh the agency token when within this many seconds of expiry
const LOC_SKEW_S = 120;    // treat a cached location token as stale within this window

class NeedsReauthError extends Error {}

async function fireAlert(env: Env, message: string): Promise<void> {
  if (!env.ALERT_WEBHOOK_URL) return;
  try {
    await globalThis.fetch(env.ALERT_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ text: `[ghl-oauth-broker] ${message}` }),
    });
  } catch {
    /* best-effort */
  }
}

function reauthUrl(req: Request): string {
  return new URL('/oauth/start', new URL(req.url).origin).toString();
}

/** Returns a fresh agency record, refreshing (and persisting the rotated refresh token) if needed.
 *  On refresh failure: marks needsReauth, alerts, throws NeedsReauthError. */
async function ensureFreshAgency(env: Env): Promise<{ accessToken: string; companyId: string }> {
  const agency = await getAgency(env.OAUTH);
  if (!agency || agency.needsReauth) throw new NeedsReauthError();
  const now = Math.floor(Date.now() / 1000);
  if (now < agency.expiresAt - AGENCY_SKEW_S) return { accessToken: agency.accessToken, companyId: agency.companyId };
  try {
    const tok = await refreshAccessToken(globalThis.fetch, {
      clientId: env.GHL_CLIENT_ID,
      clientSecret: env.GHL_CLIENT_SECRET,
      refreshToken: agency.refreshToken,
    });
    if (!tok.refresh_token) throw new Error('refresh response had no refresh_token');
    await putAgency(env.OAUTH, {
      accessToken: tok.access_token,
      refreshToken: tok.refresh_token,
      expiresAt: now + tok.expires_in,
      companyId: agency.companyId,
      scope: tok.scope ?? agency.scope,
      updatedAt: now,
      needsReauth: false,
    });
    return { accessToken: tok.access_token, companyId: agency.companyId };
  } catch (e) {
    await putAgency(env.OAUTH, { ...agency, needsReauth: true, updatedAt: now });
    await fireAlert(env, `agency token refresh failed: ${String((e as Error).message)} — re-auth needed`);
    throw new NeedsReauthError();
  }
}

async function handleLocationToken(req: Request, env: Env, policy: KeyPolicy): Promise<Response> {
  let body: { locationId?: unknown };
  try {
    body = (await req.json()) as { locationId?: unknown };
  } catch {
    return json({ error: 'bad_request', detail: 'body must be JSON' }, 400);
  }
  const locationId = typeof body.locationId === 'string' ? body.locationId.trim() : '';
  if (!locationId) return json({ error: 'bad_request', detail: 'locationId is required' }, 400);

  if (policy.locations !== '*' && !policy.locations.includes(locationId)) {
    return json({ error: 'location_forbidden', locationId }, 403);
  }
  const policyView = { tier: policy.tier, denied: policy.denied, locations: policy.locations };

  let agency: { accessToken: string; companyId: string };
  try {
    agency = await ensureFreshAgency(env);
  } catch (e) {
    if (e instanceof NeedsReauthError) return json({ error: 'needs_reauth', reauthUrl: reauthUrl(req) }, 409);
    throw e;
  }

  const now = Math.floor(Date.now() / 1000);
  const cached = await getLoc(env.OAUTH, locationId);
  if (cached && now < cached.expiresAt - LOC_SKEW_S) {
    return json({ access_token: cached.accessToken, token_type: 'Bearer', expires_in: cached.expiresAt - now, locationId, companyId: agency.companyId, scope: cached.scope, policy: policyView });
  }

  let tok;
  try {
    tok = await mintLocationToken(globalThis.fetch, { agencyAccessToken: agency.accessToken, companyId: agency.companyId, locationId });
  } catch (e) {
    if (e instanceof GhlHttpError) {
      return json({ error: 'ghl_error', status: e.status, detail: typeof e.body === 'string' ? e.body : JSON.stringify(e.body), hint: 'The app may not be installed/approved on this sub-account. Re-install at the agency level with all sub-accounts selected (or approve the app on this location).' }, 502);
    }
    throw e;
  }
  await putLoc(env.OAUTH, locationId, { accessToken: tok.access_token, expiresAt: now + tok.expires_in, scope: tok.scope, updatedAt: now });
  return json({ access_token: tok.access_token, token_type: 'Bearer', expires_in: tok.expires_in, locationId, companyId: agency.companyId, scope: tok.scope, policy: policyView });
}

async function handleClearLocationCache(req: Request, env: Env): Promise<Response> {
  let body: { locationId?: unknown } = {};
  try { body = (await req.json()) as { locationId?: unknown }; } catch { /* empty body ok */ }
  const locationId = typeof body.locationId === 'string' ? body.locationId.trim() : undefined;
  await delLoc(env.OAUTH, locationId);
  return json({ ok: true, cleared: locationId ?? 'all' });
}

async function handleLocations(env: Env): Promise<Response> {
  const locationList = await getLocationList(env.OAUTH);
  if (!locationList) {
    return json({ ok: true, companyId: null, count: 0, lastEnumeratedAt: null, locations: [] });
  }
  const now = Math.floor(Date.now() / 1000);
  const locations = await Promise.all(
    locationList.locations.map(async (l) => {
      const cached = await getLoc(env.OAUTH, l.id);
      return {
        id: l.id,
        name: l.name,
        hasToken: cached !== null,
        tokenExpiresAt: cached?.expiresAt ?? null,
      };
    }),
  );
  return json({
    ok: true,
    companyId: locationList.companyId,
    count: locationList.locations.length,
    lastEnumeratedAt: locationList.lastEnumeratedAt,
    locations,
  });
}

async function handleWarmAll(req: Request, env: Env): Promise<Response> {
  try {
    const result = await enumerateAndWarmLocations(env);
    return json(result);
  } catch (e) {
    if (e instanceof NeedsReauthError) {
      return json({ error: 'needs_reauth', reauthUrl: reauthUrl(req) }, 409);
    }
    return json({ error: 'warm_failed', detail: String((e as Error).message ?? e) }, 502);
  }
}

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(req.url);
    const path = url.pathname;

    if (path === '/' || path === '/health') {
      const rk = await resolveKey(req, env);
      if (rk instanceof Response) return rk;
      return handleHealth(env);
    }

    if (path === '/oauth/start' && req.method === 'GET') return handleOAuthStart(env);
    if (path === '/oauth/callback' && req.method === 'GET') return handleOAuthCallback(req, env, ctx);

    if (path === '/location-token' && req.method === 'POST') {
      const rk = await resolveKey(req, env);
      if (rk instanceof Response) return rk;
      return handleLocationToken(req, env, rk.policy);
    }

    if (path === '/locations' && req.method === 'GET') {
      const rk = await resolveKey(req, env);
      if (rk instanceof Response) return rk;
      const notOwner = requireOwner(rk);
      if (notOwner) return notOwner;
      return handleLocations(env);
    }

    if (path === '/admin/warm-all' && req.method === 'POST') {
      const rk = await resolveKey(req, env);
      if (rk instanceof Response) return rk;
      const notOwner = requireOwner(rk);
      if (notOwner) return notOwner;
      return handleWarmAll(req, env);
    }

    if (path === '/admin/clear-location-cache' && req.method === 'POST') {
      const rk = await resolveKey(req, env);
      if (rk instanceof Response) return rk;
      const notOwner = requireOwner(rk);
      if (notOwner) return notOwner;
      return handleClearLocationCache(req, env);
    }

    if (path === '/admin/keys' && (req.method === 'POST' || req.method === 'GET')) {
      const rk = await resolveKey(req, env);
      if (rk instanceof Response) return rk;
      const notOwner = requireOwner(rk);
      if (notOwner) return notOwner;
      return req.method === 'POST' ? handleIssueKey(req, env) : handleListKeys(env);
    }

    if (path === '/admin/keys/revoke' && req.method === 'POST') {
      const rk = await resolveKey(req, env);
      if (rk instanceof Response) return rk;
      const notOwner = requireOwner(rk);
      if (notOwner) return notOwner;
      return handleRevokeKey(req, env);
    }

    if (path === '/admin/keys/update' && req.method === 'POST') {
      const rk = await resolveKey(req, env);
      if (rk instanceof Response) return rk;
      const notOwner = requireOwner(rk);
      if (notOwner) return notOwner;
      return handleUpdateKey(req, env);
    }

    return json({ error: 'not found' }, 404);
  },

  async scheduled(_event: ScheduledEvent, env: Env, _ctx: ExecutionContext): Promise<void> {
    const agency = await getAgency(env.OAUTH);
    if (!agency || agency.needsReauth) return;
    const now = Math.floor(Date.now() / 1000);
    try {
      const tok = await refreshAccessToken(globalThis.fetch, {
        clientId: env.GHL_CLIENT_ID,
        clientSecret: env.GHL_CLIENT_SECRET,
        refreshToken: agency.refreshToken,
      });
      if (!tok.refresh_token) throw new Error('refresh response had no refresh_token');
      await putAgency(env.OAUTH, {
        accessToken: tok.access_token,
        refreshToken: tok.refresh_token,
        expiresAt: now + tok.expires_in,
        companyId: agency.companyId,
        scope: tok.scope ?? agency.scope,
        updatedAt: now,
        needsReauth: false,
      });
      await enumerateAndWarmLocations(env).catch((e) =>
        fireAlert(env, `cron location warm-up failed: ${String((e as Error).message)}`),
      );
    } catch (e) {
      await putAgency(env.OAUTH, { ...agency, needsReauth: true, updatedAt: now });
      await fireAlert(env, `cron refresh failed: ${String((e as Error).message)} — re-auth needed`);
    }
  },
};
