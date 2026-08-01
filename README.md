# ghl-oauth-broker

A tiny Cloudflare Worker that solves the annoying part of building on GoHighLevel: **keeping a Marketplace agency OAuth token alive forever, and handing out scoped, revocable, expiring access to it.**

It holds the agency-level OAuth token, refreshes it on a 12h cron (persisting each rotated refresh token), auto-discovers every sub-account the app is installed on, and mints sub-account ("location") access tokens on demand.

It does **not** proxy GHL API calls. It only does OAuth: the one-time agency authorization, the agency-token refresh loop, and location-token minting. Your scripts, agents, and CLIs ask the broker for a token and talk to GHL themselves.

## Why you'd want this

If you build automations across many GHL sub-accounts, you normally end up with a pile of Private Integration Tokens — one per location, pasted into scripts, impossible to rotate, all-or-nothing when you hand one to a teammate.

This replaces that with one authorization and a key registry:

- **One OAuth install.** Authorize once at the agency level; the broker keeps the token alive indefinitely (GHL refresh tokens rotate on every use — the broker persists them so the chain never breaks).
- **Tokens on demand.** `POST /location-token` with a `locationId` → a fresh, cached, ~24h location token.
- **Scoped keys per person or agent.** Issue a key limited to specific sub-accounts, with an expiry date and instant revocation — instead of sharing the master credential.
- **No secrets at rest in plaintext.** Issued keys are stored SHA-256 hashed; the plaintext is shown exactly once.

Pairs with [`ghl-cli`](https://github.com/Bleupreneur/ghl-cli) (`kind:'broker'` profiles), but the HTTP API is plain JSON — use it from anything.

## Endpoints

| Method · path | Auth | Purpose |
|---|---|---|
| `GET /` , `GET /health` | any valid key | status: agency token expiry, last refresh, `needsReauth`, cached-location count, `knownLocations` count |
| `GET /oauth/start` | — | 302 → GHL consent screen (`/v2/oauth/chooselocation`) — do this once, pick the agency |
| `GET /oauth/callback?code&state` | — (validates `state`) | exchanges the code, stores the agency token in KV; auto-discovers sub-accounts in the background |
| `POST /location-token` | any valid key | body `{ locationId }` → `{ access_token, token_type, expires_in, locationId, companyId, scope, policy }` |
| `GET /locations` | owner tier | list all known sub-accounts with `hasToken` + `tokenExpiresAt` for each |
| `POST /admin/warm-all` | owner tier | re-enumerate all installed sub-accounts and mint/cache a token for each → `{ enumerated, warmed, failed[] }` |
| `POST /admin/clear-location-cache` | owner tier | body `{ locationId? }` → drop one / all cached location tokens |
| `POST /admin/keys` | owner tier | issue a key: `{ id, label?, tier, locations, denied?, expiresAt? }` → `{ key, policy }` — plaintext `key` returned **once**, never stored |
| `GET /admin/keys` | owner tier | list all key policies (metadata only — never plaintext or hash) |
| `POST /admin/keys/revoke` | owner tier | body `{ id }` → `{ ok, revoked }` — instant |
| `POST /admin/keys/update` | owner tier | body `{ id, tier?, locations?, denied?, expiresAt?, label? }` → `{ ok, policy }` |

Error shapes on `/location-token`: `403 {error:"location_forbidden"}` when the key's allowlist excludes the location, `409 {error:"needs_reauth", reauthUrl}` when the agency token is dead, `502 {error:"ghl_error", status, detail, hint}` when GHL rejects the mint.

Cron `0 */12 * * *` refreshes the agency access token, then re-enumerates and re-warms all sub-account tokens.

## Access control

Two kinds of credential are accepted as `Authorization: Bearer …`:

- **`BROKER_KEY` secret** — the bootstrap **owner** credential. Compared timing-safe against the Worker secret, never stored in KV. Full power.
- **Issued keys** (`glk_<40 hex>`) — per-user / per-agent keys created via `POST /admin/keys`. Stored in KV SHA-256-hashed (`key:<hash>` → policy, plus a `keyid:<id>` → hash index so admin ops can address a key by id). Plaintext is shown exactly once at issue time.

Each issued key carries a `KeyPolicy`:

```ts
{
  id: string;                 // stable human id, e.g. "teammate"
  label: string;
  tier: 'owner' | 'team';     // team keys are refused on all owner-gated endpoints
  locations: '*' | string[];  // sub-account allowlist; '*' = all installed
  denied: DeniedClass[];      // capability classes the client refuses (owner => [])
  expiresAt: number | null;   // epoch seconds; null = never
  revoked: boolean;
  createdAt: number; updatedAt: number;
}
```

`DeniedClass` values: `'sub-accounts' | 'users' | 'saas-billing' | 'bulk-destructive'`. Issuing a `team` key with no explicit `denied` defaults to **all four** classes.

Revoked/expired keys get `401 {error:"key_revoked"}` / `401 {error:"key_expired"}`; a team key on an owner endpoint gets `403 {error:"owner_required"}`.

### What is enforced where — read this before trusting it

| Control | Enforced | Strength |
|---|---|---|
| Location allowlist | Broker, on `/location-token` | **Hard** — the token is never minted |
| Expiry (`expiresAt`) | Broker, on every request | **Hard** |
| Revocation | Broker, on every request | **Hard**, instant |
| Owner-only endpoints | Broker | **Hard** |
| `denied` capability classes | **Client side** | **Soft** — advisory |

The `denied` list is returned in the `policy` field of every token response, and the client (e.g. `ghl-cli`) refuses matching commands before making a request. A holder who bypasses the client and calls GHL directly with the minted token is **not** blocked by it. Treat `denied` as guardrails for trusted teammates, not as a security boundary against an adversary. The hard boundary is which locations a key can mint for, and for how long.

### Example: give a contractor 2 weeks on one sub-account

```bash
curl -sX POST "$BROKER_URL/admin/keys" \
  -H "Authorization: Bearer $BROKER_KEY" \
  -H 'content-type: application/json' \
  -d '{"id":"contractor","label":"Contractor — Clinic A","tier":"team",
       "locations":["<locationId>"],"expiresAt":1786000000}'
# => { "key": "glk_…", "policy": { … } }   <- the key is shown ONCE
```

Kill it early:

```bash
curl -sX POST "$BROKER_URL/admin/keys/revoke" \
  -H "Authorization: Bearer $BROKER_KEY" \
  -H 'content-type: application/json' -d '{"id":"contractor"}'
```

With [`ghl-cli`](https://github.com/Bleupreneur/ghl-cli) the same thing is:

```bash
ghl auth admin issue --name contractor --tier team \
  --locations <locationId> --expires 2026-08-15
ghl auth admin list
ghl auth admin revoke --id contractor
```

## Setup

You need a GoHighLevel **Marketplace app** (agency-level, distribution type "Agency") and a Cloudflare account.

1. **KV namespace**
   ```bash
   wrangler kv namespace create OAUTH
   ```
   Put the returned id into `wrangler.toml`, and set `account_id` there (or export `CLOUDFLARE_ACCOUNT_ID`).

2. **Secrets**
   ```bash
   wrangler secret put GHL_CLIENT_ID       # from your Marketplace app
   wrangler secret put GHL_CLIENT_SECRET
   wrangler secret put GHL_REDIRECT_URI    # https://<your-worker>.<subdomain>.workers.dev/oauth/callback
   wrangler secret put GHL_OAUTH_SCOPES    # space-separated; the full set the app is configured for
   wrangler secret put BROKER_KEY          # openssl rand -hex 32
   wrangler secret put ALERT_WEBHOOK_URL   # optional — Slack/Discord webhook for re-auth alerts
   ```
   For local dev, copy `.dev.vars.example` → `.dev.vars` instead.

3. **Marketplace app** — add `https://<your-worker>.<subdomain>.workers.dev/oauth/callback` to the app's Redirect URIs. It must match `GHL_REDIRECT_URI` exactly.

4. **Deploy**
   ```bash
   npm install && npm run deploy
   ```

5. **Authorize once** — open `https://<your-worker>.<subdomain>.workers.dev/oauth/start`, pick the **agency** (bulk install across sub-accounts), Authorize. You should see "✅ Broker authorized".

6. **Verify**
   ```bash
   curl -s -H "Authorization: Bearer $BROKER_KEY" \
     https://<your-worker>.<subdomain>.workers.dev/health
   ```
   Expect `needsReauth:false` and `agencyTokenExpiresAt` in the future.

### `/health` response shape

```json
{
  "ok": true,
  "service": "ghl-oauth-broker",
  "agencyTokenExpiresAt": 1234567890,
  "lastRefreshAt": 1234567800,
  "needsReauth": false,
  "cachedLocations": 5,
  "knownLocations": 7
}
```

`knownLocations` is the count of sub-accounts in the stored location list. `cachedLocations` is the count of currently cached location tokens (KV `loc:` keys).

### Auto-discovery

After the one-time agency authorization the broker automatically:

1. Enumerates every sub-account where the app is installed (`GET /oauth/installedLocations`, paginated).
2. Stores the list under `locations:list` in KV (durable, no TTL).
3. Mints and caches a location token for each sub-account, in chunks of 6.

The 12h cron repeats this after each agency-token refresh. Use `GET /locations` to inspect state, or `POST /admin/warm-all` to trigger it manually.

## When the refresh token finally dies

GHL refresh tokens last roughly a year, and die immediately if the app is uninstalled or the token is revoked. When that happens `/health` reports `needsReauth:true`, `/location-token` returns `409`, and an alert fires if `ALERT_WEBHOOK_URL` is set. Re-open `/oauth/start` and authorize again — nothing else to do.

## Security notes

- Never commit `.dev.vars`. It is git-ignored; `.dev.vars.example` is the template.
- `BROKER_KEY` is the master credential — it can mint a token for **every** sub-account and issue new keys. Keep it out of shared scripts; hand out issued `glk_` keys instead.
- Location tokens are cached in KV with a ~23h TTL (just under GHL's ~24h lifetime). Anyone with read access to that KV namespace effectively has those tokens — treat the namespace as a secret store.
- The `denied` capability classes are client-enforced. See the enforcement table above.

## Dev

```bash
npm install
npm test         # vitest
npm run typecheck
npm run dev      # local worker
npm run deploy
```

## License

MIT
